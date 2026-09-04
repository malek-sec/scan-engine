"""
BountyHub v3 Enterprise — core.active_recon
Module 2.5: Active Reconnaissance & Fuzzing Engine

Pure data layer — no print(), no Logger, no Colors.
All terminal rendering is the caller's responsibility (same contract as
core.recon / core.fingerprint).

Purpose
-------
Transforms the pipeline from passive enumeration into a comprehensive, active
reconnaissance and fuzzing stage that mirrors professional bug-bounty workflows:

  1. Deep crawling / spidering       → katana
  2. Directory / file brute-forcing  → ffuf
  3. Hidden parameter discovery      → arjun
  4. Comprehensive port scanning     → naabu (breadth; nmap keeps service depth)
  5. Template-based vuln scanning    → nuclei

Public API
----------
ActiveReconModule(
    target, live_hosts, output_dir,
    seed_endpoints=None, seed_js=None,
).execute() -> dict:
{
    "status"       : "ok" | "partial" | "skipped" | "error",
    "events"       : [{"level": str, "msg": str}, ...],
    "crawl"        : {"endpoints": [...], "js_files": [...], "count": int},
    "fuzz"         : {"paths": [{"url","status","length"}], "count": int},
    "params"       : {"by_endpoint": {url: [param, ...]}, "count": int},
    "ports"        : {"by_host": {host: [port, ...]}, "count": int},
    "nuclei"       : {"findings": [...], "by_severity": {...}, "count": int},
    "tools_used"   : [str, ...],
    "tools_missing": [str, ...],
}

Concurrency
-----------
The whole scan pipeline already runs inside a daemon worker thread, so this
module never blocks the Flask request loop. Internally it fans out with a
ThreadPoolExecutor:

  Phase A (independent)      naabu · katana · ffuf     run concurrently
  Phase B (needs crawl data) arjun · nuclei            run concurrently

Every external tool is a subprocess bounded by an explicit hard timeout, and
the whole module is capped by a global wall-clock budget (_TOTAL_BUDGET).

Rules of Engagement (RoE) — Rate-Limiting & DoS Prevention
----------------------------------------------------------
Active recon is louder than passive recon by design, but it is still NOT a
stress test. Every tool is invoked with an explicit request-rate cap and a
concurrency cap. Destructive / DoS / intrusive template tags are excluded from
nuclei. These knobs are the module-level constants below — tuned aggressive but
bounded. Only ever run this against targets you are authorised to test.
"""

import json
import os
import re
import shutil
import subprocess
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from core import Config


# ── Module configuration ──────────────────────────────────────────────────────
# All tunables now live in the central Config class (core/__init__.py) and are
# overridable via BOUNTYHUB_ACTIVE_* environment variables. The names below are
# thin aliases sourced from Config so the rest of this module stays readable;
# change values in Config / the environment, never here.

_MAX_HOSTS            = Config.ACTIVE_MAX_HOSTS
_TOTAL_BUDGET         = Config.ACTIVE_TOTAL_BUDGET

# katana (crawling)
_KATANA_DEPTH         = Config.ACTIVE_KATANA_DEPTH
_KATANA_RL            = Config.ACTIVE_KATANA_RL
_KATANA_CONC          = Config.ACTIVE_KATANA_CONC
_KATANA_TIMEOUT       = Config.ACTIVE_KATANA_TIMEOUT
_KATANA_MAX_ENDPOINTS = Config.ACTIVE_KATANA_MAX_ENDPOINTS

# ffuf (directory / file fuzzing)
_FFUF_RATE            = Config.ACTIVE_FFUF_RATE
_FFUF_THREADS         = Config.ACTIVE_FFUF_THREADS
_FFUF_TIMEOUT         = Config.ACTIVE_FFUF_TIMEOUT
_FFUF_MAXTIME         = Config.ACTIVE_FFUF_MAXTIME
_FFUF_MATCH_CODES     = Config.ACTIVE_FFUF_MATCH_CODES

# arjun (hidden parameter discovery)
_ARJUN_MAX_ENDPOINTS  = Config.ACTIVE_ARJUN_MAX_ENDPOINTS
_ARJUN_THREADS        = Config.ACTIVE_ARJUN_THREADS
_ARJUN_TIMEOUT        = Config.ACTIVE_ARJUN_TIMEOUT

# naabu (comprehensive port scanning)
_NAABU_TOP_PORTS      = Config.ACTIVE_NAABU_TOP_PORTS
_NAABU_ALL_PORTS      = Config.ACTIVE_NAABU_ALL_PORTS
_NAABU_RATE           = Config.ACTIVE_NAABU_RATE
_NAABU_TIMEOUT        = Config.ACTIVE_NAABU_TIMEOUT

# nuclei (template-based vulnerability scanning)
_NUCLEI_RL            = Config.ACTIVE_NUCLEI_RL
_NUCLEI_CONC          = Config.ACTIVE_NUCLEI_CONC
_NUCLEI_TIMEOUT       = Config.ACTIVE_NUCLEI_TIMEOUT
_NUCLEI_SEVERITY      = Config.ACTIVE_NUCLEI_SEVERITY
_NUCLEI_EXCLUDE_TAGS  = Config.ACTIVE_NUCLEI_EXCLUDE_TAGS
_NUCLEI_MAX_TARGETS   = Config.ACTIVE_NUCLEI_MAX_TARGETS

# ── Wordlists (SecLists) — first existing path wins ───────────────────────────
# An explicit override (Config.ACTIVE_DIR_WORDLIST / env) is tried first.
_DIR_WORDLIST_CANDIDATES = [
    p for p in [
        Config.ACTIVE_DIR_WORDLIST,
        "/home/kali/SecLists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ] if p
]

# Known tool install locations, searched when a tool is not on PATH. Covers Go
# tools (~/go/bin) and pip/pipx user installs (~/.local/bin, e.g. arjun) — the
# background worker's PATH frequently lacks both.
_GO_BIN_DIRS = [
    os.environ.get("GOBIN", ""),
    os.path.join(os.environ.get("GOPATH", ""), "bin") if os.environ.get("GOPATH") else "",
    os.path.join(os.path.expanduser("~"), "go", "bin"),
    os.path.join(os.path.expanduser("~"), ".local", "bin"),
    "/usr/local/go/bin",
    "/root/go/bin",
    "/usr/local/bin",
]


def _ev(level: str, msg: str) -> dict:
    return {"level": level, "msg": msg}


def _resolve_tool(name: str) -> str | None:
    """
    Locate a CLI robustly: PATH first, then standard Go-tool / local bin dirs.

    The background scan worker inherits its PATH from whatever launched the
    Flask app, which frequently lacks ~/go/bin. Relying on the bare name then
    fails silently, so every tool is resolved to an absolute path here.
    """
    found = shutil.which(name)
    if found:
        return found
    for d in _GO_BIN_DIRS:
        if not d:
            continue
        candidate = os.path.join(d, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _first_existing(paths: list) -> str | None:
    for p in paths:
        if p and os.path.isfile(p):
            return p
    return None


def _strip_scheme(url: str) -> str:
    """Return the bare host[:port] for a scheme-prefixed URL."""
    try:
        netloc = urllib.parse.urlparse(url).netloc
        return netloc or url
    except Exception:
        return url


class ActiveReconModule:
    """
    Active reconnaissance & fuzzing over the live hosts discovered by Module 1.

    Never raises — every tool failure is captured as an event and the module
    degrades gracefully, returning whatever partial data it gathered.
    """

    def __init__(
        self,
        target: str,
        live_hosts: list,
        output_dir: Path,
        seed_endpoints: list | None = None,
        seed_js: list | None = None,
    ) -> None:
        self.target      = target
        self.live_hosts  = [h for h in (live_hosts or []) if h][:_MAX_HOSTS]
        self.output_dir  = Path(output_dir)
        self.seed_endpoints = list(seed_endpoints or [])
        self.seed_js     = list(seed_js or [])
        self._deadline   = time.monotonic() + _TOTAL_BUDGET
        self.tools_used:    list = []
        self.tools_missing: list = []

    # ── Budget helper ─────────────────────────────────────────────────────────

    def _remaining(self) -> int:
        """Seconds left in the global budget (never negative)."""
        return max(0, int(self._deadline - time.monotonic()))

    def _bounded_timeout(self, stage_timeout: int) -> int:
        """Clamp a stage timeout to the remaining global budget."""
        return max(1, min(stage_timeout, self._remaining()))

    # ── Stage 1: katana — deep crawling / spidering ───────────────────────────

    def _crawl(self, events: list) -> dict:
        """
        Recursively crawl every live host, extracting endpoints and JS files.
        katana's -jc flag parses JavaScript for additional endpoints.
        """
        result = {"endpoints": [], "js_files": [], "count": 0}
        katana = _resolve_tool("katana")
        if not katana:
            self.tools_missing.append("katana")
            events.append(_ev("warning", "katana not installed — crawling skipped"))
            return result
        if not self.live_hosts:
            return result

        hosts_file = self.output_dir / "active_hosts.txt"
        hosts_file.write_text("\n".join(self.live_hosts) + "\n")
        out_file = self.output_dir / "katana_out.txt"

        events.append(_ev("info",
            f"katana — crawling {len(self.live_hosts)} host(s) "
            f"(depth {_KATANA_DEPTH}, rl {_KATANA_RL}/s)"
        ))
        cmd = [
            katana,
            "-list",    str(hosts_file),
            "-d",       str(_KATANA_DEPTH),
            "-jc",                       # parse JS for endpoints
            "-kf",      "all",           # known files (robots.txt, sitemap.xml)
            "-fs",      "fqdn",          # stay within the target FQDN scope
            "-rl",      str(_KATANA_RL),
            "-c",       str(_KATANA_CONC),
            "-timeout", "10",
            "-silent",
            "-nc",                       # no colour
            "-o",       str(out_file),
        ]
        try:
            subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self._bounded_timeout(_KATANA_TIMEOUT),
            )
        except subprocess.TimeoutExpired:
            events.append(_ev("warning", "katana timed out — using partial crawl output"))
        except Exception as exc:
            events.append(_ev("warning", f"katana error: {exc}"))
            return result

        endpoints: set = set(self.seed_endpoints)
        js_files:  set = set(self.seed_js)
        if out_file.exists():
            for line in out_file.read_text().splitlines():
                url = line.strip()
                if not url.startswith("http"):
                    continue
                endpoints.add(url)
                path = urllib.parse.urlparse(url).path.lower()
                if path.endswith(".js"):
                    js_files.add(url.split("?")[0])
                if len(endpoints) >= _KATANA_MAX_ENDPOINTS:
                    break

        result["endpoints"] = sorted(endpoints)
        result["js_files"]  = sorted(js_files)
        result["count"]     = len(result["endpoints"])
        if result["count"]:
            self.tools_used.append("katana")
        events.append(_ev("success",
            f"katana — {result['count']} endpoint(s), "
            f"{len(result['js_files'])} JS file(s) discovered"
        ))
        return result

    # ── Stage 2: ffuf — directory / file brute-forcing ────────────────────────

    def _fuzz_dirs(self, events: list) -> dict:
        """Brute-force hidden paths / admin panels on each host with ffuf."""
        result = {"paths": [], "count": 0}
        ffuf = _resolve_tool("ffuf")
        if not ffuf:
            self.tools_missing.append("ffuf")
            events.append(_ev("warning", "ffuf not installed — directory fuzzing skipped"))
            return result

        wordlist = _first_existing(_DIR_WORDLIST_CANDIDATES)
        if not wordlist:
            events.append(_ev("warning",
                "No directory wordlist found (SecLists) — fuzzing skipped"))
            return result

        events.append(_ev("info",
            f"ffuf — directory fuzzing {len(self.live_hosts)} host(s) "
            f"(wordlist: {os.path.basename(wordlist)}, rate {_FFUF_RATE}/s)"
        ))

        paths: list = []
        for idx, host in enumerate(self.live_hosts):
            if self._remaining() <= 5:
                events.append(_ev("warning", "ffuf — global budget exhausted, stopping"))
                break
            ffuf_json = self.output_dir / f"ffuf_{idx}.json"
            target_url = host.rstrip("/") + "/FUZZ"
            cmd = [
                ffuf,
                "-u",       target_url,
                "-w",       wordlist,
                "-mc",      _FFUF_MATCH_CODES,
                "-ac",                   # auto-calibration: filter wildcard /
                                         # uniform responses (e.g. a blanket 403)
                                         # so results are real, not CDN noise
                "-rate",    str(_FFUF_RATE),
                "-t",       str(_FFUF_THREADS),
                "-timeout", str(_FFUF_TIMEOUT),
                "-maxtime", str(min(_FFUF_MAXTIME, self._remaining())),
                "-of",      "json",
                "-o",       str(ffuf_json),
                "-s",                    # silent
            ]
            try:
                subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=self._bounded_timeout(_FFUF_MAXTIME + 30),
                )
            except subprocess.TimeoutExpired:
                events.append(_ev("warning", f"ffuf timed out on {host}"))
            except Exception as exc:
                events.append(_ev("warning", f"ffuf error on {host}: {exc}"))
                continue

            if ffuf_json.exists():
                try:
                    data = json.loads(ffuf_json.read_text() or "{}")
                    for r in data.get("results", []):
                        paths.append({
                            "url":    r.get("url", ""),
                            "status": r.get("status"),
                            "length": r.get("length"),
                        })
                except Exception:
                    continue

        result["paths"] = paths
        result["count"] = len(paths)
        if paths:
            self.tools_used.append("ffuf")
        events.append(_ev("success",
            f"ffuf — {len(paths)} hidden path(s) / file(s) discovered"))
        return result

    # ── Stage 3: naabu — comprehensive port scanning ──────────────────────────

    def _scan_ports(self, events: list) -> dict:
        """
        Fast, comprehensive port discovery with naabu (top-1000 or full 65k).
        Complements Module 2's nmap, which keeps deep service/version detection.
        """
        result = {"by_host": {}, "count": 0}
        naabu = _resolve_tool("naabu")
        if not naabu:
            self.tools_missing.append("naabu")
            events.append(_ev("warning", "naabu not installed — wide port scan skipped"))
            return result

        hosts = sorted({_strip_scheme(h).split(":")[0] for h in self.live_hosts})
        if not hosts:
            return result
        hosts_file = self.output_dir / "naabu_hosts.txt"
        hosts_file.write_text("\n".join(hosts) + "\n")
        out_file = self.output_dir / "naabu_out.json"

        port_flag = ["-p", "-"] if _NAABU_ALL_PORTS else ["-top-ports", str(_NAABU_TOP_PORTS)]
        scope = "all 65535 ports" if _NAABU_ALL_PORTS else f"top {_NAABU_TOP_PORTS} ports"
        events.append(_ev("info",
            f"naabu — comprehensive port scan of {len(hosts)} host(s) ({scope})"))

        cmd = [
            naabu,
            "-list", str(hosts_file),
            *port_flag,
            "-rate", str(_NAABU_RATE),
            "-silent",
            "-json",
            "-o",    str(out_file),
        ]
        try:
            subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self._bounded_timeout(_NAABU_TIMEOUT),
            )
        except subprocess.TimeoutExpired:
            events.append(_ev("warning", "naabu timed out — using partial results"))
        except Exception as exc:
            events.append(_ev("warning", f"naabu error: {exc}"))
            return result

        by_host: dict = {}
        if out_file.exists():
            for line in out_file.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj  = json.loads(line)
                    host = obj.get("host") or obj.get("ip", "")
                    port = obj.get("port")
                    if host and port is not None:
                        by_host.setdefault(host, []).append(port)
                except Exception:
                    continue

        for h in by_host:
            by_host[h] = sorted(set(by_host[h]))
        result["by_host"] = by_host
        result["count"]   = sum(len(v) for v in by_host.values())
        if result["count"]:
            self.tools_used.append("naabu")
        events.append(_ev("success",
            f"naabu — {result['count']} open port(s) across {len(by_host)} host(s)"))
        return result

    # ── Stage 4: arjun — hidden parameter discovery ───────────────────────────

    def _discover_params(self, endpoints: list, events: list) -> dict:
        """Mine hidden GET parameters on the most promising crawled endpoints."""
        result = {"by_endpoint": {}, "count": 0}
        arjun = _resolve_tool("arjun")
        if not arjun:
            self.tools_missing.append("arjun")
            events.append(_ev("warning", "arjun not installed — parameter discovery skipped"))
            return result

        # Prioritise endpoints that look dynamic (query string, script, api).
        def _score(u: str) -> int:
            s = 0
            low = u.lower()
            if "?" in u:                         s += 3
            if any(k in low for k in ("api", "search", "id=", "query", "q=", "user", "admin")):
                s += 2
            if low.endswith((".php", ".asp", ".aspx", ".jsp", ".do")):
                s += 1
            return s

        candidates = sorted({e.split("#")[0] for e in endpoints if e.startswith("http")},
                            key=_score, reverse=True)[:_ARJUN_MAX_ENDPOINTS]
        if not candidates:
            events.append(_ev("info", "arjun — no suitable endpoints to mine"))
            return result

        targets_file = self.output_dir / "arjun_targets.txt"
        targets_file.write_text("\n".join(candidates) + "\n")
        out_file = self.output_dir / "arjun_out.json"

        events.append(_ev("info",
            f"arjun — mining hidden parameters on {len(candidates)} endpoint(s)"))
        cmd = [
            arjun,
            "-i",  str(targets_file),     # input list of URLs
            "-oJ", str(out_file),
            "-t",  str(_ARJUN_THREADS),
            "-m",  "GET",
        ]
        try:
            subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self._bounded_timeout(_ARJUN_TIMEOUT),
            )
        except subprocess.TimeoutExpired:
            events.append(_ev("warning", "arjun timed out — using partial results"))
        except Exception as exc:
            events.append(_ev("warning", f"arjun error: {exc}"))
            return result

        by_endpoint: dict = {}
        if out_file.exists():
            try:
                data = json.loads(out_file.read_text() or "{}")
                # arjun output shape varies by version; handle the common forms.
                if isinstance(data, dict):
                    for url, info in data.items():
                        if isinstance(info, dict):
                            params = info.get("params") or info.get("parameters") or []
                        elif isinstance(info, list):
                            params = info
                        else:
                            params = []
                        if params:
                            by_endpoint[url] = params
            except Exception as exc:
                events.append(_ev("warning", f"arjun: failed to parse output: {exc}"))

        result["by_endpoint"] = by_endpoint
        result["count"]       = sum(len(v) for v in by_endpoint.values())
        if result["count"]:
            self.tools_used.append("arjun")
        events.append(_ev("success",
            f"arjun — {result['count']} hidden parameter(s) across "
            f"{len(by_endpoint)} endpoint(s)"))
        return result

    # ── Stage 5: nuclei — template-based vulnerability scanning ────────────────

    def _vuln_scan(self, extra_urls: list, events: list) -> dict:
        """
        Scan hosts (plus a bounded set of crawled URLs) with nuclei for known
        CVEs and misconfigurations. Destructive/DoS/intrusive tags are excluded.
        """
        result = {"findings": [], "by_severity": {}, "count": 0}
        nuclei = _resolve_tool("nuclei")
        if not nuclei:
            self.tools_missing.append("nuclei")
            events.append(_ev("warning", "nuclei not installed — vuln scanning skipped"))
            return result

        targets = list(dict.fromkeys(
            self.live_hosts + [u for u in extra_urls if u.startswith("http")]
        ))[:_NUCLEI_MAX_TARGETS]
        if not targets:
            return result
        targets_file = self.output_dir / "nuclei_targets.txt"
        targets_file.write_text("\n".join(targets) + "\n")
        out_file = self.output_dir / "nuclei_out.jsonl"

        events.append(_ev("info",
            f"nuclei — template scanning {len(targets)} target(s) "
            f"(severity {_NUCLEI_SEVERITY}, rl {_NUCLEI_RL}/s, "
            f"excluding {_NUCLEI_EXCLUDE_TAGS})"
        ))
        cmd = [
            nuclei,
            "-list",         str(targets_file),
            "-severity",     _NUCLEI_SEVERITY,
            "-exclude-tags", _NUCLEI_EXCLUDE_TAGS,
            "-rl",           str(_NUCLEI_RL),
            "-c",            str(_NUCLEI_CONC),
            "-timeout",      "10",
            "-jsonl",
            "-o",            str(out_file),
            "-silent",
            "-disable-update-check",
        ]
        try:
            subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self._bounded_timeout(_NUCLEI_TIMEOUT),
            )
        except subprocess.TimeoutExpired:
            events.append(_ev("warning", "nuclei timed out — using partial results"))
        except Exception as exc:
            events.append(_ev("warning", f"nuclei error: {exc}"))
            return result

        findings: list = []
        by_sev:   dict = {}
        if out_file.exists():
            for line in out_file.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj  = json.loads(line)
                    info = obj.get("info", {})
                    sev  = (info.get("severity") or "unknown").lower()
                    findings.append({
                        "template_id": obj.get("template-id", ""),
                        "name":        info.get("name", ""),
                        "severity":    sev,
                        "matched_at":  obj.get("matched-at") or obj.get("host", ""),
                        "type":        obj.get("type", ""),
                    })
                    by_sev[sev] = by_sev.get(sev, 0) + 1
                except Exception:
                    continue

        result["findings"]    = findings
        result["by_severity"] = by_sev
        result["count"]       = len(findings)
        if findings:
            self.tools_used.append("nuclei")
        events.append(_ev("success",
            f"nuclei — {len(findings)} finding(s): "
            + (", ".join(f"{k}:{v}" for k, v in sorted(by_sev.items())) or "none")))
        return result

    # ── Orchestration ─────────────────────────────────────────────────────────

    def execute(self) -> dict:
        """
        Run the full active-recon pipeline with two concurrent phases.
        Returns a result envelope — never raises.
        """
        events: list = []

        if not self.live_hosts:
            events.append(_ev("warning",
                "Active recon skipped — no live hosts forwarded from Module 1"))
            return self._envelope("skipped", events,
                                  {}, {}, {}, {}, {})

        events.append(_ev("info",
            f"Active Recon & Fuzzing — {len(self.live_hosts)} host(s), "
            f"budget {_TOTAL_BUDGET}s"))

        # ── Phase A: independent stages run concurrently ──────────────────────
        crawl = {"endpoints": [], "js_files": [], "count": 0}
        fuzz  = {"paths": [], "count": 0}
        ports = {"by_host": {}, "count": 0}
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                pool.submit(self._crawl, events):     "crawl",
                pool.submit(self._fuzz_dirs, events): "fuzz",
                pool.submit(self._scan_ports, events): "ports",
            }
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    res = fut.result()
                except Exception as exc:
                    events.append(_ev("warning", f"{name} stage crashed: {exc}"))
                    continue
                if   name == "crawl": crawl = res
                elif name == "fuzz":  fuzz  = res
                elif name == "ports": ports = res

        # ── Phase B: stages that depend on the crawl output ───────────────────
        endpoints = crawl.get("endpoints", []) or self.seed_endpoints
        params = {"by_endpoint": {}, "count": 0}
        nuclei = {"findings": [], "by_severity": {}, "count": 0}
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_params = pool.submit(self._discover_params, endpoints, events)
            f_nuclei = pool.submit(self._vuln_scan, endpoints, events)
            for fut in as_completed({f_params: "params", f_nuclei: "nuclei"}):
                try:
                    res = fut.result()
                except Exception as exc:
                    events.append(_ev("warning", f"phase-B stage crashed: {exc}"))
                    continue
                if fut is f_params: params = res
                else:               nuclei = res

        # ── Status verdict ────────────────────────────────────────────────────
        produced = any(d.get("count", 0) for d in (crawl, fuzz, ports, params, nuclei))
        if not self.tools_used and self.tools_missing:
            status = "skipped"
        elif self.tools_missing:
            status = "partial"
        else:
            status = "ok" if produced else "partial"

        events.append(_ev("success" if status == "ok" else "warning",
            f"Active Recon complete — crawl:{crawl['count']} fuzz:{fuzz['count']} "
            f"ports:{ports['count']} params:{params['count']} nuclei:{nuclei['count']} "
            f"| tools used: {', '.join(self.tools_used) or 'none'}"
            + (f" | missing: {', '.join(self.tools_missing)}" if self.tools_missing else "")
        ))

        return self._envelope(status, events, crawl, fuzz, ports, params, nuclei)

    def _envelope(self, status, events, crawl, fuzz, ports, params, nuclei) -> dict:
        out = {
            "status":        status,
            "events":        events,
            "crawl":         crawl,
            "fuzz":          fuzz,
            "ports":         ports,
            "params":        params,
            "nuclei":        nuclei,
            "tools_used":    sorted(set(self.tools_used)),
            "tools_missing": sorted(set(self.tools_missing)),
        }
        # Persist the aggregated result for reference / debugging.
        try:
            (self.output_dir / "active_recon.json").write_text(json.dumps(out, indent=2))
        except Exception:
            pass
        return out
