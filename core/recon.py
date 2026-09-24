"""
BountyHub v3 Enterprise — core.recon
Module 1: Automated Reconnaissance, Asset Discovery & Visual Recon

Pure data layer — no print(), no Logger, no Colors.
All terminal rendering is the caller's responsibility.

Public API
----------
ReconModule(target, output_dir).execute() → ReconResult dict:
{
    "status"       : "ok" | "empty" | "partial" | "error",
    "exit_signal"  : 0 (ok/empty) | 1 (partial) | 2 (error),
    "degraded"     : bool,
    "error_reason" : str | None,
    "events"       : [{"level": str, "msg": str}, ...],
    "subdomains"   : [str, ...],
    "live_hosts"   : [str, ...],   # always scheme-prefixed URLs
    "fallback_used": bool,
    "screenshots"  : {"<host_url>": "<absolute_fs_path_to_png>", ...},
}

Status semantics
----------------
"ok"      httpx verified live hosts.
"empty"   httpx ran correctly and the target is genuinely unreachable. This is
          a real, reportable answer — not a failure.
"error"   the probe itself broke (missing/shadowed binary, bad flags, timeout).
          No verdict about the target is possible; error_reason says why.
          Never silently downgraded into a "dead target" or a WAF guess.

Event levels: "info", "success", "warning", "error", "cmd", "data", "hosts_sample"

Screenshot notes
----------------
httpx -ss captures screenshots via headless Chromium when available.
If Chromium is absent, -ss silently produces no files; the pipeline
continues normally and the "screenshots" dict will be empty.
Screenshot FS paths are absolute; the caller is responsible for
copying them to a web-accessible location.

Rules of Engagement (RoE) — Rate-Limiting & DoS Prevention
-----------------------------------------------------------
Every subprocess call in this module is bounded by explicit rate-limiting and
hard timeouts.  The intent is passive enumeration only — never traffic flooding.

  subfinder
  ---------
  • -timeout <n>   Per-source DNS query timeout (default: Config.SUBFINDER_TIMEOUT).
                   Prevents a single slow passive source from stalling the pipeline.
  • subprocess timeout=300s  Hard wall-clock ceiling on the entire subfinder run.

  httpx
  -----
  • -rl  <n>          Hard requests-per-second cap (Config.HTTPX_RL = 30 r/s).
                      Ensures BountyHub never generates a traffic spike against the
                      target — well below any reasonable DoS threshold.
  • -threads <n>      Concurrency cap (Config.HTTPX_THREADS = 5).
                      Limits simultaneous open connections to avoid connection-flood.
                      (-c was removed upstream in httpx v1.9; -threads + -rl
                      carry the same RoE ceiling.)
  • -timeout <n>      Per-probe connect+read timeout (Config.HTTPX_TIMEOUT = 10 s).
                      Prevents hanging on unresponsive hosts.
  • -retries 0        No automatic retries — a failed probe stays failed.
                      Retries can multiply traffic; zero is the safe default.
  • -max-host-error 5 Bail on a host after 5 consecutive connection errors.
                      Prevents hammering hosts that are rate-limiting or down.
  • subprocess timeout=600s  Hard wall-clock ceiling on the entire httpx run.

  All other recon tools (nmap, whatweb) carry their own RoE flags in core.fingerprint.
"""

import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from core import Config

# Extensions worth keeping from historical URL dumps
_INTERESTING_EXTS = frozenset({
    ".js", ".json", ".xml", ".php", ".asp", ".aspx",
    ".config", ".env", ".sql", ".bak", ".yaml", ".yml",
    ".graphql", ".wsdl", ".wadl",
})


# ── Internal helpers ──────────────────────────────────────────────────────────

def _ev(level: str, msg: str) -> dict:
    return {"level": level, "msg": msg}

def _ev_data(label: str, value: str) -> dict:
    return {"level": "data", "label": label, "value": value}

def _ev_hosts(hosts: list) -> dict:
    return {"level": "hosts_sample", "hosts": hosts}


def _iter_httpx_objects(raw: str):
    """Yield JSON objects from an httpx ``-o`` file, tolerating every shape httpx
    emits:

      * JSONL — one compact object per line (standard ``-json``);
      * a single object or a JSON array (pretty-printed / small runs);
      * the headless ``-ss`` shape, a ``{"timestamp":…, "link_request":[…]}``
        object whose ``link_request`` array holds every sub-resource the browser
        fetched (this is how a redirect target's assets — e.g. an apex that 301s
        to ``www`` on a *different* registrable domain — are still captured).

    Never raises; unparseable input simply yields nothing.
    """
    raw = (raw or "").strip()
    if not raw:
        return
    # Whole-file JSON first (object or array) — covers headless + pretty-printed.
    try:
        doc = json.loads(raw)
        if isinstance(doc, list):
            for o in doc:
                if isinstance(o, dict):
                    yield o
        elif isinstance(doc, dict):
            yield doc
        return
    except json.JSONDecodeError:
        pass
    # Fall back to JSONL — one object per line (standard httpx output).
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(o, dict):
            yield o


def normalize_target(raw: str, *, with_scheme: bool = True) -> str:
    """
    Single normalisation boundary for every target string in the pipeline.

    Two consumers with opposite needs sit downstream of recon:

      * subfinder (-d) and httpx (-l) want a BARE hostname — they take hosts,
        not URLs, and choke on (or silently mangle) a scheme prefix.
      * fingerprint/whatweb, TLS inspection and JS-Oracle want a full URL and
        reject anything without an http(s):// scheme.

    Calling this at the boundary — once on the way in, once on the way out —
    is what keeps the two from being confused for each other. Do not re-derive
    schemes per-tool.

    with_scheme=False → "flagyard.com"
    with_scheme=True  → "https://flagyard.com"

    An empty/whitespace-only input returns "" so callers can filter it out.
    """
    t = (raw or "").strip()
    if not t:
        return ""

    # Strip any existing scheme so both branches start from the same shape.
    m = re.match(r'^([a-zA-Z][a-zA-Z0-9+.\-]*)://', t)
    scheme = m.group(1).lower() if m else ""
    if m:
        t = t[m.end():]

    if not with_scheme:
        # Bare host: drop path, query, fragment, userinfo and port.
        t = t.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in t:
            t = t.rsplit("@", 1)[1]
        # Keep IPv6 literals intact; only strip a trailing :port otherwise.
        if not t.startswith("[") and t.count(":") == 1:
            t = t.split(":", 1)[0]
        return t.rstrip(".").lower()

    # Preserve an explicit http:// — only default to https:// when absent.
    if scheme in ("http", "https"):
        return f"{scheme}://{t}"
    return f"https://{t}"


# A conservative hostname / IPv4 validator. The point is not RFC perfection but
# an argument-injection guard: the target flows into external tools as an argv
# element (subfinder -d, gau, waybackurls, crt.sh URL), so a value that begins
# with "-" or contains shell/format metacharacters must never reach them. This
# matters most on the BountyHub web path, where the target comes from a form.
_LABEL_RE    = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL_RE}(?:\.{_LABEL_RE})*$")
_IPV4_RE     = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
)


def is_valid_target(raw: str) -> bool:
    """True if ``raw`` reduces to a syntactically valid hostname or IPv4/IPv6.

    Rejects the empty string, a leading dash (argument injection), and anything
    carrying whitespace or shell/format metacharacters — none of which can
    appear in a real hostname and all of which are dangerous in an argv element.
    """
    host = normalize_target(raw, with_scheme=False)
    if not host or host.startswith("-"):
        return False
    if host.startswith("[") and host.endswith("]"):
        return len(host) > 2  # IPv6 literal — minimal sanity check
    if _IPV4_RE.match(host):
        return True
    return bool(_HOSTNAME_RE.match(host))


# ProjectDiscovery tools print "Current Version: vX.Y.Z" on -version. The
# Debian python3-httpx CLI cannot produce this (it exits 2 on an unknown flag).
_PD_VERSION_RE = re.compile(r"Current Version:\s*v?\d+\.\d+(?:\.\d+)*", re.IGNORECASE)
_ANSI_RE       = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _httpx_candidates() -> list:
    """
    Known install locations for ProjectDiscovery httpx, in priority order.

    Deliberately does NOT rely on $PATH ordering. BountyHub may run as a
    systemd service, in a container, or as a different user, none of which
    inherit an operator's interactive shell PATH — and where $PATH *is* set,
    Debian's /usr/bin/httpx impostor frequently precedes ~/go/bin. Every
    candidate is validated before use, so shutil.which() is kept last purely
    as extra coverage for unusual layouts, never as a source of trust.
    """
    cands: list = []

    def add(p) -> None:
        if p:
            p = str(p)
            if p not in cands:
                cands.append(p)

    # Go install targets: GOBIN wins over GOPATH/bin, which wins over ~/go/bin.
    if os.environ.get("GOBIN"):
        add(Path(os.environ["GOBIN"]) / "httpx")
    for gopath in (os.environ.get("GOPATH") or "").split(os.pathsep):
        if gopath.strip():
            add(Path(gopath.strip()) / "bin" / "httpx")
    try:
        add(Path.home() / "go" / "bin" / "httpx")
    except (RuntimeError, OSError):
        pass  # no resolvable home (some service accounts)

    # Common system-wide locations.
    for fixed in ("/usr/local/bin/httpx", "/usr/local/go/bin/httpx",
                  "/opt/go/bin/httpx", "/root/go/bin/httpx",
                  "/usr/bin/httpx"):
        add(fixed)

    add(shutil.which("httpx"))          # last resort, still fully validated
    return cands


def _identify_httpx(path: str) -> tuple:
    """
    Run `<path> -version` and decide whether it is ProjectDiscovery httpx.

    Returns (True, version_line) or (False, reason).
    """
    try:
        proc = subprocess.run([path, "-version"],
                              capture_output=True, text=True, timeout=20)
    except FileNotFoundError:
        return False, "not present"
    except PermissionError:
        return False, "not executable"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{exc.__class__.__name__}"

    blob  = _ANSI_RE.sub("", f"{proc.stdout}\n{proc.stderr}")
    match = _PD_VERSION_RE.search(blob)

    if proc.returncode == 0 and match:
        return True, match.group(0).strip()

    # Name the impostor explicitly — it is the single most common cause.
    if "No such option" in blob or "Usage: httpx [OPTIONS] URL" in blob:
        return False, ("python3-httpx impostor (Debian package python3-httpx "
                       "installs an unrelated HTTP-client CLI under this name)")
    return False, f"not projectdiscovery/httpx (exit {proc.returncode})"


def _resolve_httpx() -> tuple:
    """
    Locate ProjectDiscovery's httpx without trusting $PATH.

    Resolution order
    ----------------
    1. Config.HTTPX_BINARY (or $BOUNTYHUB_HTTPX_BINARY) when set. An explicit
       operator choice is validated but NEVER silently replaced: if it is not
       real httpx we fail here instead of quietly autodetecting something else,
       because a typo that "works anyway" hides a misconfigured deployment.
    2. Known install locations (see _httpx_candidates), each validated.

    An unverified binary is never returned. Returns (path, None) on success or
    (None, reason) on failure.
    """
    configured = getattr(Config, "HTTPX_BINARY", None)
    if configured:
        ok, detail = _identify_httpx(str(configured))
        if ok:
            return str(configured), None
        return None, (
            f"Config.HTTPX_BINARY / $BOUNTYHUB_HTTPX_BINARY points at "
            f"'{configured}', which is {detail}. Refusing to fall back to "
            f"auto-detection: fix or unset the setting so the failure cannot "
            f"be mistaken for a working scanner."
        )

    rejected = []
    for cand in _httpx_candidates():
        ok, detail = _identify_httpx(cand)
        if ok:
            return cand, None
        if detail != "not present":
            rejected.append(f"{cand} ({detail})")

    hint = (
        "Install it with `go install "
        "github.com/projectdiscovery/httpx/cmd/httpx@latest`, then set "
        "Config.HTTPX_BINARY (or the BOUNTYHUB_HTTPX_BINARY env var) to its "
        "absolute path — this is PATH-independent and works for systemd "
        "units, containers and service accounts."
    )
    if not rejected:
        return None, f"no httpx binary found in any known location. {hint}"
    return None, (
        "no valid projectdiscovery/httpx found. Rejected: "
        + "; ".join(rejected) + ". " + hint
    )


class ReconModule:
    """
    Module 1 — Automated Reconnaissance, Asset Discovery & Visual Recon.

    Resilience contract
    -------------------
    1. If subfinder returns 0 subdomains (e.g. target is already a specific
       subdomain), DO NOT abort. Fall back to [target] as the sole subdomain
       and write it to subdomains.txt so httpx can consume it.

    2. If httpx returns 0 live hosts, distinguish the two causes before
       reporting anything:
         * httpx ran correctly  → the target is genuinely unreachable.
           Report status "empty" and finish cleanly. Do NOT invent a WAF.
         * httpx itself failed  → report status "error" with error_reason and
           forward NO hosts. Never pass unverified hosts downstream: doing so
           previously made a broken run look like a WAF finding.

    3. If httpx screenshot capture fails (Chromium not installed or times out),
       the pipeline continues normally — screenshots will simply be absent.
    """

    def __init__(self, target: str, output_dir: Path) -> None:
        # Input boundary: subfinder -d and httpx -l both want a BARE hostname.
        self.target     = normalize_target(target, with_scheme=False)
        # Reject a malformed target before it ever reaches an external tool's
        # argv (argument-injection guard — critical on the web-driven path).
        if not is_valid_target(self.target):
            raise ValueError(
                f"Invalid target {target!r}: not a valid hostname or IP. "
                "Targets must be a bare domain/host (e.g. example.com), never a "
                "flag or a value containing spaces or shell characters."
            )
        self.output_dir = output_dir
        self.file_subs  = output_dir / Config.FILE_SUBDOMAINS
        self.file_live  = output_dir / Config.FILE_LIVE_HOSTS

    # ── Stage 1: subfinder ────────────────────────────────────────────────

    def _run_subfinder(self, events: list) -> list:
        """
        Run subfinder for passive subdomain enumeration.

        Returns the list of discovered subdomains.
        Falls back to [self.target] on zero results or tool errors so the
        pipeline can always continue into the httpx stage.
        """
        # Resolve by signature, not by name — the same discipline _run_httpx
        # uses. A bare "subfinder" trusts whatever $PATH offers first.
        from core import resolve_tool
        subfinder_bin, resolve_err = resolve_tool("subfinder")
        if resolve_err:
            events.append(_ev("error", f"subfinder unusable — {resolve_err}"))
            return self._subfinder_fallback(events)

        cmd = [
            subfinder_bin,
            "-d",          self.target,
            "-o",          str(self.file_subs),
            "-silent",
            # RoE — per-source DNS query timeout: prevents a slow passive source
            # from either stalling the pipeline or sending excessive DNS traffic.
            "-timeout",    str(Config.SUBFINDER_TIMEOUT),
            # RoE — passive sources only (no active DNS brute-force).
            # subfinder defaults to passive; this flag makes the intent explicit.
            "-sources",    "passive",
        ]
        events.append(_ev("info", f"subfinder — passive subdomain enumeration → {self.target}"))
        events.append(_ev("cmd", " ".join(cmd)))

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            events.append(_ev("error", "subfinder timed out after 5 minutes"))
            # Fall through — the file may be partially written
        except FileNotFoundError:
            events.append(_ev("error", "subfinder binary not found — is it installed and on $PATH?"))
            return self._subfinder_fallback(events)
        except PermissionError as exc:
            events.append(_ev("error", f"Permission denied executing subfinder: {exc}"))
            return self._subfinder_fallback(events)

        subdomains = []
        if self.file_subs.exists():
            lines      = self.file_subs.read_text().strip().splitlines()
            subdomains = [ln.strip() for ln in lines if ln.strip()]

        if subdomains:
            events.append(_ev("success",
                f"subfinder finished — {len(subdomains)} subdomain(s) discovered"
            ))
            events.append(_ev_data("Saved to", str(self.file_subs)))
            return subdomains

        return self._subfinder_fallback(events)

    def _subfinder_fallback(self, events: list) -> list:
        """
        Zero-subdomain fallback: treat the target itself as the only subdomain.
        Writes the target to subdomains.txt so httpx has a file to consume.
        """
        events.append(_ev("warning",
            f"subfinder returned 0 results for '{self.target}'. "
            "Target may already be a specific subdomain or all sources are rate-limited. "
            "Falling back to target itself as the sole entry."
        ))
        self.file_subs.write_text(self.target + "\n")
        return [self.target]

    # ── Stage 2: httpx ────────────────────────────────────────────────────

    def _run_httpx(self, subdomains: list, events: list) -> tuple:
        """
        Probe subdomains for live HTTP/HTTPS endpoints and capture screenshots.

        WAF evasion
        -----------
        -random-agent   Rotate User-Agent per request.
        -rl 30          Rate-limit to 30 req/s — avoids connection-flood drops.
        -fr             Follow redirects — catches hosts that 301 to HTTPS.

        Screenshot capture (v3)
        -----------------------
        -ss             Headless-browser screenshot of each live host.
        -srd DIR        Save screenshots to DIR/{hash}.png.
        Requires Chromium. If absent, -ss silently produces no files and
        the pipeline continues with an empty screenshot map.

        JSON output (v3)
        ----------------
        -json           Each line of the output file is a JSON object
                        containing url, status_code, screenshot_path, etc.
        The plain-text live_hosts.txt is reconstructed from the parsed URLs
        for backward compatibility with Module 2 and file-based resumption.

        Returns (live_hosts, screenshot_map, fallback_used, probe_error):
            live_hosts     : [str, ...]       — HTTP/HTTPS URLs (always scheme-prefixed)
            screenshot_map : {url: fs_path}   — only entries with real files
            fallback_used  : bool             — retained for API compatibility
            probe_error    : str | None       — set ONLY on a tool/input error,
                                                never when the target is simply
                                                unreachable. Callers branch on this
                                                to tell a broken run from a dead target.
        """
        screenshots_dir = self.output_dir / "screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        json_out = self.output_dir / "httpx_out.json"
        # httpx only creates -o when it has results; clear any stale file so a
        # previous run's output can never be mistaken for this run's.
        if json_out.exists():
            json_out.unlink()

        events.append(_ev("info",
            "httpx — probing for live HTTP/HTTPS endpoints + visual recon screenshots"
        ))

        httpx_bin, resolve_err = _resolve_httpx()
        if resolve_err:
            events.append(_ev("error", f"httpx unavailable — {resolve_err}"))
            return self._httpx_failed(events, f"httpx unavailable — {resolve_err}")

        cmd = [
            httpx_bin,
            "-l",              str(self.file_subs),
            "-o",              str(json_out),
            "-json",           # structured output — required for screenshot path extraction
            "-irh",            # include response headers in the JSON (-json only);
                               # without it httpx emits no header data and the
                               # downstream AI advisor reports "HTTP response
                               # headers missing" on every scan.
            "-irr",            # include the response body in the JSON so
                               # _discover_js_files() can extract inline <script
                               # src="…"> JS references. Without it the body is
                               # absent and live single-page apps yield zero JS
                               # files (JS-Oracle never runs) unless the .js also
                               # happens to be in the Wayback archive.
            "-silent",
            # ── RoE: concurrency caps ──────────────────────────────────────
            # Combined, these three flags ensure BountyHub never generates a
            # traffic spike that could be mistaken for a DoS attempt.
            "-threads",        str(Config.HTTPX_THREADS),       # max worker threads
            # NOTE: -c (max open connections) was removed in httpx v1.9 and now
            # aborts the run with "flag provided but not defined: -c".
            # -threads + -rl already enforce the RoE concurrency/rate ceiling.
            "-rl",             str(Config.HTTPX_RL),            # hard r/s rate cap
            # ── RoE: timeout & retry discipline ───────────────────────────
            "-timeout",        str(Config.HTTPX_TIMEOUT),       # per-probe timeout (s)
            "-retries",        "0",    # no retries — failed probes stay failed;
                                       # retries multiply traffic and can look like DoS
            "-max-host-error", "5",    # bail on a host after 5 consecutive errors;
                                       # prevents hammering hosts that are rate-limiting
            # ── Probe config ───────────────────────────────────────────────
            "-mc",             "200,201,204,301,302,307,401,403,404,405,500",
            "-random-agent",   # rotate User-Agent — reduces fingerprint noise
            "-fr",             # follow redirects — catches HTTPS canonical hosts
            # ── Visual recon ───────────────────────────────────────────────
            "-ss",             # headless screenshot per live host (Chromium required)
            "-srd",            str(screenshots_dir),
        ]
        events.append(_ev("cmd", " ".join(cmd)))

        # probe_error stays None only if httpx actually ran to completion.
        # It is the discriminator between "target is dead" and "our tooling
        # broke" — the two used to be collapsed into one bogus WAF verdict.
        probe_error: str | None = None
        timed_out = False
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout or "").strip().splitlines()
                detail = detail[-1] if detail else "no diagnostic output"
                probe_error = (
                    f"httpx exited {proc.returncode} — {detail}"
                )
                events.append(_ev("error", probe_error))
        except subprocess.TimeoutExpired:
            timed_out = True
            events.append(_ev("error", "httpx timed out after 10 minutes"))
            # Fall through — partial output may exist and is still usable.
        except FileNotFoundError:
            probe_error = "httpx binary disappeared mid-run"
            events.append(_ev("error", probe_error))
            return self._httpx_failed(events, probe_error)
        except PermissionError as exc:
            probe_error = f"httpx permission denied: {exc}"
            events.append(_ev("error", probe_error))
            return self._httpx_failed(events, probe_error)

        live_hosts:     list = []
        screenshot_map: dict = {}

        if json_out.exists():
            for line in json_out.read_text().strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    # httpx JSON uses "url" for the final (post-redirect) URL
                    url = obj.get("url") or obj.get("input", "")
                    if not url:
                        continue
                    # Output boundary: every downstream tool (whatweb, TLS
                    # inspection, JS-Oracle) requires an explicit scheme.
                    url = normalize_target(url)
                    if not url:
                        continue
                    live_hosts.append(url)

                    # Map screenshot if the file actually exists on disk
                    ss_path = obj.get("screenshot_path", "")
                    if ss_path and Path(ss_path).exists():
                        screenshot_map[url] = str(ss_path)

                except (json.JSONDecodeError, KeyError):
                    # Older httpx or -json flag not supported: fall back to
                    # treating the raw line as a plain URL.
                    normalized = normalize_target(line)
                    if normalized:
                        live_hosts.append(normalized)

        if live_hosts:
            # Write plain URL list for backward compatibility (Module 2, file resumption)
            self.file_live.write_text("\n".join(live_hosts) + "\n")
            events.append(_ev("success",
                f"httpx finished — {len(live_hosts)} live host(s) retained"
            ))
            events.append(_ev_data("Saved to", str(self.file_live)))
            events.append(_ev_hosts(live_hosts[:5]))
            if len(live_hosts) > 5:
                events.append(_ev("info", f"… and {len(live_hosts) - 5} more"))
            if screenshot_map:
                events.append(_ev("success",
                    f"Visual recon: {len(screenshot_map)} screenshot(s) captured"
                ))
            else:
                events.append(_ev("info",
                    "No screenshots captured (Chromium may not be installed — "
                    "install with: sudo apt install chromium -y)"
                ))
            return live_hosts, screenshot_map, False, None

        # ── Zero live hosts: work out WHY before saying anything ───────────
        if probe_error:
            return self._httpx_failed(events, probe_error)

        if timed_out:
            return self._httpx_failed(
                events,
                "httpx timed out after 10 minutes and produced no results — "
                "treating as a tool/network failure, not as a dead target"
            )

        if not json_out.exists():
            # httpx exited 0 but never created -o. It always creates the file
            # (possibly empty) on a clean run, so this means the invocation
            # was rejected before probing started.
            return self._httpx_failed(
                events,
                "httpx exited cleanly but wrote no output file — the "
                "invocation was likely rejected before probing began "
                "(check the flags in the logged command)"
            )

        # httpx ran to completion and genuinely observed nothing. Note that
        # -mc includes 403, so a WAF challenge WOULD have been retained as a
        # live host — reaching here means there is no WAF evidence at all.
        events.append(_ev("warning",
            f"httpx probed {len(subdomains)} host(s) and found 0 responding on "
            "HTTP/HTTPS. No challenge or block response was observed, so this "
            "is detection inconclusive: the target is either genuinely dead or "
            "silently dropping probes upstream. Not treating it as live."
        ))
        self.file_live.write_text("")
        return [], {}, False, None

    def _httpx_failed(self, events: list, reason: str) -> tuple:
        """
        Terminal httpx failure — the probe never produced a trustworthy answer.

        Deliberately returns NO hosts. The previous behaviour forwarded the raw
        subdomain list (bare, scheme-less) to Module 2, which made a broken run
        look like a successful one while whatweb silently rejected every host
        for having "no http(s) scheme". A tool error is now a hard, visible
        signal the caller branches on.
        """
        events.append(_ev("error",
            f"Live-host detection FAILED (tool error, not a target verdict): {reason}. "
            "Refusing to forward unverified hosts to Module 2 — results would be "
            "silently wrong. Fix the tooling and re-run."
        ))
        self.file_live.write_text("")
        return [], {}, False, reason

    # ── Stage 3: Full HTTP response capture ──────────────────────────────

    def _collect_http_responses(self, events: list) -> list:
        """
        Re-parse httpx_out.json to extract rich per-host metadata:
        status code, title, headers, content-type, CDN info, redirect chain.
        Non-blocking — returns [] if the file is missing or unparseable.
        """
        json_out = self.output_dir / "httpx_out.json"
        if not json_out.exists():
            events.append(_ev("warning", "http_responses: httpx_out.json not found — skipping"))
            return []

        events.append(_ev("info", "HTTP response capture — parsing full headers + metadata"))

        responses: list = []
        for obj in _iter_httpx_objects(json_out.read_text(errors="replace")):
            try:
                url = obj.get("url") or obj.get("input", "")
                if not url and obj.get("link_request"):
                    # Headless (-ss) output has no top-level url/headers; use the
                    # first captured request as the page's response so downstream
                    # stages still see the final (post-redirect) URL + status.
                    first = next((r for r in obj["link_request"]
                                  if isinstance(r, dict)), {})
                    url = first.get("URL") or first.get("url", "")
                    if url:
                        responses.append({
                            "url": url,
                            "status_code": first.get("StatusCode") or first.get("status_code"),
                            "title": "", "content_length": None, "content_type": "",
                            "webserver": "", "ip": "", "cdn": False, "cdn_name": "",
                            "cnames": [], "technologies": [], "response_headers": {},
                            "redirect_chain": [],
                        })
                    continue
                if not url:
                    continue
                responses.append({
                    "url":              url,
                    "status_code":      obj.get("status_code"),
                    "title":            obj.get("title", ""),
                    "content_length":   obj.get("content_length"),
                    "content_type":     obj.get("content_type", ""),
                    "webserver":        obj.get("webserver", ""),
                    "ip":               obj.get("host", obj.get("ip", "")),
                    "cdn":              obj.get("cdn", False),
                    "cdn_name":         obj.get("cdn_name", ""),
                    "cnames":           obj.get("cnames", []),
                    # ProjectDiscovery httpx uses "tech" for detected stack.
                    "technologies":     obj.get("tech", obj.get("technologies", [])),
                    # httpx nests response headers under "header" (singular) when
                    # -irh is set. Keep "headers" as a fallback for other tools.
                    "response_headers": obj.get("header", obj.get("headers", {})),
                    "redirect_chain":   [
                        r.get("url", "") for r in obj.get("chain_status_codes", [])
                    ],
                })
            except Exception:
                continue

        out_file = self.output_dir / "http_responses.json"
        out_file.write_text(json.dumps(responses, indent=2))
        events.append(_ev("success",
            f"HTTP responses — {len(responses)} host(s) captured → http_responses.json"
        ))
        return responses

    # ── Stage 4: Certificate Transparency (crt.sh) ───────────────────────

    def _query_crtsh(self, events: list) -> list:
        """
        Query crt.sh for all certificates ever issued for *.target.
        Extracts unique subdomains from SANs — often reveals hidden assets.
        Uses urllib (no extra tools needed). Timeout: 30 s.
        """
        events.append(_ev("info", f"crt.sh — certificate transparency lookup → {self.target}"))

        url = (
            f"https://crt.sh/?q=%.{urllib.parse.quote(self.target)}&output=json"
        )
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "BountyHub/3.0 Security Research"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))

            subdomains: set = set()
            for entry in data:
                for name in entry.get("name_value", "").splitlines():
                    # strip wildcard prefix
                    clean = name.strip().lstrip("*").lstrip(".")
                    if clean and "." in clean and clean.endswith(self.target):
                        subdomains.add(clean.lower())

            result = sorted(subdomains)
            out_file = self.output_dir / "crtsh_subdomains.json"
            out_file.write_text(json.dumps(result, indent=2))
            events.append(_ev("success",
                f"crt.sh — {len(result)} unique subdomain(s) found → crtsh_subdomains.json"
            ))
            return result

        except urllib.error.URLError as exc:
            events.append(_ev("warning", f"crt.sh request failed: {exc} — skipping"))
        except Exception as exc:
            events.append(_ev("warning", f"crt.sh lookup error: {exc} — skipping"))
        return []

    @staticmethod
    def _resolve_tool(name: str) -> str | None:
        """
        Locate a Go-based CLI (waybackurls / gau) robustly.

        These are invoked by the background scan worker, whose PATH is inherited
        from whatever launched the Flask app — commonly a service manager or a
        shell WITHOUT ~/go/bin on PATH. Relying on the bare name then silently
        fails (FileNotFoundError) and the pipeline degrades to the slower CDX
        fallback. Check PATH first, then the standard Go install locations.
        """
        found = shutil.which(name)
        if found:
            return found
        home = os.path.expanduser("~")
        candidates = [
            os.path.join(os.environ.get("GOBIN", ""), name) if os.environ.get("GOBIN") else "",
            os.path.join(os.environ.get("GOPATH", ""), "bin", name) if os.environ.get("GOPATH") else "",
            os.path.join(home, "go", "bin", name),
            f"/usr/local/go/bin/{name}",
            f"/root/go/bin/{name}",
            f"/usr/local/bin/{name}",
        ]
        for path in candidates:
            if path and os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        return None

    # ── Stage 5: Historical URLs ──────────────────────────────────────────

    def _fetch_historical_urls(self, events: list) -> list:
        """
        Collect historical URLs via:
          1. waybackurls (preferred — faster, filters out noise)
          2. gau           (fallback tool)
          3. Wayback CDX API (pure-Python last resort, no tools needed)
        Keeps only URLs with security-relevant extensions.
        Timeout per attempt: 60 s.
        """
        events.append(_ev("info", f"Historical URLs — archive enumeration → {self.target}"))

        raw_urls: list = []

        # Try waybackurls
        wb_bin = self._resolve_tool("waybackurls")
        if wb_bin:
            try:
                proc = subprocess.run(
                    [wb_bin, self.target],
                    capture_output=True, text=True, timeout=60,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    raw_urls = proc.stdout.strip().splitlines()
                    events.append(_ev("info", f"waybackurls → {len(raw_urls)} raw URLs"))
            except subprocess.TimeoutExpired:
                events.append(_ev("warning", "waybackurls timed out after 60 s"))
        else:
            events.append(_ev("info", "waybackurls not installed — trying gau / CDX fallback"))

        # Try gau if waybackurls yielded nothing
        if not raw_urls:
            gau_bin = self._resolve_tool("gau")
            if gau_bin:
                try:
                    proc = subprocess.run(
                        [gau_bin, "--threads", "5", self.target],
                        capture_output=True, text=True, timeout=60,
                    )
                    if proc.returncode == 0 and proc.stdout.strip():
                        raw_urls = proc.stdout.strip().splitlines()
                        events.append(_ev("info", f"gau → {len(raw_urls)} raw URLs"))
                except subprocess.TimeoutExpired:
                    events.append(_ev("warning", "gau timed out after 60 s"))
            else:
                events.append(_ev("info", "gau not installed — using CDX API fallback"))

        # Pure-Python CDX API fallback
        if not raw_urls:
            try:
                cdx_url = (
                    "https://web.archive.org/cdx/search/cdx"
                    f"?url=*.{urllib.parse.quote(self.target)}/*"
                    "&output=text&fl=original&collapse=urlkey&limit=5000"
                )
                req = urllib.request.Request(
                    cdx_url,
                    headers={"User-Agent": "BountyHub/3.0 Security Research"},
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                raw_urls = [u for u in body.strip().splitlines() if u.startswith("http")]
                events.append(_ev("info", f"Wayback CDX API → {len(raw_urls)} raw URLs"))
            except Exception as exc:
                events.append(_ev("warning", f"Wayback CDX API failed: {exc} — skipping"))

        if not raw_urls:
            events.append(_ev("warning", "No historical URL source available — skipping"))
            return []

        # Filter to security-relevant extensions only
        def _is_interesting(u: str) -> bool:
            path = u.split("?")[0].lower()
            return any(path.endswith(ext) for ext in _INTERESTING_EXTS)

        filtered = [u for u in raw_urls if _is_interesting(u)]

        out_file = self.output_dir / "historical_urls.json"
        out_file.write_text(json.dumps(filtered, indent=2))
        events.append(_ev("success",
            f"Historical URLs — {len(filtered)} interesting endpoint(s) "
            f"(from {len(raw_urls)} total) → historical_urls.json"
        ))
        return filtered

    # ── Stage 6: JavaScript file discovery ───────────────────────────────

    def _discover_js_files(
        self, live_hosts: list, historical_urls: list, events: list
    ) -> list:
        """
        Compile a deduplicated list of JavaScript file URLs from every source:
          • historical_urls filtered to *.js
          • httpx_out.json — the headless (-ss) "link_request" resources AND any
            standard body/href fields (inline <script src> extraction)
          • a catch-all sweep for absolute .js URLs anywhere in the httpx output
        Saves js_files.json for JS-Oracle to consume.

        The link_request + catch-all sources are what make a redirecting apex work:
        e.g. nour.net.sa 301s to www.nournet.sa, the headless browser fetches
        www.nournet.sa's scripts, and those .js URLs are harvested here even though
        a same-domain crawler scope would never follow the cross-domain redirect.
        """
        events.append(_ev("info", "JS discovery — extracting JavaScript file endpoints"))

        js_urls: set = set()

        def _is_js(u: str) -> bool:
            return u.split("?", 1)[0].lower().endswith(".js")

        # Source 1: historical URLs
        for url in historical_urls:
            if _is_js(url):
                js_urls.add(url.split("?")[0])

        json_out = self.output_dir / "httpx_out.json"
        if json_out.exists():
            raw      = json_out.read_text(errors="replace")
            _rel_re  = re.compile(r'["\']([^"\'<>\s]*\.js(?:\?[^"\'<>\s]*)?)["\']')

            # Source 2: structured parse (link_request resources, own url, body).
            for obj in _iter_httpx_objects(raw):
                base = obj.get("url") or obj.get("input") or ""
                if base and _is_js(base):
                    js_urls.add(base.split("?")[0])
                for req in obj.get("link_request", []) or []:
                    if not isinstance(req, dict):
                        continue
                    u = req.get("URL") or req.get("url") or ""
                    if u and _is_js(u):
                        js_urls.add(u.split("?")[0])
                body = obj.get("body", "") or obj.get("response", "") or ""
                for match in _rel_re.findall(body[:50_000]):
                    if match.startswith("http"):
                        js_urls.add(match.split("?")[0])
                    elif match.startswith("/") and base:
                        p = urllib.parse.urlparse(base)
                        js_urls.add(f"{p.scheme}://{p.netloc}" + match.split("?")[0])

            # Source 3: bulletproof catch-all — every absolute .js URL in the raw
            # output, regardless of the JSON shape the httpx build produced.
            for m in re.findall(r'https?://[^\s"\'<>\\]+?\.js(?:\?[^\s"\'<>\\]*)?', raw):
                js_urls.add(m.split("?")[0])

        result = sorted(js_urls)
        out_file = self.output_dir / "js_files.json"
        out_file.write_text(json.dumps(result, indent=2))
        events.append(_ev("success",
            f"JS discovery — {len(result)} unique JS file(s) → js_files.json"
        ))
        return result

    # ── Public interface ──────────────────────────────────────────────────

    def execute(self) -> dict:
        """
        Run the full recon pipeline: subfinder → httpx (+screenshots).

        Returns a result envelope — never raises; status reflects outcome.
        """
        events: list = []

        subdomains                                    = self._run_subfinder(events)
        live_hosts, screenshot_map, fallback, probe_error = self._run_httpx(
            subdomains, events)

        if probe_error:
            # Tool/input error — loud failure, never dressed up as a finding.
            status = "error"
            events.append(_ev("error",
                "Module 1 FAILED — live-host detection is broken, so no verdict "
                "about this target can be trusted. Pipeline halted."
            ))
        elif not live_hosts:
            # Genuinely nothing responding. Not an error, not a success.
            status = "empty"
            events.append(_ev("warning",
                "Module 1 complete — target appears DEAD (0 responding hosts). "
                "Nothing to forward to Module 2."
            ))
        elif fallback:
            status = "partial"
            events.append(_ev("success",
                f"Module 1 complete (fallback mode) — "
                f"{len(live_hosts)} host(s) forwarded to Module 2"
            ))
        else:
            status = "ok"
            events.append(_ev("success",
                f"Module 1 complete — {len(live_hosts)} live target(s) ready"
            ))

        # ── Enrichment stages (non-blocking — each failure is logged + skipped)
        http_responses  = self._collect_http_responses(events)
        crtsh_subs      = self._query_crtsh(events)
        historical_urls = self._fetch_historical_urls(events)
        js_files        = self._discover_js_files(live_hosts, historical_urls, events)

        return {
            "status":           status,
            # Non-zero-style signal the pipeline branches on: 0 = trustworthy,
            # 1 = degraded, 2 = tool error (no verdict possible).
            "exit_signal":      {"ok": 0, "empty": 0, "partial": 1, "error": 2}[status],
            "degraded":         status in ("partial", "error"),
            "error_reason":     probe_error,
            "events":           events,
            "subdomains":       subdomains,
            "live_hosts":       live_hosts,
            "fallback_used":    fallback,
            "screenshots":      screenshot_map,
            "http_responses":   http_responses,
            "crtsh_subdomains": crtsh_subs,
            "historical_urls":  historical_urls,
            "js_files":         js_files,
        }
