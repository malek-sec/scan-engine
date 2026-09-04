"""
BountyHub v2 — core.fingerprint
Module 2: Technology Stack Fingerprinting & Attack Surface Mapping

Pure data layer — no print(), no Logger, no Colors.
All terminal rendering is the caller's responsibility.

Public API
----------
FingerprintModule(live_hosts, output_dir).execute() → FingerprintResult dict:
{
    "status"  : "ok" | "partial" | "error",
    "events"  : [{"level": str, ...}, ...],
    "results" : [
        {
            "host"           : str,
            "scan_timestamp" : str (ISO-8601),
            "open_ports"     : [str, ...],
            "technologies"   : {
                "web_server"          : str,
                "cms"                 : str | None,
                "language"            : str | None,
                "javascript_libraries": [str, ...],
                "other"               : [str, ...]
            },
            "raw_nmap"       : str,
            "nmap_error"     : str | None,
            "whatweb_error"  : str | None,
        },
        ...
    ],
}

Event levels: "info", "success", "warning", "error", "cmd", "data", "host_header"
"""

import json
import os
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from core import Config


# ── Hostname allow-list regex ─────────────────────────────────────────────────
# Only well-formed DNS labels are permitted as subprocess arguments.
# Rejects anything that could be interpreted as a flag (e.g. "--script=..."),
# an IP with embedded options, or a shell metacharacter sequence.
_HOSTNAME_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
)

# Allowed file extensions for whatweb target URLs (must start with http scheme)
_HTTP_SCHEME_RE = re.compile(r'^https?://', re.IGNORECASE)


def _extract_hostname(host: str) -> str | None:
    """
    Strip the HTTP(S) scheme, path, and port from a host URL and return the
    bare hostname.  Returns None if the result fails strict DNS validation —
    the caller must skip subprocess execution in that case.
    """
    raw = re.sub(r'^https?://', '', host, flags=re.IGNORECASE)
    raw = raw.split('/')[0].split(':')[0].strip()
    if _HOSTNAME_RE.match(raw):
        return raw
    return None


# ── Internal helpers ──────────────────────────────────────────────────────────

def _ev(level: str, msg: str) -> dict:
    return {"level": level, "msg": msg}

def _ev_data(label: str, value: str) -> dict:
    return {"level": "data", "label": label, "value": value}

def _ev_host(idx: int, total: int, host: str) -> dict:
    """Signals the start of per-host processing for the CLI to render."""
    return {"level": "host_header", "idx": idx, "total": total, "host": host}


class FingerprintModule:
    """
    Module 2 — Technology Stack Fingerprinting and Attack Surface Mapping.

    Runs nmap + whatweb against every host in live_hosts, collects structured
    results, and persists them to fingerprint.json.
    """

    def __init__(self, live_hosts: list, output_dir: Path) -> None:
        self.live_hosts       = live_hosts
        self.output_dir       = output_dir
        self.fingerprint_file = output_dir / Config.FILE_FINGERPRINT

    # ── nmap ──────────────────────────────────────────────────────────────

    def _run_nmap(self, host: str, events: list) -> dict:
        """
        Top-1000 port scan with service version detection.
        Returns {"open_ports": [...], "raw_output": str, "error": str|None}.
        """
        hostname = _extract_hostname(host)
        if hostname is None:
            events.append(_ev("warning",
                f"nmap skipped — '{host}' did not pass strict hostname "
                "validation (possible argument-injection attempt)"))
            return {"open_ports": [], "raw_output": "", "error": "invalid_hostname"}

        events.append(_ev("info", f"nmap → {hostname}"))

        cmd = [
            "nmap",
            "--top-ports", str(Config.NMAP_TOP_PORTS),   # 50 — minimal footprint
            "-sV",
            "--open",
            f"-T{Config.NMAP_TIMING}",                   # T2 = polite timing
            "--max-rate",  str(Config.NMAP_MAX_RATE),    # 10 pkts/s — never floods
            "-oN", "-",
            hostname,
        ]
        events.append(_ev("cmd", " ".join(cmd)))

        try:
            proc  = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # T2 needs more time
            raw   = proc.stdout
            ports = [
                line.strip()
                for line in raw.splitlines()
                if ("/tcp" in line or "/udp" in line) and "open" in line
            ]

            if ports:
                events.append(_ev_data("Open ports", str(len(ports))))
            else:
                events.append(_ev("warning", f"No open ports detected on {hostname}"))

            return {"open_ports": ports, "raw_output": raw[:3000], "error": None}

        except subprocess.TimeoutExpired:
            events.append(_ev("warning", f"nmap timed out on {hostname}"))
            return {"open_ports": [], "raw_output": "TIMEOUT", "error": "timeout"}
        except FileNotFoundError:
            events.append(_ev("error", "nmap binary not found"))
            return {"open_ports": [], "raw_output": "", "error": "not_found"}
        except PermissionError as exc:
            events.append(_ev("error", f"nmap permission error (try sudo): {exc}"))
            return {"open_ports": [], "raw_output": "", "error": str(exc)}

    # ── whatweb ───────────────────────────────────────────────────────────

    def _run_whatweb(self, host: str, events: list) -> dict:
        """
        WhatWeb technology fingerprinting via JSON log output.
        Returns a technology dict plus an "error" key (None on success).
        """
        # Validate the scheme prefix and the embedded hostname separately so
        # neither can smuggle flags or shell characters into the argv list.
        if not _HTTP_SCHEME_RE.match(host):
            events.append(_ev("warning",
                f"whatweb skipped — '{host}' has no http(s) scheme"))
            return {
                "web_server": "Unknown", "cms": None, "language": None,
                "javascript_libraries": [], "other": [], "error": "invalid_host",
            }
        _bare = _extract_hostname(host)
        if _bare is None:
            events.append(_ev("warning",
                f"whatweb skipped — '{host}' did not pass strict hostname "
                "validation (possible argument-injection attempt)"))
            return {
                "web_server": "Unknown", "cms": None, "language": None,
                "javascript_libraries": [], "other": [], "error": "invalid_hostname",
            }

        events.append(_ev("info", f"whatweb → {host}"))

        tmp      = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        tmp_path = tmp.name
        tmp.close()

        cmd = [
            "whatweb",
            "--log-json", tmp_path,
            "-a", str(Config.WHATWEB_AGGRESSION),  # 1 = passive/stealthy
            "--quiet",
            host,
        ]
        events.append(_ev("cmd", " ".join(cmd)))

        tech: dict = {
            "web_server":           "Unknown",
            "cms":                  None,
            "language":             None,
            "javascript_libraries": [],
            "other":                [],
            "error":                None,
        }

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=30)  # level-1 is fast

            if not os.path.exists(tmp_path):
                return tech

            raw = Path(tmp_path).read_text().strip()
            if not raw:
                return tech

            # WhatWeb emits one JSON object per line; take the first parseable one
            data = None
            for line in raw.splitlines():
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        break
                    except json.JSONDecodeError:
                        continue

            if data is None:
                events.append(_ev("warning", f"WhatWeb JSON unparseable for {host}"))
                return tech

            plugins = data.get("plugins", {})

            # Web server
            for server in ("Nginx", "Apache", "IIS", "LiteSpeed", "Caddy", "OpenResty"):
                if server in plugins:
                    ver = (plugins[server].get("version") or [""])[0]
                    tech["web_server"] = f"{server} {ver}".strip()
                    break
            if tech["web_server"] == "Unknown" and "Server" in plugins:
                strs = plugins["Server"].get("string", [])
                tech["web_server"] = strs[0] if strs else "Unknown"

            # CMS
            for cms in ("WordPress", "Drupal", "Joomla", "Magento",
                        "Shopify", "Ghost", "TYPO3", "Squarespace"):
                if cms in plugins:
                    ver = (plugins[cms].get("version") or [""])[0]
                    tech["cms"] = f"{cms} {ver}".strip()
                    break

            # Backend language / framework
            for lang in ("PHP", "Ruby-on-Rails", "Python", "Java",
                         "ASP.NET", "Node.js", "Go", "Perl"):
                if lang in plugins:
                    ver = (plugins[lang].get("version") or [""])[0]
                    tech["language"] = f"{lang} {ver}".strip()
                    break

            # JavaScript libraries
            for lib in ("jQuery", "React", "Angular", "Vue.js",
                        "Bootstrap", "Lodash", "Prototype", "Mootools"):
                if lib in plugins:
                    ver = (plugins[lib].get("version") or [""])[0]
                    tech["javascript_libraries"].append(f"{lib} {ver}".strip())

            # Everything else
            categorised = {
                "Nginx", "Apache", "IIS", "LiteSpeed", "Caddy", "OpenResty", "Server",
                "WordPress", "Drupal", "Joomla", "Magento", "Shopify",
                "Ghost", "TYPO3", "Squarespace",
                "PHP", "Ruby-on-Rails", "Python", "Java", "ASP.NET", "Node.js", "Go", "Perl",
                "jQuery", "React", "Angular", "Vue.js", "Bootstrap",
                "Lodash", "Prototype", "Mootools",
            }
            for name, pdata in plugins.items():
                if name not in categorised:
                    ver = ""
                    if isinstance(pdata, dict) and pdata.get("version"):
                        ver = pdata["version"][0]
                    tech["other"].append(f"{name} {ver}".strip())

            # Emit data events for the CLI to render
            if tech["web_server"] != "Unknown":
                events.append(_ev_data("Server",   tech["web_server"]))
            if tech["cms"]:
                events.append(_ev_data("CMS",      tech["cms"]))
            if tech["language"]:
                events.append(_ev_data("Language", tech["language"]))

            return tech

        except subprocess.TimeoutExpired:
            events.append(_ev("warning", f"WhatWeb timed out on {host}"))
            tech["error"] = "timeout"
            return tech
        except FileNotFoundError:
            events.append(_ev("error", "whatweb binary not found"))
            tech["error"] = "not_found"
            return tech
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    # ── TLS / Certificate Inspection ─────────────────────────────────────

    def _inspect_tls(self, host: str, events: list) -> dict:
        """
        Inspect TLS certificate + session via openssl s_client.
        Only runs on https:// hosts. Non-blocking — returns {} on any failure.

        Extracts: subject, issuer, validity dates, SANs, protocol, cipher.
        SANs are the key output — they reveal additional subdomains and assets
        that were never discovered via passive DNS enumeration.
        """
        if not host.startswith("https://"):
            return {}

        hostname = _extract_hostname(host)
        if hostname is None:
            return {}

        events.append(_ev("info", f"TLS → {hostname}"))

        tls: dict = {
            "hostname":   hostname,
            "subject":    None,
            "issuer":     None,
            "not_before": None,
            "not_after":  None,
            "san":        [],
            "protocol":   None,
            "cipher":     None,
            "error":      None,
        }

        try:
            # Single openssl s_client call — gives cert + session info
            proc = subprocess.run(
                [
                    "openssl", "s_client",
                    "-connect", f"{hostname}:443",
                    "-servername", hostname,
                    "-showcerts",
                ],
                input="Q\n",
                capture_output=True, text=True, timeout=15,
            )
            raw = proc.stdout + proc.stderr

            # Parse TLS session metadata
            proto_m  = re.search(r'Protocol\s*:\s*(\S+)', raw)
            cipher_m = re.search(r'Cipher\s*:\s*(\S+)', raw)
            if proto_m:
                tls["protocol"] = proto_m.group(1).strip()
            if cipher_m:
                tls["cipher"] = cipher_m.group(1).strip()

            # Extract first PEM certificate and parse via openssl x509
            cert_m = re.search(
                r'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)',
                raw, re.DOTALL,
            )
            if cert_m:
                x509 = subprocess.run(
                    [
                        "openssl", "x509", "-noout",
                        "-subject", "-issuer", "-dates",
                        "-ext", "subjectAltName",
                    ],
                    input=cert_m.group(1),
                    capture_output=True, text=True, timeout=10,
                )
                for line in x509.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("subject="):
                        tls["subject"] = line[8:].strip()
                    elif line.startswith("issuer="):
                        tls["issuer"] = line[7:].strip()
                    elif line.startswith("notBefore="):
                        tls["not_before"] = line[10:].strip()
                    elif line.startswith("notAfter="):
                        tls["not_after"] = line[9:].strip()
                    elif "DNS:" in line:
                        tls["san"] = re.findall(r'DNS:([^,\s]+)', line)

            if tls["san"]:
                events.append(_ev_data("TLS SANs", str(len(tls["san"]))))
            if tls["protocol"]:
                events.append(_ev_data("TLS protocol", tls["protocol"]))

        except subprocess.TimeoutExpired:
            tls["error"] = "timeout"
            events.append(_ev("warning", f"TLS inspection timed out: {hostname}"))
        except FileNotFoundError:
            tls["error"] = "openssl_not_found"
            events.append(_ev("warning", "openssl not found — TLS inspection skipped"))
        except Exception as exc:
            tls["error"] = str(exc)

        return tls

    # ── Public interface ──────────────────────────────────────────────────

    def execute(self) -> dict:
        """
        Fingerprint every live host and persist results to fingerprint.json.

        Returns a result envelope — never raises.
        """
        events:      list = []
        results:     list = []
        tls_results: list = []

        if not self.live_hosts:
            events.append(_ev("error", "No live hosts provided — run Module 1 first"))
            return {"status": "error", "events": events, "results": []}

        total = len(self.live_hosts)
        events.append(_ev("info", f"Fingerprinting {total} live host(s)…"))

        for idx, host in enumerate(self.live_hosts, 1):
            events.append(_ev_host(idx, total, host))

            nmap_data    = self._run_nmap(host, events)
            whatweb_data = self._run_whatweb(host, events)
            tls_data     = self._inspect_tls(host, events)

            # Strip internal "error" key before storing in results
            tech = {k: v for k, v in whatweb_data.items() if k != "error"}

            results.append({
                "host":           host,
                "scan_timestamp": datetime.now().isoformat(),
                "open_ports":     nmap_data["open_ports"],
                "technologies":   tech,
                "tls":            tls_data,
                "raw_nmap":       nmap_data["raw_output"],
                "nmap_error":     nmap_data["error"],
                "whatweb_error":  whatweb_data.get("error"),
            })

            if tls_data:
                tls_results.append(tls_data)

        # Persist fingerprint.json — Module 3 input contract
        self.fingerprint_file.write_text(json.dumps(results, indent=2))
        events.append(_ev("success",
            f"Module 2 complete — {len(results)} host(s) fingerprinted → {self.fingerprint_file}"
        ))

        # Persist tls_inspection.json separately for AI consumption
        if tls_results:
            tls_file = self.output_dir / "tls_inspection.json"
            tls_file.write_text(json.dumps(tls_results, indent=2))
            events.append(_ev("success",
                f"TLS inspection — {len(tls_results)} host(s) → tls_inspection.json"
            ))

        status = "ok" if results else "error"
        return {"status": status, "events": events, "results": results}
