#!/usr/bin/env python3
"""
BountyHub v2 — cli.main
Argument parser + top-level orchestrator + all terminal rendering.

This module is the ONLY place that imports Colors/Logger and calls print().
The core/* modules are pure data libraries — they return structured result
envelopes that this module renders into coloured terminal output.

Usage
-----
  python3 BountyHub_v2/cli/main.py full          --target example.com
  python3 BountyHub_v2/cli/main.py recon         --target example.com
  python3 BountyHub_v2/cli/main.py fingerprint   --target example.com
  python3 BountyHub_v2/cli/main.py advise        --target example.com
  python3 BountyHub_v2/cli/main.py report

Environment Variables
---------------------
  GEMINI_API_KEY   Required for 'advise' and 'report'.
                   export GEMINI_API_KEY='AIza...'
"""

import argparse
import json
import re
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Ensure BountyHub_v2/ is on sys.path so `core` is importable ─────────────
_HERE = Path(__file__).resolve()
_ROOT = _HERE.parent.parent          # BountyHub_v2/
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core import Colors, Config, DependencyChecker, Logger
from core.recon import ReconModule
from core.fingerprint import FingerprintModule
from core.ai_advisor import AIAdvisorModule
from core.js_oracle import JSOracle


# ═════════════════════════════════════════════════════════════════════════════
# EVENT RENDERER
# Translates the structured event dicts emitted by core modules into
# the coloured terminal output operators see.  This is the single seam
# between the pure-data core and the CLI presentation layer.
# ═════════════════════════════════════════════════════════════════════════════

def render_events(events: list) -> None:
    """
    Replay a list of event dicts produced by a core module through Logger/Colors.

    Supported event shapes
    ----------------------
    {"level": "info"|"success"|"warning"|"error",  "msg": str}
    {"level": "cmd",         "msg": str}
    {"level": "data",        "label": str, "value": str}
    {"level": "hosts_sample","hosts": [str, ...]}
    {"level": "host_header", "idx": int, "total": int, "host": str}
    {"level": "analysis",    "host": str, "text": str}
    """
    for ev in events:
        level = ev.get("level", "info")

        if level == "info":
            Logger.info(ev["msg"])
        elif level == "success":
            Logger.success(ev["msg"])
        elif level == "warning":
            Logger.warning(ev["msg"])
        elif level == "error":
            Logger.error(ev["msg"])
        elif level == "cmd":
            Logger.cmd(ev["msg"])
        elif level == "data":
            Logger.data(ev["label"], ev["value"])
        elif level == "hosts_sample":
            Logger.info("Sample live hosts:")
            for h in ev["hosts"]:
                print(f"      {Colors.SUCCESS}→{Colors.RESET} {h}")
        elif level == "host_header":
            Logger.info(
                f"\n[{ev['idx']}/{ev['total']}] "
                f"{Colors.CYAN}{ev['host']}{Colors.RESET}"
            )
        elif level == "analysis":
            render_ai_analysis(ev["host"], ev["text"])


def render_ai_analysis(host_url: str, analysis: str) -> None:
    """
    Render Gemini AI analysis text with rich terminal formatting.

    Visual language
    ---------------
    Magenta box border  → AI-generated content boundary
    Cyan + underline    → ## section headers
    Yellow bold         → ### subsection headers
    Green bullet        → list items
    Gray                → code blocks
    """
    C     = Colors
    width = 70

    print(f"\n{C.MAGENTA}{C.BOLD}╔{'═' * (width - 2)}╗{C.RESET}")
    title = f"  GEMINI AI ANALYSIS  ·  {host_url}"
    print(f"{C.MAGENTA}{C.BOLD}║{title:<{width - 2}}║{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}╚{'═' * (width - 2)}╝{C.RESET}\n")

    in_code_block = False

    for line in analysis.split("\n"):
        s = line.rstrip()

        if s.startswith("```"):
            in_code_block = not in_code_block
            print(f"  {C.GRAY}{s}{C.RESET}")
            continue

        if in_code_block:
            print(f"  {C.GRAY}{s}{C.RESET}")
            continue

        if s.startswith("## "):
            text = s[3:]
            print(f"\n  {C.CYAN}{C.BOLD}{C.UNDERLINE}{text}{C.RESET}")
            print(f"  {C.CYAN}{'─' * min(len(text) + 4, width - 4)}{C.RESET}")
        elif s.startswith("### "):
            print(f"\n  {C.YELLOW}{C.BOLD}{s[4:]}{C.RESET}")
        elif s.startswith("**") and s.endswith("**") and len(s) > 4:
            print(f"  {C.WHITE}{C.BOLD}{s}{C.RESET}")
        elif s.startswith("- **"):
            print(f"  {C.GREEN}•{C.RESET} {C.WHITE}{s[2:]}{C.RESET}")
        elif s.startswith(("- ", "* ")):
            print(f"  {C.GREEN}•{C.RESET} {s[2:]}")
        elif s[:2] in ("1.", "2.", "3.", "4.", "5."):
            print(f"  {C.YELLOW}{s}{C.RESET}")
        elif s == "---":
            print(f"\n  {C.GRAY}{'─' * (width - 4)}{C.RESET}")
        elif s:
            print(f"  {s}")
        else:
            print()

    print(f"\n{C.MAGENTA}{'─' * width}{C.RESET}\n")


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 4 — Interactive Report Synthesizer
# Lives here (not in core/) because it is inherently interactive (stdin)
# and depends on terminal output — it cannot be a pure-data library.
# ═════════════════════════════════════════════════════════════════════════════

try:
    from google import genai as _genai
    from google.genai import types as _genai_types
    _GENAI_AVAILABLE = True
except ImportError:
    _GENAI_AVAILABLE = False


class ReportModule:
    """
    Module 4 — Automated Proof of Concept and Final Report Synthesizer.

    Workflow
    --------
    1. Interactively collect vulnerability metadata from the operator
       (programme, endpoint, vuln type, severity, raw Burp HTTP data).
    2. Build a heavily-constrained Gemini prompt.
    3. Send to gemini-2.5-flash via google-genai SDK.
    4. Save the fully-formatted Markdown report to disk.
    """

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self._client    = None

    # ── Client initialisation ─────────────────────────────────────────────

    def _init_client(self) -> bool:
        if not _GENAI_AVAILABLE:
            Logger.error("google-genai is not installed — run: pip install google-genai")
            return False
        if not Config.api_key_present():
            Logger.error("GEMINI_API_KEY is not set")
            Logger.warning("export GEMINI_API_KEY='AIza…'")
            return False
        try:
            import os
            self._client = _genai.Client(api_key=os.environ["GEMINI_API_KEY"])
            Logger.success("Gemini client ready for report generation")
            return True
        except Exception as exc:
            Logger.error(f"Client init failed: {exc}")
            return False

    # ── Interactive input ─────────────────────────────────────────────────

    def _multiline_input(self, prompt_label: str, end_sentinel: str = "END") -> str:
        print(
            f"\n{Colors.CYAN}[?]{Colors.RESET} Paste the raw HTTP "
            f"{Colors.BOLD}{prompt_label}{Colors.RESET} from Burp Suite Repeater.\n"
            f"    {Colors.GRAY}(Type '{end_sentinel}' on its own line when done){Colors.RESET}"
        )
        print(f"    {Colors.YELLOW}─── BEGIN {prompt_label} ───{Colors.RESET}")
        lines: list = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line.strip().upper() == end_sentinel.upper():
                break
            lines.append(line)
        print(f"    {Colors.YELLOW}─── END {prompt_label} ───{Colors.RESET}")
        return "\n".join(lines)

    def _collect_vuln_data(self) -> Optional[dict]:
        Logger.section("MODULE 4 — Report Generation: Input Collection")
        print(
            f"\n{Colors.YELLOW}This module generates a professional, platform-ready bug bounty report.\n"
            f"You will need: programme name, affected URL, vulnerability type,\n"
            f"Burp Suite HTTP request and response.{Colors.RESET}\n"
        )

        try:
            data: dict = {}
            data["programme"] = input(f"{Colors.CYAN}[?]{Colors.RESET} Bug bounty programme name: ").strip()
            data["endpoint"]  = input(f"{Colors.CYAN}[?]{Colors.RESET} Affected URL / endpoint: ").strip()
            data["vuln_type"] = input(f"{Colors.CYAN}[?]{Colors.RESET} Vulnerability type (e.g., Stored XSS, IDOR, SQLi): ").strip()

            print(f"\n{Colors.CYAN}[?]{Colors.RESET} Severity:")
            sev_opts = [
                ("1", "Critical", "9.0–10.0", Colors.RED),
                ("2", "High",     "7.0–8.9",  Colors.RED),
                ("3", "Medium",   "4.0–6.9",  Colors.YELLOW),
                ("4", "Low",      "0.1–3.9",  Colors.GREEN),
                ("5", "Info",     "N/A",       Colors.BLUE),
            ]
            for key, label, cvss, col in sev_opts:
                print(f"    {col}[{key}]{Colors.RESET} {label:<12} CVSS {cvss}")

            sev_map = {k: label for k, label, _, _ in sev_opts}
            sev_raw = input(f"    {Colors.CYAN}→{Colors.RESET} Choice [1-5]: ").strip()
            data["severity"] = sev_map.get(sev_raw, "Medium")

            data["http_request"]  = self._multiline_input("REQUEST")
            data["http_response"] = self._multiline_input("RESPONSE")
            data["notes"] = input(
                f"\n{Colors.CYAN}[?]{Colors.RESET} Additional context / notes (optional, Enter to skip): "
            ).strip()

            if not data["endpoint"] or not data["vuln_type"]:
                Logger.error("Endpoint and vulnerability type are required — aborting")
                return None

            return data

        except KeyboardInterrupt:
            print()
            Logger.warning("Report generation cancelled by operator")
            return None

    # ── Prompt ────────────────────────────────────────────────────────────

    def _build_report_prompt(self, d: dict) -> str:
        today = datetime.now().strftime("%Y-%m-%d")
        return f"""You are a world-class application security researcher and professional bug bounty hunter. Your reports are consistently accepted at maximum bounty and praised by triage teams for clarity and completeness.

Generate a complete, publication-ready bug bounty report. Follow the EXACT structure below — no deviations, no omitted sections.

─── VULNERABILITY DATA ─────────────────────────────────────────────────────
Programme   : {d.get('programme',  'Unknown Programme')}
Endpoint    : {d.get('endpoint',   'Unknown')}
Vuln Type   : {d.get('vuln_type',  'Unknown')}
Severity    : {d.get('severity',   'Medium')}
Notes       : {d.get('notes',      'None')}

HTTP Request:
```http
{d.get('http_request',  '(not provided)')}
```

HTTP Response:
```http
{d.get('http_response', '(not provided)')}
```
────────────────────────────────────────────────────────────────────────────

# [Specific, descriptive title referencing the exact vulnerability and component]

## Summary
[2-3 technically precise sentences: what it is, where it exists, worst-case impact.]

## Vulnerability Details

| Field | Value |
|---|---|
| **Type** | {d.get('vuln_type', 'TBD')} (CWE-XXX) |
| **Severity** | {d.get('severity', 'Medium')} |
| **CVSS 3.1** | [vector string + numeric score] |
| **Affected Endpoint** | `{d.get('endpoint', 'TBD')}` |
| **Auth Required** | [Yes/No + role] |
| **User Interaction** | [Yes/No] |

## Business Impact
[3-4 sentences for a non-technical CISO audience. Business consequences only — no technical re-description.]

## Technical Description
[Root-cause analysis: why the vulnerability exists, which control is absent, how the app processes malicious input.]

## Steps to Reproduce

> **Prerequisites:** [required account level / network position]

1. Navigate to: [exact URL]
2. [Specific action]
3. Inject: [exact payload in inline code]
4. Observe: [what confirms exploitability]
5. Impact: [what the attacker can now do]

## Proof of Concept

### Vulnerable Request
```http
{d.get('http_request', '(paste request here)')}
```

### Response Confirming Vulnerability
```http
{d.get('http_response', '(paste response here)')}
```

### Exploit Code
```python
#!/usr/bin/env python3
# {d.get('vuln_type', 'Vulnerability')} — Proof of Concept
# Target   : {d.get('endpoint', 'TARGET')}
# Programme: {d.get('programme', 'PROGRAMME')}
# Date     : {today}
# WARNING  : For authorised testing only.

[Full working exploit — no placeholder logic, no pseudocode.]
```

## Impact Assessment

| Dimension | Rating | Justification |
|---|---|---|
| **Confidentiality** | High/Medium/Low | [why] |
| **Integrity** | High/Medium/Low | [why] |
| **Availability** | High/Medium/Low | [why] |
| **Scope** | Changed/Unchanged | [why] |

## Mitigation Recommendations

### Immediate (0-24 hours)
1. [Concrete triage action]

### Short-term Fix (1-2 weeks)
1. [Code-level remediation with framework guidance]

### Secure Code Example
```python
# ── Vulnerable ──
[insecure pattern]
# ── Secure ──
[corrected implementation with defence comment]
```

## References
- [CWE link]
- [OWASP link]
- [CVE if applicable]

---
*Generated by BountyHub v2 — {today}*"""

    # ── API call ──────────────────────────────────────────────────────────

    def _generate(self, vuln_data: dict) -> Optional[str]:
        Logger.info("Sending data to Gemini for report synthesis…")
        Logger.info("This typically takes 20-45 seconds for a full report.")

        prompt = self._build_report_prompt(vuln_data)
        try:
            response = self._client.models.generate_content(
                model=Config.GEMINI_MODEL,
                contents=prompt,
                config=_genai_types.GenerateContentConfig(
                    system_instruction=(
                        "You are an expert security researcher writing a professional bug bounty report. "
                        "Reports must be technically precise, include fully functional exploit code — "
                        "never pseudocode — and follow the requested structure exactly."
                    ),
                    temperature=0.3,
                    max_output_tokens=4096,
                ),
            )
            text = getattr(response, "text", None)
            if text and text.strip():
                Logger.success(f"Report generated — {len(text):,} characters")
                return text.strip()
            Logger.error("Gemini returned an empty response")
            return None
        except Exception as exc:
            Logger.error(f"Report generation error: {exc}")
            return None

    def _save_report(self, text: str, vuln_data: dict) -> Path:
        safe_vuln = re.sub(r"[^\w]", "_", vuln_data.get("vuln_type", "report").lower())
        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        path      = self.output_dir / f"report_{safe_vuln}_{ts}.md"
        path.write_text(text)
        Logger.success(f"Report saved → {Colors.GREEN}{path}{Colors.RESET}")
        return path

    # ── Public interface ──────────────────────────────────────────────────

    def execute(self) -> Optional[Path]:
        Logger.section("MODULE 4 — PoC & Report Synthesizer  [Gemini]")

        if not self._init_client():
            return None

        vuln_data = self._collect_vuln_data()
        if not vuln_data:
            return None

        Logger.section("Report Parameters")
        Logger.data("Programme",     vuln_data.get("programme", "N/A"))
        Logger.data("Endpoint",      vuln_data.get("endpoint",  "N/A"))
        Logger.data("Vulnerability", vuln_data.get("vuln_type", "N/A"))
        Logger.data("Severity",      vuln_data.get("severity",  "N/A"))

        report_text = self._generate(vuln_data)
        if not report_text:
            Logger.error("Report generation failed")
            return None

        Logger.section("Report Preview (first 30 lines)")
        preview = report_text.split("\n")
        for line in preview[:30]:
            print(f"  {line}")
        remaining = len(preview) - 30
        if remaining > 0:
            print(f"\n  {Colors.GRAY}… {remaining} more lines in the full report{Colors.RESET}")

        report_path = self._save_report(report_text, vuln_data)
        Logger.success("Module 4 complete — report ready for submission")
        return report_path


# ═════════════════════════════════════════════════════════════════════════════
# TOP-LEVEL ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════════════

class BountyHub:
    """
    Top-level orchestrator.  Calls core modules, renders their event envelopes,
    and manages the engagement lifecycle.

    Dispatch table
    --------------
    full        → Module 1 → 2 → 3 → (optional) 4
    recon       → Module 1 only
    fingerprint → Module 2 (auto-loads live_hosts.txt if no in-memory data)
    advise      → Module 3 (auto-loads fingerprint.json if no in-memory data)
    report      → Module 4 (standalone, interactive)
    """

    def __init__(self, args: argparse.Namespace) -> None:
        self.args       = args
        self.target: Optional[str]  = getattr(args, "target", None)
        self.output_dir: Optional[Path] = None
        self.live_hosts: list = []
        self.fp_data:    list = []
        self.js_files:   list = []
        self.js_data:    dict = {}

    # ── Setup ─────────────────────────────────────────────────────────────

    def _setup(self) -> None:
        if self.target:
            self.output_dir = Config.engagement_dir(self.target)
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = Path(Config.OUTPUT_BASE) / f"report_{ts}"
            self.output_dir.mkdir(parents=True, exist_ok=True)

        Logger.success(f"Engagement directory: {Colors.CYAN}{self.output_dir}{Colors.RESET}")
        Logger.data("Target",     self.target or "N/A")
        Logger.data("Timestamp",  datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        Logger.data("AI model",   Config.GEMINI_MODEL)
        Logger.data("Output dir", str(self.output_dir))

    # ── Module wrappers (call core, render events, return data) ───────────

    def _recon(self) -> list:
        if not self.target:
            Logger.error("--target DOMAIN is required for reconnaissance")
            return []
        if not DependencyChecker.verify(Config.RECON_TOOLS, "Recon (Module 1)"):
            Logger.error("Missing recon tools — install them and retry")
            return []

        Logger.section("MODULE 1 — Reconnaissance & Asset Discovery")
        result = ReconModule(self.target, self.output_dir).execute()
        render_events(result["events"])

        if result.get("status") == "error":
            Logger.error(
                "Live-host detection FAILED — scanner fault, not a target verdict: "
                f"{result.get('error_reason') or 'cause unknown'}"
            )
            Logger.error("Halting: forwarding unverified hosts would produce wrong results.")
            self.live_hosts = []
            return []

        if result.get("status") == "empty":
            Logger.warning(
                f"Target '{self.target}' appears DEAD — 0 hosts responding on HTTP/HTTPS."
            )
            self.live_hosts = []
            return []

        if result["fallback_used"]:
            Logger.warning(
                "Recon DEGRADED — proceeding with unverified host list. "
                "Module 2 results may be less accurate."
            )

        self.live_hosts = result["live_hosts"]
        # Capture discovered JS URLs so the JS-Oracle stage (and its token
        # pre-filter/purifier) can run in the CLI too, like the web pipeline.
        self.js_files   = result.get("js_files", [])
        return self.live_hosts

    def _fingerprint(self, hosts: Optional[list] = None) -> list:
        source = hosts or self.live_hosts
        if not source:
            live_file = self.output_dir / Config.FILE_LIVE_HOSTS
            if live_file.exists():
                source = [h.strip() for h in live_file.read_text().splitlines() if h.strip()]
                Logger.info(f"Loaded {len(source)} hosts from {live_file}")
            else:
                Logger.error("No live hosts available — run recon first")
                return []

        if not DependencyChecker.verify(Config.FINGERPRINT_TOOLS, "Fingerprint (Module 2)"):
            Logger.error("Missing fingerprint tools — install them and retry")
            return []

        Logger.section("MODULE 2 — Technology Fingerprinting & Attack Surface Mapping")
        result = FingerprintModule(source, self.output_dir).execute()
        render_events(result["events"])

        self.fp_data = result["results"]
        return self.fp_data

    def _js_oracle(self, js_urls: Optional[list] = None) -> dict:
        """
        JS-Oracle stage — JavaScript analysis with the token pre-filter (purifier).

        Mirrors the web pipeline's JS stage so the pre-filter runs in the CLI too.
        Source order: an explicit list, else recon's discovered js_files, else a
        js_files.json in the engagement dir. Degrades gracefully — skips cleanly
        when js-oracle is not installed or when no JavaScript was found.
        """
        source = js_urls if js_urls is not None else self.js_files
        if not source:
            js_file = self.output_dir / "js_files.json"
            if js_file.exists():
                try:
                    loaded = json.loads(js_file.read_text())
                    source = loaded if isinstance(loaded, list) else []
                    Logger.info(f"Loaded {len(source)} JS URL(s) from {js_file}")
                except Exception:
                    source = []
        if not source:
            Logger.info("JS-Oracle skipped — no JavaScript files to analyze")
            return {}

        offline = getattr(self.args, "offline", False)
        label = "offline regex pass, $0" if offline else "Claude + token pre-filter"
        Logger.section(f"JS-ORACLE — JavaScript Analysis  [{label}]")
        result = JSOracle(self.output_dir).execute(self.target, source, offline=offline)
        render_events(result["events"])
        self.js_data = result
        return result

    def _advise(self, fp: Optional[list] = None, js_data: Optional[dict] = None) -> dict:
        data = fp or self.fp_data
        if not data:
            fp_file = self.output_dir / Config.FILE_FINGERPRINT
            if fp_file.exists():
                data = json.loads(fp_file.read_text())
                Logger.info(f"Loaded fingerprint data from {fp_file}")
            else:
                Logger.error("No fingerprint data — run fingerprint first")
                return {}

        # The advisor uses Anthropic Claude (see core/ai_advisor.py), not Gemini —
        # the old "[Gemini]" label was cosmetic and misled key setup.
        Logger.section("MODULE 3 — AI Vulnerability Advisor  [Claude]")
        DependencyChecker.check_optional()

        result = AIAdvisorModule(data, self.output_dir,
                                 js_data=js_data or self.js_data).execute()
        render_events(result["events"])

        return result["analyses"]

    def _report(self) -> Optional[Path]:
        return ReportModule(self.output_dir).execute()

    # ── Summary ───────────────────────────────────────────────────────────

    def _print_summary(self) -> None:
        Logger.section("Engagement Summary")
        Logger.data("Target",     self.target or "N/A")
        Logger.data("Output dir", str(self.output_dir))

        if self.output_dir and self.output_dir.exists():
            Logger.info("Generated artefacts:")
            for f in sorted(self.output_dir.iterdir()):
                sz   = f.stat().st_size
                size = f"{sz / 1024:.1f} KB" if sz >= 1024 else f"{sz} B"
                print(f"    {Colors.SUCCESS}→{Colors.RESET} {f.name:<40} {Colors.GRAY}{size}{Colors.RESET}")

    # ── Full pipeline ─────────────────────────────────────────────────────

    def _full_pipeline(self) -> None:
        Logger.info(
            f"Starting full BountyHub pipeline → "
            f"target: {Colors.YELLOW}{self.target}{Colors.RESET}"
        )

        # Stage 1 — Recon
        live_hosts = self._recon()
        if not live_hosts:
            Logger.error("Pipeline aborted: Module 1 produced no hosts")
            return
        Logger.success(f"Stage 1 complete — {len(live_hosts)} host(s) forwarded to Stage 2")

        # Stage 2 — Fingerprint
        fp_data = self._fingerprint(live_hosts)
        if not fp_data:
            Logger.error("Pipeline aborted: Module 2 produced no fingerprint data")
            return
        Logger.success(f"Stage 2 complete — {len(fp_data)} host(s) fingerprinted")

        # Stage 2.5 — JS-Oracle (JavaScript analysis + token pre-filter/purifier)
        js_data = self._js_oracle(self.js_files)

        # Stage 3 — Reporting. FREE mode: deterministic offline report ($0).
        # AI mode: the Opus advisor (spends credit).
        if getattr(self.args, "offline", False):
            from core.offline_report import build_report
            report_md = build_report(self.output_dir)
            out_file = self.output_dir / "offline_report.md"
            try:
                out_file.write_text(report_md, encoding="utf-8")
            except Exception as exc:
                Logger.error(f"Could not write {out_file}: {exc}")
            Logger.success(f"FREE mode — report generated offline ($0): {out_file}")
            Logger.info("Want a Claude synthesis of these SAME findings later? Run: "
                        f"advise --target {self.target}  (one Opus call, reuses saved findings)")
            self._print_summary()
            return

        # Stage 3 — AI Advisor (folds in JS-Oracle findings)
        analyses = self._advise(fp_data, js_data=js_data)
        Logger.success(f"Stage 3 complete — AI analysis for {len(analyses)} host(s)")

        # Stage 4 — Optional report
        try:
            print(
                f"\n{Colors.YELLOW}[?]{Colors.RESET} Generate a bug bounty report now? "
                f"{Colors.GRAY}[y/N]{Colors.RESET}: ",
                end="",
            )
            if input().strip().lower() == "y":
                self._report()
            else:
                Logger.info("Report generation skipped — run with the 'report' subcommand when ready")
        except (KeyboardInterrupt, EOFError):
            Logger.info("Report generation skipped")

        self._print_summary()

    # ── Dispatch ──────────────────────────────────────────────────────────

    def run(self) -> None:
        Logger.banner()
        self._setup()

        cmd = self.args.command

        if cmd == "full":
            self._full_pipeline()

        elif cmd == "recon":
            self._recon()
            self._print_summary()

        elif cmd == "fingerprint":
            hosts_file = getattr(self.args, "hosts_file", None)
            preloaded  = None
            if hosts_file and Path(hosts_file).exists():
                preloaded = [h.strip() for h in Path(hosts_file).read_text().splitlines() if h.strip()]
                Logger.info(f"Loaded {len(preloaded)} hosts from {hosts_file}")
            self._fingerprint(preloaded)
            self._print_summary()

        elif cmd == "advise":
            fp_file   = getattr(self.args, "fingerprint_file", None)
            preloaded = None
            if fp_file and Path(fp_file).exists():
                preloaded = json.loads(Path(fp_file).read_text())
                Logger.info(f"Loaded fingerprint data from {fp_file}")
            self._advise(preloaded)
            self._print_summary()

        elif cmd == "jsoracle":
            js_file = getattr(self.args, "js_file", None)
            urls: Optional[list] = None
            if js_file and Path(js_file).exists():
                txt = Path(js_file).read_text()
                try:
                    loaded = json.loads(txt)
                    urls = loaded if isinstance(loaded, list) else None
                except json.JSONDecodeError:
                    urls = [ln.strip() for ln in txt.splitlines()
                            if ln.strip() and not ln.strip().startswith("#")]
            self._js_oracle(urls)
            self._print_summary()

        elif cmd == "report":
            self._report()
            self._print_summary()

        else:
            Logger.error(f"Unknown command: '{cmd}'")
            sys.exit(1)


# ═════════════════════════════════════════════════════════════════════════════
# CLI ARGUMENT PARSER
# ═════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bountyhub",
        description=(
            "BountyHub v2 — AI-Powered Bug Bounty Intelligence Framework\n"
            "Integrates subfinder, httpx, nmap, whatweb with Google Gemini AI."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  Full pipeline (all 4 modules):
      python3 BountyHub_v2/cli/main.py full --target example.com

  Recon only (handles specific subdomains automatically):
      python3 BountyHub_v2/cli/main.py recon --target testphp.vulnweb.com

  Fingerprint from existing host list:
      python3 BountyHub_v2/cli/main.py fingerprint --target example.com --hosts-file live_hosts.txt

  AI advisor from existing fingerprint:
      python3 BountyHub_v2/cli/main.py advise --target example.com --fingerprint-file fingerprint.json

  Interactive report generation:
      python3 BountyHub_v2/cli/main.py report

environment variables:
  ANTHROPIC_API_KEY  Required for 'advise' + 'jsoracle' (Claude). The engine does
                     NOT read js-oracle/.env — set it in this shell or scan-engine/.env.
                     export ANTHROPIC_API_KEY='sk-ant-...'
  GEMINI_API_KEY     Required only for the interactive 'report' (Gemini).
                     export GEMINI_API_KEY='AIza...'

required tools:
  Module 1: subfinder, httpx
  Module 2: nmap, whatweb
  Optional: nuclei, ffuf (referenced in AI-generated commands)

disclaimer:
  Use ONLY against systems you have explicit written authorisation to test.
        """,
    )
    parser.add_argument("--version", action="version", version="bountyhub 2.0.0")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── full ──────────────────────────────────────────────────────────────
    p_full = sub.add_parser(
        "full",
        help="Run the complete 4-module pipeline (recommended entry point)",
    )
    p_full.add_argument(
        "--target", "-t", required=True, metavar="DOMAIN",
        help="Target domain, e.g. example.com or sub.example.com",
    )
    p_full.add_argument(
        "--offline", action="store_true",
        help="FREE mode ($0): analyze JS with the deterministic regex pass only "
             "(no LLM) and write the report offline (offline_report.md). Skips the "
             "paid AI advisor — run 'advise' later if you want a Claude synthesis.",
    )

    # ── recon ─────────────────────────────────────────────────────────────
    p_recon = sub.add_parser(
        "recon",
        help="Module 1 — Passive subdomain enumeration + live host validation",
    )
    p_recon.add_argument("--target", "-t", required=True, metavar="DOMAIN")

    # ── fingerprint ───────────────────────────────────────────────────────
    p_fp = sub.add_parser(
        "fingerprint",
        help="Module 2 — Port scanning + technology stack fingerprinting",
    )
    p_fp.add_argument("--target", "-t", required=True, metavar="DOMAIN")
    p_fp.add_argument(
        "--hosts-file", metavar="FILE",
        help="Path to live_hosts.txt (one URL per line). Skips Module 1.",
    )

    # ── advise ────────────────────────────────────────────────────────────
    p_adv = sub.add_parser(
        "advise",
        help="Module 3 — AI vulnerability analysis (Claude/Opus; needs ANTHROPIC_API_KEY + credit)",
    )
    p_adv.add_argument("--target", "-t", metavar="DOMAIN",
                       help="Target domain (for output directory context)")
    p_adv.add_argument(
        "--fingerprint-file", "-f", metavar="FILE",
        help="Path to fingerprint.json from Module 2. Skips Modules 1-2.",
    )

    # ── jsoracle ──────────────────────────────────────────────────────────
    p_js = sub.add_parser(
        "jsoracle",
        help="JS-Oracle — JavaScript analysis + token pre-filter (needs js-oracle installed)",
    )
    p_js.add_argument("--target", "-t", required=True, metavar="DOMAIN")
    p_js.add_argument(
        "--js-file", metavar="FILE",
        help="js_files.json OR a newline-separated list of JS URLs to analyze.",
    )
    p_js.add_argument(
        "--offline", action="store_true",
        help="FREE mode ($0): deterministic regex pass only — no LLM call.",
    )

    # ── report ────────────────────────────────────────────────────────────
    p_rep = sub.add_parser(
        "report",
        help="Module 4 — Interactive AI-powered bug bounty report generation",
    )
    p_rep.add_argument("--target", "-t", metavar="DOMAIN",
                       help="Optional target domain for output directory naming")

    return parser


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if not args.command:
        parser.print_help()
        print(
            f"\n{Colors.WARNING}[!]{Colors.RESET} No command specified.  "
            f"Choose: full | recon | fingerprint | advise | report\n"
        )
        sys.exit(1)

    try:
        BountyHub(args).run()
    except KeyboardInterrupt:
        print(
            f"\n\n{Colors.WARNING}[!]{Colors.RESET} "
            "Interrupted by operator — exiting BountyHub cleanly."
        )
        sys.exit(0)
    except Exception as exc:
        Logger.error(f"Fatal unhandled exception: {exc}")
        Logger.warning("Full traceback follows:")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
