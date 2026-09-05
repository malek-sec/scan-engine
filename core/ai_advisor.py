"""
BountyHub v3 Enterprise — core.ai_advisor
Module 3: AI Vulnerability Advisor powered by Anthropic Claude Opus 4.8

Batch architecture: ALL live hosts are assembled into ONE API request,
bypassing per-host rate limits entirely and maximising analytical coherence.
Claude's extended context window handles even large target scopes comfortably.

Requires:
    pip install anthropic
    export ANTHROPIC_API_KEY='sk-ant-...'

Public API
----------
AIAdvisorModule(fp_data, output_dir).execute() → AdvisorResult dict:
{
    "status"   : "ok" | "partial" | "error",
    "events"   : [{"level": str, "msg": str}, ...],
    "analyses" : {
        "<host_url>": "<markdown analysis text>",
        ...
    },
}

Event levels: "info", "success", "warning", "error", "data", "analysis"
"""

import json
import os
import re
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from core import Config


# ── Anthropic SDK ─────────────────────────────────────────────────────────────
try:
    import anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False


# ── Load .env as a safety net (no-op if already loaded by the caller) ────────
# Ensures ANTHROPIC_API_KEY is visible when this module is used standalone
# (e.g. CLI). override=False means it never clobbers keys already set by app.py.
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(override=False)
except ImportError:
    pass


# ── Model constants ───────────────────────────────────────────────────────────

# Model for the advisor — the component that WRITES the intelligence report.
# Pinned to Opus and DECOUPLED from ANTHROPIC_MODEL, so the final report stays
# high-quality even under a cheap/balanced JS-analysis profile. Change it only
# via the dedicated BOUNTYHUB_ADVISOR_MODEL env var.
_CLAUDE_MODEL = os.environ.get("BOUNTYHUB_ADVISOR_MODEL", "").strip() or "claude-opus-4-8"

# Generous token budget: ~1,700 tokens per host for a 19-host scan
_MAX_TOKENS = 32768

# Retry config for transient API errors (overload / connection issues)
_MAX_RETRIES  = 2
_RETRY_DELAY  = 20   # seconds between retries


# ── Internal helpers ──────────────────────────────────────────────────────────

def _ev(level: str, msg: str) -> dict:
    return {"level": level, "msg": msg}

def _ev_data(label: str, value: str) -> dict:
    return {"level": "data", "label": label, "value": value}

def _ev_analysis(host: str, text: str) -> dict:
    """Carries the raw AI output for the CLI renderer."""
    return {"level": "analysis", "host": host, "text": text}


# ── System instruction ────────────────────────────────────────────────────────
#
# DESIGN NOTE — two-layer constraint architecture
# ------------------------------------------------
# The Rules of Engagement (RoE) are enforced at BOTH layers of the API call:
#
#   Layer 1 — _SYSTEM (this constant): sets the model's standing persona and
#             lists hard prohibitions.  Claude treats system-prompt instructions
#             as higher-authority than user-turn instructions, so destructive
#             behaviours are suppressed even if the user prompt is ambiguous.
#
#   Layer 2 — _build_batch_prompt(): the user turn re-states the key safety
#             flags inline (e.g. nuclei -exclude-tags, sqlmap --level 1) so the
#             model has immediate, contextual reminders when writing each command.
#
# Both layers must remain in sync.  If you update one, update the other.

_SYSTEM = """\
You are a professional bug bounty hunter and vulnerability researcher operating \
under strict Rules of Engagement (RoE) and responsible-disclosure / Safe Harbor \
principles. You have 15 years of active experience on HackerOne, Bugcrowd, \
Intigriti, and the Synack Red Team, with hundreds of responsibly-disclosed \
critical and high-severity findings.

════════════════════════════════════════════════════════════════════
MANDATORY RULES OF ENGAGEMENT  —  NON-NEGOTIABLE CONSTRAINTS
════════════════════════════════════════════════════════════════════

The following categories of action are STRICTLY FORBIDDEN.  You MUST NOT
suggest, imply, reference, or provide commands that perform any of these:

1. DESTRUCTION OR IRREVERSIBLE DATA MODIFICATION
   • No DROP TABLE, TRUNCATE, DELETE without a scoped WHERE clause, ALTER TABLE
   • No overwriting / deleting files or logs on the target system
   • No modifying user accounts, passwords, or access-control lists on the target

2. REMOTE CODE EXECUTION (RCE) BEYOND READ-ONLY CONFIRMATION
   • No uploading webshells of any language (shell.php, cmd.aspx, *.jsp, *.py …)
   • No establishing reverse shells, bind shells, or persistent backdoors
   • No executing arbitrary OS commands via injection beyond a single, non-destructive
     confirmation signal (e.g. a sleep delay, a DNS callback, or `id` once)
   • No lateral movement, privilege escalation chains, or post-exploitation steps

3. DENIAL OF SERVICE (DoS) — ZERO TOLERANCE
   • No load-testing or stress-testing tools (ab, wrk, siege, hey, flood*)
   • No resource-exhaustion payloads (XML bomb, zip bomb, ReDoS, large file upload loops)
   • No packet-flood techniques or connection-saturation attacks
   • No sending malformed protocol data designed to crash or hang services

4. BULK DATA EXFILTRATION BEYOND MINIMAL PoC
   • No --dump-all, no SELECT * without LIMIT 1 (or equivalent minimal fetch)
   • No harvesting PII, credentials, session tokens, or financial data at scale
   • No exfiltrating more data than is strictly necessary to prove the vulnerability exists

5. AGGRESSIVE AUTOMATION WITHOUT EXPLICIT PERMISSION
   • No credential-stuffing or password-spray campaigns
   • No recursive spidering / crawling without a depth and rate cap
   • No chaining vulnerabilities beyond the first confirmed PoC step

════════════════════════════════════════════════════════════════════
REQUIRED SAFETY FLAGS  —  EVERY COMMAND MUST COMPLY
════════════════════════════════════════════════════════════════════

NUCLEI
  Every nuclei command MUST include:
      -exclude-tags dos,destructive,fuzz
  and MUST NOT use -interactsh-server with exfiltration payloads.
  Stick to detection / information-disclosure templates only.

SQLMAP
  Every sqlmap command MUST include:
      --level 1 --risk 1 --technique=BEUST --batch
  and MUST NOT include any of:
      --os-shell  --os-pwn  --os-cmd  --dump-all  --dump
      --sql-shell  --file-write  --file-dest  --priv-esc
  Goal: confirm the injection point only.  Do not extract real data.

FFUF / WFUZZ / FEROXBUSTER
  All directory / parameter brute-force commands MUST include a rate cap:
      -rate 20  (or equivalent for the tool)
  and a per-request timeout: -timeout 10
  No credential-stuffing wordlists.

DALFOX
  All XSS probing commands MUST include:
      --skip-bav --timeout 10
  Use --only-discovery when blind XSS callbacks are not in scope.

CURL / HTTP PROBES
  Single-request confirmation only.
  No while-true loops.  No multi-threaded curl one-liners.

════════════════════════════════════════════════════════════════════
REPORTING STYLE  —  WRITE LIKE A SCANNER + PENTEST REPORT, NOT AN ESSAY
════════════════════════════════════════════════════════════════════

The operator wants signal, not prose. Model the output on Burp / Nessus / nuclei
findings and a tight pentest report:

  ✓ EVIDENCE FIRST — every line states what was OBSERVED and cites its source.
    Keep CONFIRMED findings (proven by the collected data) strictly separate from
    LEADS (unconfirmed hypotheses needing a manual check). Never blur the two.
  ✓ HONESTY OVER VOLUME — if the data proves nothing, say "No confirmed findings
    from the collected evidence." Do NOT invent "probable" vulnerabilities to look
    thorough. A short true report beats a long speculative one.
  ✓ NO severity / CVSS on anything that is not a CONFIRMED finding. A lead carries
    a next step, not a score.
  ✓ SUPPRESS THE NOISE — do NOT report these as findings; they are near-universally
    informational or out-of-scope on bug-bounty programs. Note them in ONE
    "Suppressed" line at most: TLS/cipher/protocol config, missing security headers,
    server-version banners, 404 / error-page text, rate-limiting / captcha absence,
    SPF/DKIM/DMARC, clickjacking on non-sensitive pages, self-XSS, CSRF on
    non-sensitive forms, generic best-practice / hardening suggestions.
  ✗ NO padding — no "reading lists", no generic "historical precedent" essays, no
    "search these dorks", no textbook explanations of what a vuln class is.
  ✗ NO URLs, and NO invented CVE / report IDs. Cite a CVE only with the detected
    version beside it (see CONFIRMATION DISCIPLINE).

════════════════════════════════════════════════════════════════════
EVIDENCE-BASED ANALYSIS ONLY  —  NON-NEGOTIABLE
════════════════════════════════════════════════════════════════════

Every finding MUST cite its evidence source using this exact format:
  **Evidence:** [tool_name] → [specific data point]

Examples of acceptable evidence citations:
  **Evidence:** JS-Oracle → innerHTML sink in booking.js:234
  **Evidence:** openssl → TLS 1.0 negotiated successfully on port 443
  **Evidence:** waybackurls → /api/v1/debug endpoint found in 2024 archive
  **Evidence:** HTTP headers → script-src * 'unsafe-inline' in Content-Security-Policy
  **Evidence:** whatweb → Umbraco CMS 7.12.4 version string in X-Umbraco-Version header

════════════════════════════════════════════════════════════════════
CONFIRMATION DISCIPLINE  —  NON-NEGOTIABLE (three hard rules)
════════════════════════════════════════════════════════════════════

RULE 1 — "Confirmed" requires EXECUTABLE evidence. NOTHING ELSE.
  The word "Confirmed" (and any "Vulnerability confirmed" phrasing) is RESERVED
  for a finding proven by ONE of these, quoted from the ACTUAL response:
    • an injected payload that demonstrably executed or was reflected unmodified
      in the response body, OR
    • the exploit request returning HTTP 200 (or the specific status that proves
      the issue) with the expected marker in the response, OR
    • a byte-for-byte matching indicator (exact string / hash / version match)
      returned by the target.
  If you only detected a technology, product, or version — WITHOUT firing a
  working request that proves exploitability — you MUST label it
  "Technology detected", NEVER "Vulnerability confirmed" and NEVER "Confirmed".
  Detecting Apache 2.4.49 is "Technology detected: Apache 2.4.49"; it becomes
  "Confirmed" only if a traversal/RCE payload actually returned the expected
  output. When in doubt, it is NOT confirmed.

RULE 2 — VERSION DETECTION BEFORE ANY CVE CITATION.
  You MUST NOT cite, reference, or imply a CVE unless a concrete version number
  for the affected component was actually detected in the recon data (Server /
  X-Powered-By header, whatweb/JS-Oracle version string, banner, etc.). No
  detected version → no CVE. Cite the exact version and its evidence source
  right next to the CVE (e.g. "nginx 1.18.0 — Evidence: HTTP headers → Server:
  nginx/1.18.0"). If the version is unknown, say "version not detected — CVE
  correlation not possible" and give a manual version-fingerprinting step
  instead of guessing a CVE.

RULE 3 — GROUND FINDINGS IN THE ACTUAL HTTP RESPONSE, NOT URL EXISTENCE.
  A URL appearing in crawl / katana / wayback / gau output is only a CANDIDATE,
  never a finding. Base every conclusion on the observed HTTP response for that
  target: the status code, the response headers, and whether an injected payload
  was reflected or executed. Do NOT claim an endpoint is "exposed",
  "vulnerable", or "accessible" merely because its URL was discovered — a
  discovered URL with no observed 2xx/priv response is "candidate endpoint (not
  yet probed)". State what the response actually showed, or mark it
  "Needs verification".

BEST-EFFORT ANALYSIS — analyse whatever data IS available and never refuse:
  • You will often receive PARTIAL recon data (some of: technologies, open ports,
    HTTP headers, JS analysis, historical URLs, TLS may be missing). This is
    normal and expected. NEVER respond with an "insufficient data" placeholder,
    and NEVER decline the analysis. Work with what you have.
  • CONFIRMED findings still require a real evidence citation — do NOT fabricate
    evidence, headers, versions, CVEs, or tool output that was not provided.
  • When a promising vector CANNOT yet be backed by concrete evidence (because
    the relevant data is missing or was not collected), you MAY still surface it
    as a **manual attack vector / hypothesis** — but you MUST label it clearly as
    "Needs verification" and state the exact manual recon step that would confirm
    it. Reasoned, technology-specific hypotheses are encouraged; unlabelled
    speculation presented as fact is FORBIDDEN.

PERMANENTLY EXCLUDED — DO NOT SUGGEST THESE:
  ✗ Akamai Pragma debug headers (fully mitigated since 2018; not a valid finding)
  ✗ Generic "security header missing" observations without demonstrated exploitable impact
  ✗ Any CVSS score above 5.0 without a confirmed version-specific CVE or JS-Oracle finding

CVSS SCORING RULES:
  • Without a confirmed CVE: maximum score is 5.0 (Medium) — append "(Estimated)" to the score
  • With a confirmed NVD CVE: use the official NVD base score verbatim
  • With a confirmed JS-Oracle business-logic finding: 6.0–8.0 based on demonstrated impact

════════════════════════════════════════════════════════════════════
OBJECTIVE: Non-Destructive Proof of Concept (PoC) ONLY
════════════════════════════════════════════════════════════════════

Your goal is to IDENTIFY and CONFIRM the existence of a vulnerability with the
minimum interaction necessary — not to exploit it to its full potential.
Stop at the first reliable evidence of the vulnerability.
Estimate CVSS scores from the theoretical impact, not from an executed chain.

You produce ONLY technically precise, version-specific vulnerability intelligence.
You NEVER give generic advice.  Every recommendation must be tied to the EXACT
detected software versions and technology stack reported in the fingerprint data.
You format all responses in clean, well-structured Markdown.
"""


# ── Data-sufficiency gate ─────────────────────────────────────────────────────

def _count_data_points(
    fp_data: list,
    js_data: dict,
    historical_urls: list | None = None,
    http_responses: list | None = None,
    active_data: dict | None = None,
) -> tuple[int, list, list]:
    """
    Count meaningful recon data points available for AI analysis.
    Returns (count, present_list, missing_list).
    Minimum threshold is 5 before the Claude API call is worthwhile.

    Parameters
    ----------
    fp_data         : fingerprint.json results (list of per-host dicts)
    js_data         : JS-Oracle merged result dict
    historical_urls : list loaded from historical_urls.json (recon stage)
    http_responses  : list loaded from http_responses.json (recon stage)
    """
    present: list[str] = []
    missing: list[str] = []

    # HTTP headers — from http_responses.json (recon stage, response_headers key)
    # fp_data items carry no "headers" field; the data lives in http_responses.json.
    header_count = sum(
        len(r.get("response_headers", {}))
        for r in (http_responses or [])
    )
    if header_count > 0:
        present.append(f"HTTP headers ({header_count} detected)")
    else:
        missing.append("HTTP response headers (run with header collection enabled)")

    # Technologies — from fingerprint.json (whatweb/nmap detection)
    # FingerprintModule stores technologies as a dict
    # {web_server, cms, language, javascript_libraries, other}, NOT a list.
    tech_versioned: list[str] = []
    for item in fp_data:
        tech = item.get("technologies", {})
        if isinstance(tech, dict):
            for field in ("web_server", "cms", "language"):
                val = tech.get(field)
                if val and val != "Unknown":
                    tech_versioned.append(str(val))
            for lib in tech.get("javascript_libraries", []):
                if lib:
                    tech_versioned.append(str(lib))
            for other in tech.get("other", []):
                if other:
                    tech_versioned.append(str(other))
        elif isinstance(tech, list):
            for t in tech:
                if isinstance(t, dict):
                    name    = t.get("name") or t.get("technology", "")
                    version = t.get("version", "")
                    tech_versioned.append(f"{name} {version}".strip() if version else name)
                elif isinstance(t, str) and t:
                    tech_versioned.append(t)
    if tech_versioned:
        preview = ", ".join(tech_versioned[:3]) + ("…" if len(tech_versioned) > 3 else "")
        present.append(f"Technologies ({len(tech_versioned)}): {preview}")
    else:
        missing.append("Technology fingerprints with version numbers (whatweb / wappalyzer)")

    # JS endpoints from JS-Oracle
    js_endpoints = (js_data or {}).get("endpoints", [])
    if js_endpoints:
        present.append(f"JS endpoints ({len(js_endpoints)} from JS-Oracle)")
    else:
        missing.append("JavaScript analysis (run JS-Oracle against discovered JS files)")

    # TLS findings — from fingerprint data (openssl s_client per HTTPS host)
    tls_findings: list = []
    for item in fp_data:
        tls = item.get("tls") or {}
        if tls:
            tls_findings.append(tls)
    tls_findings.extend((js_data or {}).get("tls_findings", []))
    if tls_findings:
        present.append(f"TLS certificate data ({len(tls_findings)} host(s))")
    else:
        missing.append("TLS certificate details (openssl s_client / testssl.sh)")

    # Historical URLs — from historical_urls.json (recon stage)
    # fp_data items carry no historical_urls field; they live in historical_urls.json.
    historical = list(historical_urls or [])
    historical.extend((js_data or {}).get("historical_urls", []))
    if historical:
        present.append(f"Historical URLs ({len(historical)} from Wayback/crt.sh)")
    else:
        missing.append("Historical endpoint data (waybackurls / gau / crt.sh)")

    # Open ports — from fingerprint.json (nmap results stored under "open_ports")
    # FingerprintModule uses "open_ports", not "ports".
    port_count = sum(len(item.get("open_ports", [])) for item in fp_data)
    active = active_data or {}
    wide_ports = active.get("ports", {}).get("count", 0)
    if port_count > 0 or wide_ports > 0:
        present.append(f"Open ports ({port_count} nmap + {wide_ports} naabu)")
    else:
        missing.append("Port scan results (nmap / naabu)")

    # ── Active recon & fuzzing signals (katana / ffuf / arjun / nuclei) ────────
    crawl_count  = active.get("crawl", {}).get("count", 0)
    fuzz_count   = active.get("fuzz", {}).get("count", 0)
    param_count  = active.get("params", {}).get("count", 0)
    nuclei_count = active.get("nuclei", {}).get("count", 0)

    if crawl_count > 0:
        present.append(f"Crawled endpoints ({crawl_count} from katana)")
    else:
        missing.append("Deep crawl / spider data (katana)")

    if fuzz_count > 0:
        present.append(f"Brute-forced paths ({fuzz_count} from ffuf)")
    else:
        missing.append("Directory / file brute-force (ffuf)")

    if param_count > 0:
        present.append(f"Hidden parameters ({param_count} from arjun)")

    if nuclei_count > 0:
        present.append(f"Template vuln findings ({nuclei_count} from nuclei)")
    else:
        missing.append("Template-based vuln scan (nuclei)")

    return len(present), present, missing


def _build_insufficient_report(present: list, missing: list) -> str:
    present_block = "\n".join(f"  - {p}" for p in present) or "  (none)"
    missing_block = "\n".join(f"  - {m}" for m in missing) or "  (none)"
    return (
        "## Recon data insufficient for specific analysis.\n\n"
        f"**Detected ({len(present)} data point(s)):**\n{present_block}\n\n"
        "**Missing data that would improve this report:**\n"
        f"{missing_block}\n\n"
        "> Re-run scan with extended profile."
    )


# ── Prompt builder ────────────────────────────────────────────────────────────

def _build_js_section(js_data: dict) -> str:
    """
    Render a JS-Oracle findings block to embed in the batch prompt.
    Returns an empty string when there are no findings to include.
    """
    if not js_data or js_data.get("raw_findings_count", 0) == 0:
        return ""

    lines = [
        "",
        "---",
        "",
        "## Module 4: JavaScript Analysis (JS-Oracle)",
        "",
        f"**Files analyzed:** {js_data.get('js_files_analyzed', 0)}  "
        f"| **Total findings:** {js_data.get('raw_findings_count', 0)}  "
        f"| **Highest severity:** {js_data.get('highest_severity', 'none')}",
        "",
    ]

    endpoints = js_data.get("endpoints", [])
    if endpoints:
        lines += [
            f"### Discovered Endpoints ({len(endpoints)})",
            "",
            "| Method | Path | Confidence | Evidence |",
            "|--------|------|------------|----------|",
        ]
        for ep in endpoints[:30]:
            evidence = (ep.get("evidence") or "")[:80].replace("|", "\\|")
            lines.append(
                f"| {ep.get('method','?')} "
                f"| `{ep.get('path','')}` "
                f"| {ep.get('confidence','')} "
                f"| {evidence} |"
            )
        lines.append("")

    api_keys = js_data.get("api_keys", [])
    if api_keys:
        lines += [f"### Secrets / API Keys Found ({len(api_keys)})", ""]
        for s in api_keys:
            evidence = (s.get("evidence") or "")[:80]
            lines.append(
                f"- **{s.get('type','')}**: `{s.get('value_preview','')}` "
                f"— {evidence}"
            )
        lines.append("")

    auth_issues = js_data.get("auth_issues", [])
    if auth_issues:
        lines += [f"### Authentication Logic ({len(auth_issues)})", ""]
        for a in auth_issues:
            evidence = (a.get("evidence") or "")[:80]
            lines.append(
                f"- **{a.get('mechanism','')}** stored in "
                f"`{a.get('storage_location','')}` — {evidence}"
            )
        lines.append("")

    sinks = js_data.get("sinks", [])
    if sinks:
        lines += [f"### Dangerous Sinks ({len(sinks)})", ""]
        for s in sinks:
            sev      = s.get("severity", "info").upper()
            evidence = (s.get("evidence") or "")[:80]
            lines.append(
                f"- **[{sev}]** {s.get('description','')} "
                f"— `{evidence}`"
            )
        lines.append("")

    business_logic = js_data.get("business_logic", [])
    if business_logic:
        lines += [f"### Business Logic Issues ({len(business_logic)})", ""]
        for b in business_logic:
            sev      = b.get("severity", "info").upper()
            evidence = (b.get("evidence") or "")[:80]
            lines.append(
                f"- **[{sev}]** {b.get('description','')} "
                f"— `{evidence}`"
            )
        lines.append("")

    return "\n".join(lines)


def _build_http_section(http_responses: list | None) -> str:
    """
    Render captured HTTP response headers/metadata for the batch prompt.

    HTTP headers are collected by ReconModule into http_responses.json but are
    NOT part of fp_data, so they must be embedded here explicitly — otherwise
    the model can never cite header-based evidence (CSP, Server, X-Powered-By…).
    Returns an empty string when nothing was captured.
    """
    if not http_responses:
        return ""

    lines = [
        "",
        "---",
        "",
        f"## HTTP Response Metadata ({len(http_responses)} host(s))",
        "",
        "Full response headers captured during recon (httpx). Use these as "
        "evidence for header-based findings (missing/weak CSP, server version "
        "disclosure, cookie flags, CORS, etc.):",
        "",
    ]
    for r in http_responses:
        url     = r.get("url", "unknown")
        status  = r.get("status_code")
        server  = r.get("webserver", "") or "unknown"
        ctype   = r.get("content_type", "") or ""
        headers = r.get("response_headers", {}) or {}
        lines.append(f"### {url}")
        lines.append(
            f"- **Status:** {status}  |  **Server:** {server}"
            + (f"  |  **Content-Type:** {ctype}" if ctype else "")
        )
        if headers:
            lines.append("- **Response headers:**")
            lines.append("```")
            for name, value in headers.items():
                # httpx may emit list-valued headers; normalise to a string.
                if isinstance(value, (list, tuple)):
                    value = ", ".join(str(v) for v in value)
                lines.append(f"{name}: {value}")
            lines.append("```")
        else:
            lines.append("- **Response headers:** (none captured)")
        lines.append("")

    return "\n".join(lines)


def _build_active_recon_section(active_data: dict | None) -> str:
    """
    Render the Active Recon & Fuzzing results (katana / ffuf / arjun / naabu /
    nuclei) into a data-rich block for the AI prompt. Returns "" when nothing
    was gathered so partial scans stay clean.
    """
    if not active_data:
        return ""

    crawl  = active_data.get("crawl", {}) or {}
    fuzz   = active_data.get("fuzz", {}) or {}
    ports  = active_data.get("ports", {}) or {}
    params = active_data.get("params", {}) or {}
    nuclei = active_data.get("nuclei", {}) or {}

    total = (crawl.get("count", 0) + fuzz.get("count", 0) + ports.get("count", 0)
             + params.get("count", 0) + nuclei.get("count", 0))
    if total == 0:
        return ""

    lines = [
        "",
        "---",
        "",
        "## Active Recon & Fuzzing (katana / ffuf / arjun / naabu / nuclei)",
        "",
        f"Tools used: {', '.join(active_data.get('tools_used', [])) or 'none'}",
        "",
    ]

    # nuclei — highest signal first
    findings = nuclei.get("findings", [])
    if findings:
        by_sev = nuclei.get("by_severity", {})
        lines.append(f"### Template-Based Vulnerability Findings — nuclei ({len(findings)})")
        lines.append("Severity breakdown: "
                     + (", ".join(f"{k}:{v}" for k, v in sorted(by_sev.items())) or "n/a"))
        lines.append("")
        lines.append("| Severity | Template | Name | Matched At |")
        lines.append("|----------|----------|------|-----------|")
        _rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        for f in sorted(findings, key=lambda x: _rank.get(x.get("severity", "unknown"), 9))[:40]:
            lines.append(
                f"| {f.get('severity','')} | `{f.get('template_id','')}` "
                f"| {f.get('name','')} | {f.get('matched_at','')} |"
            )
        lines.append("")

    # naabu — comprehensive port map
    by_host = ports.get("by_host", {})
    if by_host:
        lines.append(f"### Comprehensive Port Scan — naabu ({ports.get('count',0)} open port(s))")
        for host, plist in list(by_host.items())[:20]:
            lines.append(f"- **{host}**: {', '.join(str(p) for p in plist)}")
        lines.append("")

    # ffuf — hidden paths
    paths = fuzz.get("paths", [])
    if paths:
        lines.append(f"### Directory / File Brute-Force — ffuf ({len(paths)} hit(s))")
        for p in paths[:40]:
            lines.append(f"- `{p.get('url','')}` → {p.get('status')} ({p.get('length')} bytes)")
        lines.append("")

    # arjun — hidden parameters
    by_endpoint = params.get("by_endpoint", {})
    if by_endpoint:
        lines.append(f"### Hidden Parameters — arjun ({params.get('count',0)} across "
                     f"{len(by_endpoint)} endpoint(s))")
        for url, plist in list(by_endpoint.items())[:25]:
            lines.append(f"- `{url}` → {', '.join(str(p) for p in plist)}")
        lines.append("")

    # katana — crawl surface (sampled; full list can be huge)
    endpoints = crawl.get("endpoints", [])
    if endpoints:
        lines.append(f"### Crawled Attack Surface — katana ({crawl.get('count',0)} endpoint(s), "
                     f"{len(crawl.get('js_files', []))} JS file(s))")
        lines.append("Representative endpoints:")
        for e in endpoints[:40]:
            lines.append(f"- {e}")
        if len(endpoints) > 40:
            lines.append(f"- … and {len(endpoints) - 40} more (see active_recon.json)")
        lines.append("")

    return "\n".join(lines)


def _build_availability_note(present: list, missing: list) -> str:
    """
    Render a short data-availability summary for a best-effort analysis.

    Instead of hard-rejecting when some recon data is missing, we tell the
    model exactly what is and isn't available so it can analyse whatever exists
    and clearly label gaps + the manual recon that would close them.
    """
    present_block = "\n".join(f"  - {p}" for p in present) or "  - (none)"
    missing_block = "\n".join(f"  - {m}" for m in missing) or "  - (none — full coverage)"
    return (
        "\n---\n\n"
        "## Recon Data Availability (Best-Effort Mode)\n\n"
        "**Available for this engagement:**\n"
        f"{present_block}\n\n"
        "**Not available (do NOT invent it — treat findings that would depend "
        "on it as hypotheses requiring manual verification):**\n"
        f"{missing_block}\n\n"
        "Perform a **best-effort analysis** with whatever data is present above. "
        "Never refuse or return an 'insufficient data' placeholder. When a "
        "promising vector depends on missing data, still surface it as a "
        "manual attack vector labelled **Needs verification**, and state the "
        "exact recon step that would confirm it.\n"
    )


def _build_batch_prompt(
    target: str,
    fp_data: list,
    js_data: dict | None = None,
    http_responses: list | None = None,
    data_present: list | None = None,
    data_missing: list | None = None,
    active_data: dict | None = None,
) -> str:
    """
    Build the user-turn message that is sent alongside _SYSTEM.

    The safety constraints from _SYSTEM are deliberately re-stated inline here
    (two-layer architecture) so the model has immediate, contextual reminders
    at the exact point where it writes each command.  This is not redundancy —
    it is defence-in-depth against prompt drift in long responses.
    """
    fp_json   = json.dumps(fp_data, indent=2)
    host_list = "\n".join(
        f"  - {item.get('host', 'unknown')}" for item in fp_data
    )

    return f"""You are conducting an **authorised bug bounty engagement** against the scope: `{target}`

The recon and fingerprinting pipeline has discovered **{len(fp_data)} live host(s)**:
{host_list}

Below is the complete technology fingerprint data for every host:

```json
{fp_json}
```
{_build_js_section(js_data or {})}
{_build_http_section(http_responses)}
{_build_active_recon_section(active_data or {})}
{_build_availability_note(data_present or [], data_missing or [])}
---

## ⚠️ Rules of Engagement — Read Before Writing Any Command

These constraints are **absolute** and apply to every host, every section, and every
command in your response.  They reflect the Safe Harbor terms of the engagement.

| Category | Requirement |
|---|---|
| **Nuclei** | MUST include `-exclude-tags dos,destructive,fuzz` on every command |
| **SQLMap** | MUST use `--level 1 --risk 1 --technique=BEUST --batch`; NEVER use `--os-shell`, `--dump-all`, `--dump`, `--file-write` |
| **ffuf / wfuzz** | MUST include `-rate 20 -timeout 10`; no credential-stuffing wordlists |
| **dalfox** | MUST include `--skip-bav --timeout 10` |
| **Webshells** | STRICTLY FORBIDDEN — do not suggest uploading shell.php or any backdoor |
| **Data destruction** | STRICTLY FORBIDDEN — no DROP, TRUNCATE, DELETE without a scoped WHERE |
| **DoS** | STRICTLY FORBIDDEN — no flood tools, no resource-exhaustion payloads |
| **Bulk exfil** | STRICTLY FORBIDDEN — no --dump-all; use LIMIT 1 for SQL confirmation only |
| **RCE exploitation** | CONFIRM ONLY — one non-destructive signal (DNS callback, sleep delay, or `id` once) then stop |

**Goal: Non-Destructive PoC only.  Stop at the first evidence of the vulnerability.**

---

## Your Task

Analyse **each host individually** and produce an **evidence-first findings report** in the
style of a professional scanner + pentest report. Report only what the collected recon data
supports; never speculate to fill space.

**CRITICAL — Machine-parseable output format:**
Wrap every host's analysis inside these exact XML delimiters.
Use the host URL exactly as it appears in the fingerprint data above:

```
<host_analysis url="EXACT_HOST_URL">
[analysis content here]
</host_analysis>
```

---

### Required sections for EACH host — in this order

#### 1. Target
- **Host:** the URL   **Stack:** one precise sentence — only what was actually detected.

#### 2. Confirmed Findings
Findings the collected evidence PROVES (per the CONFIRMATION DISCIPLINE below). For each:

**[SEVERITY] Title** — CVSS 3.1 X.X (`vector`)
- **Evidence:** [tool] → [exact data point quoted from the recon data above]
- **Impact:** one concrete sentence — what an attacker actually gains.

If nothing is proven, write this line for the section and nothing else:
`No confirmed findings from the collected evidence.`
That is a valid, professional result — do NOT invent "probable" vulnerabilities to fill space,
and put NO CVSS/severity anywhere except a genuinely confirmed finding.

#### 3. Leads to Verify  (unconfirmed — NOT findings; NO severity, NO CVSS)
Concrete, evidence-anchored hypotheses worth a MANUAL check, ordered by how likely each is to
convert into an in-scope, impact-bearing bug. Omit any lead you cannot tie to a specific data
point above. For each, one tight block:
- **Lead:** what was observed (cite tool → data point).
- **Why plausible:** one sentence tied to that exact evidence.
- **Confirm with:** the single least-intrusive manual step (use the command sections below).
- **Promotes to a finding if:** the exact observable result that would make it real.

#### 4. Context-Aware Nuclei Commands  ⚠️ MUST include `-exclude-tags dos,destructive,fuzz`
For the LEADS above only (omit this section entirely if there are no leads): detection-only
`nuclei` commands using exact template paths that would confirm a specific lead.

```bash
# [What CVE / misconfiguration this confirms]
nuclei -u TARGET -t cves/YEAR/CVE-XXXX-XXXXX.yaml -exclude-tags dos,destructive,fuzz

# [Technology-specific exposure check]
nuclei -u TARGET -t exposures/configs/template-name.yaml -exclude-tags dos,destructive,fuzz

# [Authentication bypass / information-disclosure probe]
nuclei -u TARGET -t vulnerabilities/category/template.yaml \
  -exclude-tags dos,destructive,fuzz -H "X-Custom-Header: value"
```

#### 5. Safe PoC Commands  ⚠️ Destructive flags and webshells are FORBIDDEN
For the LEADS above only (omit if there are none): minimal, non-destructive commands that
confirm a specific lead. Each command MUST comply with the tool-specific safety flags above.

```bash
# sqlmap — injection confirmation only (no data dump, no OS interaction)
sqlmap -u "TARGET/page?id=1" --level 1 --risk 1 --technique=BEUST --batch --string="welcome"

# ffuf — endpoint discovery with rate cap
ffuf -u TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -rate 20 -timeout 10 -mc 200,301,302,403

# dalfox — XSS parameter probe (no blind callbacks)
dalfox url "TARGET/search?q=test" --skip-bav --timeout 10

# curl — single-request header / version confirmation
curl -sI TARGET | grep -i "server:\\|x-powered-by:\\|x-aspnet"
```

#### 6. Attack Surface (for manual testing)
The concrete inputs discovered in the recon data above — this is the actionable map. List the
real endpoints, parameters, forms, upload/account/auth flows, and JS-derived routes/secrets
worth manual testing, grouped by area, each citing where it came from (JS-Oracle / crawl /
http). If none were discovered, say "none discovered".

---

#### 7. Evidence Matrix

Close your analysis for this host with the following table.
Include ONLY items that appear in the Confirmed Findings (2) and Leads (3) sections above.

```
## Evidence Matrix

| # | Finding | Source Tool | Evidence | Confidence |
|---|---------|-------------|----------|------------|
| 1 | <finding name> | <tool> | <specific data point> | Confirmed |
| 2 | <finding name> | <tool> | <detected product/version> | Technology detected |
| 3 | <finding name> | <tool> | <specific data point> | Needs verification |
```

Confidence levels — use EXACTLY one of these THREE labels (see the CONFIRMATION
DISCIPLINE rules in the system prompt):
  - **Confirmed**: ONLY when executable evidence proves exploitability — an
    injected payload that executed/reflected, an exploit request returning the
    expected HTTP 200/marker, or a byte-for-byte matching response. A detected
    version or product is NOT enough for "Confirmed".
  - **Technology detected**: a product/version/stack was fingerprinted, but no
    working request has proven the vulnerability. Use this for version-based CVE
    suspicions where the exploit was not fired.
  - **Needs verification**: historical, indirect, or URL-only signal (e.g. an
    endpoint discovered in crawl/wayback output with no observed response);
    requires a manual check before reporting.

Rules for this table:
  ✗ NEVER include a row for a finding you cannot cite a tool and data point for
  ✗ NEVER use "Confirmed" without executable evidence quoted from the response
  ✗ NEVER cite a CVE in a row whose evidence has no detected version number
  ✗ NEVER use a confidence level other than the three labels above
  ✓ Every row MUST map to a finding already listed in Sections 2 or 6

---

All analysis MUST be version-specific.  Generic web-app advice is forbidden.
Every command MUST comply with the Rules of Engagement table above."""


# ── Response parser ───────────────────────────────────────────────────────────

def _parse_batch_response(text: str, fp_data: list) -> dict:
    """
    Extract per-host analyses from Claude's batch response.

    Parsing strategy (priority order):
    1. <host_analysis url="...">...</host_analysis>  (canonical XML tags)
    2. ## ANALYSIS: <url>  section headers           (fallback)
    3. Entire response attributed to first host       (last resort)
    """
    analyses: dict = {}

    # ── Strategy 1: XML tags (expected canonical format) ─────────────────────
    xml_re = re.compile(
        r'<host_analysis\s+url=["\']([^"\']+)["\']>(.*?)</host_analysis>',
        re.DOTALL | re.IGNORECASE,
    )
    for url, content in xml_re.findall(text):
        analyses[url.strip()] = content.strip()

    if analyses:
        _fill_missing(analyses, fp_data)
        return analyses

    # ── Strategy 2: Section headers ───────────────────────────────────────────
    parts = re.split(r'(?m)^##\s+ANALYSIS[:\s]+', text)
    if len(parts) > 1:
        for part in parts[1:]:
            lines = part.strip().splitlines()
            if lines:
                url     = lines[0].strip().rstrip(":")
                content = "\n".join(lines[1:]).strip()
                if url:
                    analyses[url] = content

    if analyses:
        _fill_missing(analyses, fp_data)
        return analyses

    # ── Strategy 3: Attribute entire response to first host ───────────────────
    if fp_data:
        first = fp_data[0].get("host", "unknown")
        analyses[first] = text.strip()
        for item in fp_data[1:]:
            h = item.get("host", "")
            if h:
                analyses[h] = "See combined analysis above."

    return analyses


def _fill_missing(analyses: dict, fp_data: list) -> None:
    """
    For any fingerprinted host absent from the parsed analyses dict, try a
    fuzzy URL match (handles trailing-slash / scheme mismatches), then fall
    back to marking it as unavailable.
    """
    known = list(analyses.keys())
    for item in fp_data:
        host = item.get("host", "")
        if not host or host in analyses:
            continue
        norm  = host.rstrip("/")
        found = False
        for k in known:
            if k.rstrip("/") == norm or norm in k or k in norm:
                analyses[host] = analyses[k]
                found = True
                break
        if not found:
            analyses[host] = "Analysis not generated for this host."


# ── Command sanitizer ────────────────────────────────────────────────────────

class CommandSanitizer:
    """
    Hardcoded post-processing layer that enforces Rules of Engagement
    on every shell command extracted from AI output.

    This is defence-in-depth — the prompt already asks for safe commands,
    but this layer enforces them in Python code regardless of AI output.
    It is NOT a filter applied before sending to the AI.
    It is applied AFTER the AI response is received.
    """

    # ── Forbidden flags — remove these from any command ──────────────
    SQLMAP_FORBIDDEN = [
        '--os-shell', '--os-pwn', '--os-cmd',
        '--dump-all', '--dump',
        '--sql-shell', '--file-write', '--file-dest',
        '--priv-esc', '--os-bof',
    ]

    NUCLEI_FORBIDDEN = [
        '-interactsh-server',  # exfil server override
    ]

    # ── Required flags — add these if missing ────────────────────────
    NUCLEI_REQUIRED = '-exclude-tags dos,destructive,fuzz'
    SQLMAP_REQUIRED = '--level 1 --risk 1 --batch'
    FFUF_RATE_CAP   = '-rate 20'
    DALFOX_REQUIRED = '--skip-bav'

    # ── Completely forbidden tools ────────────────────────────────────
    FORBIDDEN_TOOLS = [
        'msfconsole', 'msfvenom',   # Metasploit
        'sqlninja', 'sqlsus',        # aggressive SQL tools
        'commix',                    # OS injection auto-exploit
        'weevely',                   # webshell generator
        'beef-xss',                  # browser exploitation framework
    ]

    @classmethod
    def sanitize_command(cls, cmd: str) -> tuple[str, list[str]]:
        """
        Apply all safety rules to a single shell command string.

        Returns:
            (sanitized_cmd, warnings)
            warnings: list of strings describing what was changed

        Rules applied:
        1. If command uses a forbidden tool → replace entire command
           with a comment explaining it was blocked
        2. sqlmap: remove all SQLMAP_FORBIDDEN flags
                   add SQLMAP_REQUIRED flags if missing
        3. nuclei:  remove NUCLEI_FORBIDDEN flags
                    add NUCLEI_REQUIRED if -exclude-tags is absent
        4. ffuf / wfuzz / feroxbuster: add -rate 20 if no -rate flag
        5. dalfox: add --skip-bav if missing
        6. curl: block while-true loops
                 (detect: 'while' and 'curl' in same command)
        """
        warnings: list[str] = []
        stripped = cmd.strip()

        if not stripped:
            return cmd, warnings

        # Rule 6: curl while-true loops
        if 'while' in stripped and 'curl' in stripped:
            warnings.append(
                f"Blocked curl while-loop (DoS risk): {stripped}"
            )
            return "# BLOCKED: curl while-loop removed (DoS risk)", warnings

        tokens = stripped.split()
        first_token = tokens[0].lower() if tokens else ''

        # Rule 1: forbidden tools
        for tool in cls.FORBIDDEN_TOOLS:
            if first_token == tool:
                warnings.append(f"Blocked forbidden tool '{tool}'")
                return (
                    "# BLOCKED: tool not permitted under Rules of Engagement",
                    warnings,
                )

        # Rule 2: sqlmap
        if first_token == 'sqlmap':
            for flag in cls.SQLMAP_FORBIDDEN:
                if flag in stripped:
                    stripped = re.sub(
                        r'\s+' + re.escape(flag) + r'(?=\s|$)', '', stripped
                    )
                    warnings.append(f"Removed forbidden sqlmap flag: {flag}")
            missing = []
            if '--level 1' not in stripped:
                missing.append('--level 1')
            if '--risk 1' not in stripped:
                missing.append('--risk 1')
            if '--batch' not in stripped:
                missing.append('--batch')
            if missing:
                addition = ' '.join(missing)
                stripped = stripped.rstrip() + ' ' + addition
                warnings.append(f"Added required sqlmap flags: {addition}")
            return stripped, warnings

        # Rule 3: nuclei
        if first_token == 'nuclei':
            for flag in cls.NUCLEI_FORBIDDEN:
                if flag in stripped:
                    stripped = re.sub(
                        r'\s+' + re.escape(flag) + r'(?=\s|$)', '', stripped
                    )
                    warnings.append(f"Removed forbidden nuclei flag: {flag}")
            if '-exclude-tags' not in stripped:
                stripped = stripped.rstrip() + ' ' + cls.NUCLEI_REQUIRED
                warnings.append(f"Added required nuclei flags: {cls.NUCLEI_REQUIRED}")
            return stripped, warnings

        # Rule 4: ffuf / wfuzz / feroxbuster
        if first_token in ('ffuf', 'wfuzz', 'feroxbuster'):
            if '-rate' not in stripped:
                stripped = stripped.rstrip() + ' ' + cls.FFUF_RATE_CAP
                warnings.append(f"Added rate cap to {first_token}: {cls.FFUF_RATE_CAP}")
            return stripped, warnings

        # Rule 5: dalfox
        if first_token == 'dalfox':
            if '--skip-bav' not in stripped:
                stripped = stripped.rstrip() + ' ' + cls.DALFOX_REQUIRED
                warnings.append(f"Added required dalfox flags: {cls.DALFOX_REQUIRED}")
            return stripped, warnings

        return stripped, warnings

    @classmethod
    def sanitize_markdown(cls, text: str) -> tuple[str, list[str]]:
        """
        Extract all code blocks from Markdown text, sanitize each
        shell command inside them, and return the modified text.

        A "shell command" is any line inside a fenced code block
        (``` or ```bash or ```sh) that starts with a known tool name:
        nuclei, sqlmap, ffuf, wfuzz, feroxbuster, dalfox, curl, nmap,
        whatweb, httpx, subfinder.

        Algorithm:
        1. Find all fenced code blocks with regex:
               r'```(?:bash|sh|shell)?\n(.*?)```'
               flags: re.DOTALL
        2. For each code block, split into lines
        3. For each line, check if it starts with a known tool
           (after stripping leading whitespace and comments)
        4. If yes: apply sanitize_command()
        5. Reassemble the code block with sanitized lines
        6. Replace the original block in the text
        7. Collect all warnings across all blocks

        Returns:
            (sanitized_text, all_warnings)
        """
        KNOWN_TOOLS = {
            'nuclei', 'sqlmap', 'ffuf', 'wfuzz', 'feroxbuster',
            'dalfox', 'curl', 'nmap', 'whatweb', 'httpx', 'subfinder',
        }
        all_warnings: list[str] = []
        code_block_re = re.compile(
            r'(```(?:bash|sh|shell)?\n)(.*?)(```)', re.DOTALL
        )

        def process_block(match: re.Match) -> str:
            opener  = match.group(1)
            body    = match.group(2)
            closer  = match.group(3)

            lines     = body.split('\n')
            new_lines = []
            for line in lines:
                lstripped = line.lstrip()
                if not lstripped or lstripped.startswith('#'):
                    new_lines.append(line)
                    continue
                first_token = lstripped.split()[0].lower()
                if first_token in KNOWN_TOOLS:
                    sanitized, warns = cls.sanitize_command(lstripped)
                    all_warnings.extend(warns)
                    leading = line[: len(line) - len(line.lstrip())]
                    new_lines.append(leading + sanitized)
                else:
                    new_lines.append(line)

            return opener + '\n'.join(new_lines) + closer

        result = code_block_re.sub(process_block, text)
        return result, all_warnings

    @classmethod
    def sanitize_analysis(cls, analyses: dict) -> tuple[dict, dict]:
        """
        Apply sanitize_markdown() to every host analysis in the dict.

        analyses: { host_url: markdown_string }

        Returns:
            (sanitized_analyses, warnings_by_host)
            warnings_by_host: { host_url: [warning_strings] }
        """
        sanitized: dict        = {}
        warnings_by_host: dict = {}
        for host, text in analyses.items():
            sanitized_text, warnings = cls.sanitize_markdown(text)
            sanitized[host] = sanitized_text
            if warnings:
                warnings_by_host[host] = warnings
        return sanitized, warnings_by_host


# ── Module ────────────────────────────────────────────────────────────────────

class AIAdvisorModule:
    """
    Module 3 — AI Vulnerability Advisor (v3 Enterprise Edition).

    Sends all fingerprinted hosts to Claude Opus 4.8 in a single batch
    request, parses per-host analysis sections, and persists the full report.
    Never raises — all exceptions are caught and surfaced as error events.
    """

    def __init__(
        self,
        fp_data: list,
        output_dir: Path,
        js_data: dict | None = None,
        active_data: dict | None = None,
    ) -> None:
        self.fp_data     = fp_data
        self.output_dir  = output_dir
        self.js_data     = js_data or {}
        self.active_data = active_data or {}
        self.advice_file = output_dir / Config.FILE_AI_ADVICE
        self._client: Optional["anthropic.Anthropic"] = None

    # ── Client initialisation ─────────────────────────────────────────────

    def _init_client(self, events: list) -> bool:
        if not _ANTHROPIC_AVAILABLE:
            events.append(_ev("error",
                "Python package 'anthropic' is not installed. "
                "Run: pip install anthropic"
            ))
            return False

        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            events.append(_ev("error",
                "ANTHROPIC_API_KEY environment variable is not set. "
                "Obtain a key at: https://console.anthropic.com/"
            ))
            return False

        try:
            self._client = anthropic.Anthropic(api_key=api_key)
            events.append(_ev("success",
                f"Anthropic client initialised → model: {_CLAUDE_MODEL}"
            ))
            return True
        except Exception as exc:
            events.append(_ev("error", f"Failed to initialise Anthropic client: {exc}"))
            return False

    # ── Batch API call with retry ─────────────────────────────────────────

    def _call_claude(self, prompt: str, events: list) -> Optional[str]:
        """
        Send the batch prompt to Claude Opus 4.8.

        Retries up to _MAX_RETRIES times on transient errors (overload,
        connection failures). Bails immediately on auth / bad-request errors.
        Returns the raw response text, or None on unrecoverable failure.
        """
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                events.append(_ev("info",
                    f"[Attempt {attempt}/{_MAX_RETRIES}] Sending batch request to "
                    f"{_CLAUDE_MODEL} — {len(self.fp_data)} host(s) in scope…"
                ))

                with self._client.messages.stream(
                    model=_CLAUDE_MODEL,
                    max_tokens=_MAX_TOKENS,
                    system=_SYSTEM,
                    messages=[{"role": "user", "content": prompt}],
                ) as stream:
                    msg = stream.get_final_message()

                text = msg.content[0].text if msg.content else ""
                if text.strip():
                    events.append(_ev("success",
                        f"Claude response received — {len(text):,} chars, "
                        f"stop_reason: {msg.stop_reason}"
                    ))
                    return text.strip()

                events.append(_ev("warning", "Claude returned an empty response"))
                return None

            except Exception as exc:
                exc_name = type(exc).__name__
                exc_str  = str(exc)

                # Non-retryable: authentication
                if any(x in exc_name for x in ("AuthenticationError", "PermissionDenied")):
                    events.append(_ev("error",
                        "Authentication failed — verify ANTHROPIC_API_KEY is valid "
                        "and has Messages API access"
                    ))
                    return None

                # Non-retryable: bad request (prompt too large, invalid params)
                if any(x in exc_name for x in ("InvalidRequestError", "BadRequestError")):
                    events.append(_ev("error", f"Invalid request: {exc}"))
                    return None

                # Retryable: overload, rate limit, connection errors
                if attempt < _MAX_RETRIES:
                    events.append(_ev("warning",
                        f"Transient error on attempt {attempt}/{_MAX_RETRIES}: "
                        f"{exc_name} — retrying in {_RETRY_DELAY}s…"
                    ))
                    time.sleep(_RETRY_DELAY)
                else:
                    events.append(_ev("error",
                        f"Claude API failed after {_MAX_RETRIES} attempt(s): "
                        f"{exc_name}: {exc_str}"
                    ))

        return None

    # ── Public interface ──────────────────────────────────────────────────

    def execute(self) -> dict:
        """
        Run a single-batch Claude analysis for all fingerprinted hosts.
        Returns a result envelope — never raises.
        """
        events:   list = []
        analyses: dict = {}

        if not self.fp_data:
            events.append(_ev("error", "No fingerprint data — run Module 2 first"))
            return {"status": "error", "events": events, "analyses": {}}

        if not self._init_client(events):
            return {"status": "error", "events": events, "analyses": {}}

        # Derive a clean target name for the prompt header
        first_host = self.fp_data[0].get("host", "unknown")
        try:
            target = urlparse(first_host).netloc or first_host
        except Exception:
            target = first_host

        # Load supplementary recon outputs from disk for the data-point gate.
        # These files are written by ReconModule and are not embedded in fp_data.
        hist_file = self.output_dir / "historical_urls.json"
        try:
            historical_urls: list = (
                json.loads(hist_file.read_text()) if hist_file.exists() else []
            )
        except Exception:
            historical_urls = []

        http_file = self.output_dir / "http_responses.json"
        try:
            http_responses: list = (
                json.loads(http_file.read_text()) if http_file.exists() else []
            )
        except Exception:
            http_responses = []

        # Assess data availability for a BEST-EFFORT analysis.
        # We no longer hard-reject when some categories are missing: as long as
        # there is at least fingerprint data (guaranteed above), we run the
        # analysis and tell the model exactly what is / isn't available so it
        # can degrade gracefully instead of returning a placeholder.
        dp_count, dp_present, dp_missing = _count_data_points(
            self.fp_data, self.js_data, historical_urls, http_responses,
            self.active_data,
        )
        events.append(_ev("info",
            f"Data-point check: {dp_count}/6 categories populated "
            f"— best-effort analysis (no minimum gate)"
        ))
        if dp_missing:
            events.append(_ev("warning",
                "Partial recon data — proceeding best-effort. Missing: "
                + ", ".join(dp_missing)
            ))

        events.append(_ev("info",
            f"Starting batch analysis — {len(self.fp_data)} host(s) → "
            f"{_CLAUDE_MODEL} (single request, no rate-limit overhead)"
        ))

        prompt   = _build_batch_prompt(
            target,
            self.fp_data,
            self.js_data,
            http_responses=http_responses,
            data_present=dp_present,
            data_missing=dp_missing,
            active_data=self.active_data,
        )
        raw_text = self._call_claude(prompt, events)

        if not raw_text:
            for item in self.fp_data:
                h = item.get("host", "")
                if h:
                    analyses[h] = "Analysis unavailable."
            return {"status": "error", "events": events, "analyses": analyses}

        # Parse XML-delimited per-host sections
        analyses = _parse_batch_response(raw_text, self.fp_data)

        # Post-processing: enforce safety rules on all AI-generated commands
        sanitized_analyses, sanitization_warnings = \
            CommandSanitizer.sanitize_analysis(analyses)

        # Log any changes made by the sanitizer
        for host, warnings in sanitization_warnings.items():
            for w in warnings:
                events.append({
                    "level": "warning",
                    "msg": f"[SANITIZER] {host}: {w}"
                })

        # Replace analyses with sanitized version
        analyses = sanitized_analyses

        # Emit structured analysis events for the CLI renderer
        for host, text in analyses.items():
            if text and text not in (
                "Analysis unavailable.",
                "Analysis not generated for this host.",
                "See combined analysis above.",
            ):
                events.append(_ev_analysis(host, text))

        # Persist full report to disk
        output_parts: list = []
        for host, text in analyses.items():
            if text and "unavailable" not in text.lower() and "not generated" not in text.lower():
                output_parts += [
                    f"\n{'=' * 70}",
                    f"TARGET: {host}",
                    f"{'=' * 70}\n",
                    text,
                ]

        if output_parts:
            self.advice_file.write_text("\n".join(output_parts))
            events.append(_ev_data("AI advice saved to", str(self.advice_file)))

        _UNAVAILABLE = {
            "Analysis unavailable.",
            "Analysis not generated for this host.",
            "See combined analysis above.",
            "",
        }
        success_count = sum(1 for v in analyses.values() if v not in _UNAVAILABLE)
        total         = len(self.fp_data)

        events.append(_ev("success",
            f"Module 3 complete — {success_count}/{total} host(s) analysed "
            f"by {_CLAUDE_MODEL} in a single batch request"
        ))

        status = (
            "ok"      if success_count == total else
            "partial" if success_count > 0      else
            "error"
        )
        return {"status": status, "events": events, "analyses": analyses}
