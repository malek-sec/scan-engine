"""
core/offline_report.py — deterministic recon report, ZERO API cost.

Renders a professional, evidence-first Markdown report from a scan's on-disk
artifacts (js_oracle_findings.json + surface files) with NO LLM call. It is the
report path for FREE / --offline scans, and the recovery path when the Opus
advisor cannot run (e.g. empty API credit).

Importable:   from core.offline_report import build_report
              md = build_report(output_dir)          # output_dir: Path | str
CLI wrapper:  scan-engine/tools/offline_report.py

Every function is pure + deterministic. A missing findings file degrades to a
surface-only report (never raises) so a JS-less scan still produces something.
"""
from __future__ import annotations

import json
from pathlib import Path

_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "none": 0}
_CONF_RANK = {"high": 3, "medium": 2, "low": 1}
_CRED_TYPES = {"api_key", "aws_key", "jwt", "token", "secret", "private_key", "password"}


def _load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _load_lines(p: Path) -> list:
    try:
        return [ln.strip() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    except Exception:
        return []


def _sev_badge(sev: str) -> str:
    return {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
            "low": "LOW", "info": "INFO"}.get((sev or "info").lower(), (sev or "info").upper())


def _extras(item: dict, known: set) -> str:
    rest = {k: v for k, v in item.items() if k not in known and v not in (None, "", [], {})}
    if not rest:
        return ""
    return "  \n    · " + " · ".join(f"{k}=`{v}`" for k, v in rest.items())


def _fmt_secrets(secrets: list, out: list) -> None:
    if not secrets:
        return
    creds = [s for s in secrets if str(s.get("type", "")).lower() in _CRED_TYPES]
    info = [s for s in secrets if s not in creds]
    out.append(f"## 🔑 Secrets & Credentials ({len(secrets)})\n")
    if creds:
        out.append("**Credential-class (verify manually — most likely real):**\n")
        for s in creds:
            out.append(
                f"- **{s.get('type','?')}** — `{s.get('value_preview','?')}`"
                + (f"  \n    evidence: `{s.get('evidence','')}`" if s.get("evidence") else "")
                + _extras(s, {"type", "value_preview", "evidence"})
            )
        out.append("")
    if info:
        out.append("**Informational (IPs / source maps / low-signal):**\n")
        for s in info:
            out.append(
                f"- {s.get('type','?')} — `{s.get('value_preview', s.get('description','?'))}`"
                + (f"  \n    evidence: `{s.get('evidence','')}`" if s.get("evidence") else "")
            )
        out.append("")


def _fmt_endpoints(endpoints: list, out: list) -> None:
    if not endpoints:
        return
    endpoints = sorted(
        endpoints,
        key=lambda e: (-_CONF_RANK.get(str(e.get("confidence", "low")).lower(), 1), str(e.get("path", "")))
    )
    out.append(f"## 🌐 API Endpoints ({len(endpoints)})\n")
    out.append("Test each for authz gaps (IDOR/BOLA), missing auth, and injection. "
               "High/medium confidence first.\n")
    out.append("| Method | Path | Conf. | Evidence |")
    out.append("|---|---|---|---|")
    for e in endpoints:
        path = str(e.get("path", "")).replace("|", "\\|")
        ev = str(e.get("evidence", "")).replace("|", "\\|").replace("\n", " ")[:80]
        out.append(f"| {e.get('method','UNKNOWN')} | `{path}` | {e.get('confidence','low')} | {ev} |")
    out.append("")


def _fmt_auth(auth: list, out: list) -> None:
    if not auth:
        return
    out.append(f"## 🔐 Authentication / Session Logic ({len(auth)})\n")
    for a in auth:
        out.append(
            f"- **{a.get('mechanism','?')}** — stored in `{a.get('storage_location','unknown')}`"
            + (f"  \n    evidence: `{a.get('evidence','')}`" if a.get("evidence") else "")
            + _extras(a, {"mechanism", "storage_location", "evidence"})
        )
    out.append("")


def _fmt_suspicious(items: list, title: str, out: list) -> None:
    if not items:
        return
    items = sorted(items, key=lambda x: -_SEV_RANK.get(str(x.get("severity", "info")).lower(), 1))
    out.append(f"## ⚠️ {title} ({len(items)})\n")
    for x in items:
        out.append(
            f"- **[{_sev_badge(x.get('severity'))}]** {x.get('description', x.get('type','(no description)'))}"
            + (f"  \n    evidence: `{x.get('evidence','')}`" if x.get("evidence") else "")
            + _extras(x, {"severity", "description", "type", "evidence"})
        )
    out.append("")


def _fmt_archived(dir_: Path, out: list) -> None:
    data = _load_json(dir_ / "js_archived_endpoints.json")
    if not data:
        return
    rows = data if isinstance(data, list) else data.get("archived_endpoints", data.get("endpoints", []))
    if not rows:
        return
    out.append(f"## 🗄️ Archived JS — NOT analyzed, manual review ({len(rows)})\n")
    out.append("Referenced (historical/blocked) but not served as live JS at scan time. "
               "Not evidence the target is clean — fetch and review manually.\n")
    for r in rows[:60]:
        u = r.get("url") if isinstance(r, dict) else r
        st = f" (status {r.get('status')})" if isinstance(r, dict) and r.get("status") is not None else ""
        out.append(f"- `{u}`{st}")
    if len(rows) > 60:
        out.append(f"- … and {len(rows) - 60} more")
    out.append("")


def _fmt_surface(dir_: Path, out: list) -> None:
    subs = _load_lines(dir_ / "subdomains.txt")
    live = _load_lines(dir_ / "live_hosts.txt") or _load_lines(dir_ / "active_hosts.txt")
    fp = _load_json(dir_ / "fingerprint.json")
    if not (subs or live or fp):
        return
    out.append("## 🗺️ Attack Surface\n")
    if live:
        out.append(f"**Live hosts ({len(live)}):**")
        for h in live[:40]:
            out.append(f"- `{h}`")
        out.append("")
    if subs and len(subs) != len(live):
        out.append(f"**Subdomains discovered ({len(subs)}):** " + ", ".join(f"`{s}`" for s in subs[:40])
                   + (f" … +{len(subs)-40} more" if len(subs) > 40 else ""))
        out.append("")
    if isinstance(fp, dict):
        techs = fp.get("technologies") or fp.get("tech") or []
        if techs:
            names = [t.get("name", str(t)) if isinstance(t, dict) else str(t) for t in techs]
            out.append("**Technologies:** " + ", ".join(f"`{n}`" for n in names[:30]))
            out.append("")


def build_report(output_dir) -> str:
    """Render the Markdown report for a scan output directory (or a direct path
    to a js_oracle_findings.json). Never raises."""
    p = Path(output_dir)
    findings_path = p if p.is_file() else p / "js_oracle_findings.json"
    base = findings_path.parent
    data = _load_json(findings_path) or {}

    endpoints = data.get("endpoints", [])
    secrets = data.get("secrets", data.get("api_keys", []))
    auth = data.get("auth_logic", data.get("auth_issues", []))
    sinks = data.get("sinks", [])
    biz = data.get("business_logic", [])
    highest = data.get("highest_severity", "none")
    total = len(endpoints) + len(secrets) + len(auth) + len(sinks) + len(biz)

    out: list = []
    out.append(f"# Recon Report — {base.name}")
    out.append("")
    out.append("> Generated **offline** from saved scan artifacts — **no API call, no cost.** "
               "Deterministic render of the findings; not an AI synthesis.")
    out.append("")
    out.append("## Summary")
    out.append("")
    out.append(f"- **Total findings:** {total}")
    out.append(f"- **Highest severity:** {_sev_badge(highest) if highest != 'none' else 'none'}")
    out.append(f"- Endpoints: {len(endpoints)} · Secrets: {len(secrets)} · "
               f"Auth: {len(auth)} · Sinks: {len(sinks)} · Business-logic: {len(biz)}")
    if "js_files_analyzed" in data:
        out.append(f"- JS files analyzed: {data.get('js_files_analyzed')} "
                   f"(live: {data.get('js_live_count','?')}, archived parked: {data.get('archived_count','?')})")
    out.append("")
    out.append("> ⚠️ Program policy: raw tool output is **not** an acceptable report. "
               "Every item below is a *lead* — reproduce manually and attach a PoC before submitting.")
    out.append("")

    _fmt_secrets(secrets, out)
    _fmt_endpoints(endpoints, out)
    _fmt_auth(auth, out)
    _fmt_suspicious(sinks, "Dangerous Sinks (XSS / injection / eval)", out)
    _fmt_suspicious(biz, "Business-Logic Concerns", out)
    _fmt_archived(base, out)
    _fmt_surface(base, out)

    if total == 0:
        out.append("_No JS findings were recorded. The analysis may have been skipped "
                   "(no live JS) or blocked — check the scan log. This is NOT proof the "
                   "target is clean._\n")

    out.append("---")
    out.append("_offline_report · deterministic · $0 · re-run any time from the saved findings._")
    return "\n".join(out) + "\n"
