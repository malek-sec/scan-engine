#!/usr/bin/env python3
"""
offline_report.py — render a professional recon report from a scan's on-disk
artifacts, with ZERO API calls (no Claude, no cost).

Use it to (a) recover the synthesized report when the Opus advisor could not run
(e.g. empty API credit), and (b) as your DEFAULT report path for --offline scans
so routine recon costs nothing.

    python3 tools/offline_report.py <scan_output_dir>
    python3 tools/offline_report.py /tmp/bountyhub_scans/<scan_id>/

Reads (all optional except the findings file):
    js_oracle_findings.json      (required) — merged JS findings
    js_archived_endpoints.json   — endpoints from JS no longer served (manual review)
    subdomains.txt / live_hosts.txt / active_hosts.txt / fingerprint.json — surface

Writes  <dir>/offline_report.md  and prints it to stdout. Fully deterministic.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "none": 0}
_CONF_RANK = {"high": 3, "medium": 2, "low": 1}
# Secret types that are credentials worth flagging first, vs informational (IPs, maps)
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
    """Render any finding keys we didn't explicitly print, so nothing is hidden."""
    rest = {k: v for k, v in item.items() if k not in known and v not in (None, "", [], {})}
    if not rest:
        return ""
    parts = [f"{k}=`{v}`" for k, v in rest.items()]
    return "  \n    · " + " · ".join(parts)


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
    out.append("These files were referenced (historical/blocked) but not served as live JS at scan time. "
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


def build_report(dir_: Path) -> str:
    findings_path = dir_ if dir_.is_file() else dir_ / "js_oracle_findings.json"
    base = findings_path.parent
    data = _load_json(findings_path)
    if data is None:
        return f"ERROR: could not read {findings_path}\n"

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
    out.append("> Generated offline from saved scan artifacts — **no API call, no cost.** "
               "Deterministic render of JS-Oracle findings; not an AI synthesis.")
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
        out.append("_No JS findings were recorded. Check the scan log — the analysis may have "
                   "been skipped (no live JS) or blocked. This is not proof the target is clean._\n")

    out.append("---")
    out.append("_offline_report.py · deterministic · $0 · re-run any time from the saved JSON._")
    return "\n".join(out) + "\n"


def main(argv: list) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    target = Path(argv[1]).expanduser()
    if not target.exists():
        print(f"ERROR: path not found: {target}", file=sys.stderr)
        return 1
    report = build_report(target)
    out_dir = target if target.is_dir() else target.parent
    out_file = out_dir / "offline_report.md"
    try:
        out_file.write_text(report, encoding="utf-8")
        saved = f"\n[saved → {out_file}]"
    except Exception as e:
        saved = f"\n[warn: could not write {out_file}: {e}]"
    print(report)
    print(saved, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
