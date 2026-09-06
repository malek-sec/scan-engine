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


def _is_sourcemap(x: dict) -> bool:
    return (str(x.get("description", "")).startswith("Source map referenced")
            or "sourcemappingurl=" in str(x.get("evidence", "")).lower())


def _map_name(item: dict) -> str:
    ev = str(item.get("evidence", ""))
    if "sourceMappingURL=" in ev:
        return ev.split("sourceMappingURL=", 1)[1].strip().strip("\"'")
    desc = str(item.get("description", ""))
    if "(" in desc and ")" in desc:
        return desc[desc.find("(") + 1:desc.rfind(")")].strip()
    return ""


def _fmt_sourcemaps(maps: list, base: Path, out: list) -> None:
    if not maps:
        return
    host = ""
    live = _load_lines(base / "live_hosts.txt") or _load_lines(base / "active_hosts.txt")
    if live:
        host = live[0].rstrip("/")
    out.append(f"## 🗺️ Source Maps — likely source-code disclosure ({len(maps)})\n")
    out.append("Each live bundle references a `.map`. If it is publicly reachable it exposes the "
               "**original source** (often readable TS/JS with internal routes, comments and "
               "hidden endpoints) — a common information-disclosure finding and a goldmine for "
               "manual review. **Verify each returns 200 and contains a `sources` array before "
               "reporting, and confirm it is in scope.**\n")
    urls: list = []
    for m in maps:
        name = _map_name(m)
        if not name:
            continue
        full = name if name.startswith("http") else (f"{host}/{name.lstrip('/')}" if host else name)
        urls.append(full)
        out.append(f"- `{full}`")
    out.append("")
    if urls:
        out.append("Check accessibility (a `200` with JSON `\"sources\"` = exposed source):")
        out.append("```bash")
        out.append("urls=(")
        for u in urls:
            out.append(f'  "{u}"')
        out.append(")")
        out.append('for u in "${urls[@]}"; do printf \'[%s] %s\\n\' '
                   '"$(curl -sk -o /dev/null -w \'%{http_code}\' "$u")" "$u"; done')
        out.append("```")
        out.append("Then reconstruct any that return 200, e.g. `npx source-map-explorer` or "
                   "`curl -sk <map> | npx sourcemapper -output ./src` — and read the recovered "
                   "code for real bugs.")
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
    out.append("Referenced but not served as live JavaScript at scan time — the `reason` below "
               "says why. A `200` here usually means an SPA catch-all returned `index.html` "
               "(HTML, not JS) for a deleted bundle, so it was parked. **If any reason says the "
               "content-type IS JavaScript, that file was wrongly skipped — analyze it manually.** "
               "Not evidence the target is clean.\n")
    for r in rows[:60]:
        if isinstance(r, dict):
            u = r.get("url", "")
            reason = r.get("reason") or r.get("content_type") or ""
            if not reason and r.get("status") is not None:
                reason = f"status {r.get('status')}"
            out.append(f"- `{u}`" + (f" — {reason}" if reason else ""))
        else:
            out.append(f"- `{r}`")
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

    # Pull source-map references out of the suspicious buckets into their own
    # section — on a webpack/Angular app an exposed .map is the headline lead,
    # not an "info" business-logic note.
    source_maps = [x for x in (sinks + biz) if _is_sourcemap(x)]
    sinks = [x for x in sinks if not _is_sourcemap(x)]
    biz = [x for x in biz if not _is_sourcemap(x)]

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
    out.append(f"- Endpoints: {len(endpoints)} · Secrets: {len(secrets)} · Auth: {len(auth)} · "
               f"Source maps: {len(source_maps)} · Sinks: {len(sinks)} · Business-logic: {len(biz)}")
    if "js_live_count" in data or "js_files_analyzed" in data:
        llm_n = data.get("js_files_analyzed", 0)
        js_line = (f"- JS files: {data.get('js_live_count','?')} live (mined for findings) · "
                   f"{data.get('archived_count','?')} archived / not served as JS (parked)")
        if llm_n:
            js_line += f" · {llm_n} deep-analyzed by AI"
        out.append(js_line)
    out.append("")
    out.append("> ⚠️ Program policy: raw tool output is **not** an acceptable report. "
               "Every item below is a *lead* — reproduce manually and attach a PoC before submitting.")
    out.append("")

    _fmt_secrets(secrets, out)
    _fmt_sourcemaps(source_maps, base, out)
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
