"""
core/advise_from_dir.py — run the AI advisor on an ALREADY-COMPLETED scan.

Takes a scan's saved output directory (the artifacts BountyHub / the CLI wrote
to /tmp/bountyhub_scans/<scan_id>/) and runs Module 3 (the Opus advisor) on it,
REUSING the JS findings that were already extracted and saved. That means a
single synthesis call — no re-scan, and no re-analysis of the JS files (which
may have cost money the first time). This is the "upgrade a FREE scan to a full
AI report" path, and the recovery path when the advisor failed on empty credit.

    from core.advise_from_dir import advise_from_dir
    res = advise_from_dir("/tmp/bountyhub_scans/<scan_id>/")
    # res = {status, events, analyses, report}   ("report" = combined Markdown)

Requires ANTHROPIC_API_KEY (+ credit) — it makes ONE advisor call. Never raises.
"""
from __future__ import annotations

import json
from pathlib import Path


def _load_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return default


def _js_data_from_findings(d: dict) -> dict:
    """Map the on-disk js_oracle_findings.json schema to the js_data envelope the
    advisor expects (secrets→api_keys, auth_logic→auth_issues, + raw count)."""
    endpoints = d.get("endpoints", []) or []
    secrets = d.get("secrets", d.get("api_keys", [])) or []
    auth = d.get("auth_logic", d.get("auth_issues", [])) or []
    sinks = d.get("sinks", []) or []
    biz = d.get("business_logic", []) or []
    return {
        "endpoints":          endpoints,
        "api_keys":           secrets,
        "auth_issues":        auth,
        "sinks":              sinks,
        "business_logic":     biz,
        "highest_severity":   d.get("highest_severity", "none"),
        "js_files_analyzed":  d.get("js_files_analyzed", 0),
        "raw_findings_count": len(endpoints) + len(secrets) + len(auth) + len(sinks) + len(biz),
        "archived_endpoints": d.get("archived_endpoints", []),
        "archived_count":     d.get("archived_count", 0),
    }


def load_scan_inputs(output_dir) -> tuple[list, dict, dict]:
    """Reconstruct (fp_data, js_data, active_data) from a saved scan directory.
    Missing files degrade to empty — historical_urls.json / http_responses.json
    are read by the advisor itself, straight from output_dir."""
    d = Path(output_dir)

    raw_fp = _load_json(d / "fingerprint.json", [])
    fp_data = raw_fp.get("results", []) if isinstance(raw_fp, dict) else (raw_fp or [])

    raw_js = _load_json(d / "js_oracle_findings.json", None)
    js_data = _js_data_from_findings(raw_js) if isinstance(raw_js, dict) else {}

    active_data = _load_json(d / "active_recon.json", {}) or {}
    if not isinstance(active_data, dict):
        active_data = {}

    return fp_data, js_data, active_data


def advise_from_dir(output_dir) -> dict:
    """Run the advisor on a saved scan dir. Returns {status, events, analyses,
    report}; "report" is the combined per-host Markdown (empty if none). Requires
    ANTHROPIC_API_KEY (+ credit) — one synthesis call. Never raises."""
    d = Path(output_dir)
    fp_data, js_data, active_data = load_scan_inputs(d)

    if not fp_data:
        return {
            "status":   "error",
            "events":   [{"level": "error",
                          "msg": (f"No usable fingerprint.json in {d} — cannot run the "
                                  "advisor. The scan artifacts are missing or expired "
                                  "(/tmp is cleared on reboot). Re-run the scan.")}],
            "analyses": {},
            "report":   "",
        }

    from core.ai_advisor import AIAdvisorModule
    res = AIAdvisorModule(fp_data, d, js_data=js_data, active_data=active_data).execute()

    analyses = res.get("analyses", {}) or {}
    parts: list = []
    for host, text in analyses.items():
        if text and "unavailable" not in text.lower() and "not generated" not in text.lower():
            parts.append(f"## {host}\n\n{text}")
    res["report"] = "\n\n---\n\n".join(parts) if parts else ""
    return res
