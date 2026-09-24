"""A single machine-readable rollup of a whole scan run.

Each module already writes its own artifact (subdomains, live hosts, fingerprint,
active-recon output, JS findings). This adds one ``summary.json`` that ties them
together — counts, the scope that was enforced, and the JS-analysis rollup — so a
run can be consumed by automation (or BountyHub) without re-parsing every file.

The builder is a pure function so it can be unit-tested without running the
pipeline; the CLI wraps it to write the file.
"""

from __future__ import annotations

from datetime import datetime


def build_run_summary(
    *,
    target: str | None,
    scope_desc: str | None,
    live_hosts: list,
    fp_data: list,
    js_files: list,
    historical_urls: list,
    active_data: dict | None,
    js_data: dict | None,
) -> dict:
    """Assemble the whole-run summary dict from in-memory pipeline state."""
    ac = active_data or {}

    def _count(section: str) -> int:
        return int((ac.get(section) or {}).get("count", 0) or 0)

    js = js_data or {}
    # JS-Oracle rollup keys vary by version; read them defensively.
    js_rollup = {
        "files_analyzed": js.get("js_files_analyzed", js.get("files_analyzed", 0)),
        "secrets": len(js.get("secrets", []) or []),
        "endpoints": len(js.get("endpoints", []) or []),
        "status": js.get("status"),
    }

    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "target": target,
        "scope": scope_desc,
        "totals": {
            "live_hosts": len(live_hosts or []),
            "fingerprinted": len(fp_data or []),
            "js_files": len(js_files or []),
            "historical_urls": len(historical_urls or []),
            "active_crawl": _count("crawl"),
            "active_fuzz": _count("fuzz"),
            "active_params": _count("params"),
            "nuclei": _count("nuclei"),
        },
        "live_hosts": list(live_hosts or []),
        "js_analysis": js_rollup,
    }
