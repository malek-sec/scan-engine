#!/usr/bin/env python3
"""
offline_report.py — CLI wrapper around core.offline_report.

Render a professional recon report from a scan's on-disk artifacts with ZERO
API calls (no Claude, no cost). Recovers the synthesized report when the Opus
advisor could not run (e.g. empty credit), and is the default report path for
--offline / FREE scans.

    python3 tools/offline_report.py <scan_output_dir>
    python3 tools/offline_report.py /tmp/bountyhub_scans/<scan_id>/

Writes <dir>/offline_report.md and prints it. The report logic lives in
core/offline_report.py so the web app can import and reuse it.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scan-engine root
from core.offline_report import build_report  # noqa: E402


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
