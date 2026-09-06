#!/usr/bin/env python3
"""
advise_from_dir.py — run the Opus AI advisor on a COMPLETED scan's saved output,
reusing the JS findings already extracted (ONE synthesis call, no re-scan).

Use it to upgrade a FREE ($0) scan to a full AI report, or to recover the report
when the advisor failed the first time (e.g. empty API credit).

    python3 tools/advise_from_dir.py /tmp/bountyhub_scans/<scan_id>/

Needs ANTHROPIC_API_KEY (+ credit). Writes ai_report.md (and ai_advice.txt) into
the directory and prints the report. For a $0 report with no AI, use
tools/offline_report.py instead.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scan-engine root
from core.advise_from_dir import advise_from_dir  # noqa: E402


def main(argv: list) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    d = Path(argv[1]).expanduser()
    if not d.exists():
        print(f"ERROR: path not found: {d}", file=sys.stderr)
        return 1

    res = advise_from_dir(d)
    for ev in res.get("events", []):
        print(f"  [{str(ev.get('level', 'info'))[:4]}] {ev.get('msg', '')}", file=sys.stderr)

    report = res.get("report") or ""
    if report:
        out = d / "ai_report.md"
        try:
            out.write_text(report, encoding="utf-8")
            print(f"\n[saved → {out}]  (+ ai_advice.txt)", file=sys.stderr)
        except Exception as e:
            print(f"[warn: could not write {out}: {e}]", file=sys.stderr)
        print(report)
        return 0

    print("\nNo AI report produced — see the events above. Common cause: empty API "
          "credit. Add credit and retry, or run tools/offline_report.py for a $0 "
          "deterministic report from the same saved findings.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
