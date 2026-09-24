#!/usr/bin/env python3
"""
prefilter_tune — tune the JS pre-filter thresholds on REAL data, for free.

Runs ONLY the deterministic scorer from core.js_prefilter (no LLM, no API key,
no cost) over local files / a directory / a URL list, and shows how the
skip/cheap/deep split and the estimated tokens-to-LLM change as you slide the
DEEP threshold. Use it to choose BOUNTYHUB_PREFILTER_DEEP_THRESHOLD for a given
target BEFORE spending any Opus tokens.

Examples
--------
    python tools/prefilter_tune.py --dir ~/downloads/target_js --domain target.com
    cat live_js.txt | python tools/prefilter_tune.py --url-list - --domain target.com
    python tools/prefilter_tune.py -f app.js -f vendor.js

Only analyze assets you are authorized to test. The URL-list mode performs a
plain GET per URL (same fail-open fetch the pre-filter uses); local modes touch
no network at all.
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.js_prefilter import (                       # noqa: E402
    score_content, slice_content, build_offline,
    _fetch_js_source, _CHEAP_THRESHOLD, _DEEP_THRESHOLD,
)


def _load(args) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for f in args.file:
        items.append((f, Path(f).read_text(encoding="utf-8", errors="replace")))
    if args.dir:
        for p in sorted(Path(args.dir).rglob("*.js")):
            items.append((str(p), p.read_text(encoding="utf-8", errors="replace")))
    if args.url_list:
        raw = sys.stdin.read() if args.url_list == "-" else Path(args.url_list).read_text()
        for line in raw.splitlines():
            u = line.strip()
            if not u or u.startswith("#"):
                continue
            content = _fetch_js_source(u)
            if content is None:
                print(f"  ! fetch failed (would fail-open -> deep): {u}", file=sys.stderr)
                continue
            items.append((u, content))
    return items


def main() -> None:
    ap = argparse.ArgumentParser(description="Tune JS pre-filter thresholds on real data (offline).")
    ap.add_argument("-f", "--file", action="append", default=[], help="A JS file (repeatable).")
    ap.add_argument("-d", "--dir", help="Directory of JS files (recursive *.js).")
    ap.add_argument("--url-list", help="File of JS URLs, one per line ('-' = stdin).")
    ap.add_argument("--domain", default="", help="Target domain (for offline endpoint attribution).")
    ap.add_argument("--sweep", default="3,4,5,6,7,8",
                    help="Comma-separated DEEP thresholds to compare (default 3..8).")
    args = ap.parse_args()

    items = _load(args)
    if not items:
        print("No inputs. Provide --file / --dir / --url-list.", file=sys.stderr)
        raise SystemExit(1)

    rows = []
    for name, content in items:
        sc = score_content(content)
        sliced = slice_content(content, sc.hot_lines)
        off = build_offline(content, args.domain)
        n_sec, n_ep = len(off["secrets"]), len(off["endpoints"])
        rows.append((name, len(content), sc.score, dict(sc.signals), len(sliced), n_sec, n_ep))

    print(f"\nScored {len(rows)} file(s) — deterministic only, no LLM calls.")
    print(f"(current env thresholds: CHEAP<{_CHEAP_THRESHOLD}=skip, DEEP>={_DEEP_THRESHOLD})\n")
    print(f"{'FILE':38} {'SIZE':>8} {'SCORE':>6} {'->LLM':>8} {'SEC':>4} {'EP':>4}  SIGNALS")
    print("-" * 100)
    for name, size, score, sig, sent, n_sec, n_ep in sorted(rows, key=lambda r: -r[2]):
        short = name if len(name) <= 36 else "..." + name[-33:]
        print(f"{short:38} {size:>8} {score:>6} {sent:>8} {n_sec:>4} {n_ep:>4}  {sig}")

    print("\nThreshold sweep — skip/cheap/deep split and est. tokens sent to the LLM:")
    print(f"{'DEEP>=':>7} {'skip':>5} {'cheap':>6} {'deep':>5} {'KB->LLM':>9} {'~ktokens':>9}")
    print("-" * 48)
    for th in (int(x) for x in args.sweep.split(",")):
        skip = cheap = deep = sent = 0
        for _n, _size, score, _sig, slen, _s, _e in rows:
            if score < _CHEAP_THRESHOLD:
                skip += 1
            elif score >= th:
                deep += 1
                sent += slen
            else:
                cheap += 1
                sent += slen
        print(f"{th:>7} {skip:>5} {cheap:>6} {deep:>5} {sent / 1024:>9.1f} {sent / 4 / 1000:>9.1f}")

    whole = sum(r[1] for r in rows)
    print(f"\nBaseline if every file went WHOLE to the LLM: "
          f"{whole / 1024:.1f} KB / ~{whole / 4 / 1000:.1f}k input tokens.")
    print("Pick the DEEP threshold where 'deep' still covers the files that carry real\n"
          "signals (SEC/EP columns above) while pushing vendor noise into skip/cheap.")


if __name__ == "__main__":
    main()
