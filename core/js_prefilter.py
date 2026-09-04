"""
BountyHub — core.js_prefilter
The "Purifier": content-level triage that decides, for each LIVE JavaScript
file, whether it is worth an LLM call at all — and if so, with which model and
how much of it.

Where it sits in the pipeline
-----------------------------
    recon  ->  js_files.json
        ->  core.js_oracle._select_urls          (URL-level: CDN drop, vendor dedup)
        ->  core.js_oracle._partition_by_liveness (keep only files still served)
        ->  ★ core.js_prefilter.build_plan        (THIS module — content-level)
        ->  js-oracle CLI (Claude)                (only the winners, only the hot parts)

Why it exists
-------------
The liveness gate answers "does this file still exist?". It does NOT answer
"is this file worth premium-model tokens?". A live 900 KB vendored bundle with
no app-specific endpoints is still beautified, chunked and sent to Opus — pure
waste. This module runs a FREE deterministic pass (the same class of regexes
js-oracle uses in its offline mode) and turns it into three routing decisions:

    skip   score == 0          -> NO LLM call at all; keep the free offline
                                  findings only.
    cheap  0 < score < DEEP    -> send to a cheap model (Haiku / Gemini flash).
    deep   score >= DEEP       -> send to the premium model (Opus).

For large files it also SLICES the content: only the ±window lines around each
signal are sent, plus a compact table of every path-like string literal (so
endpoint recall is preserved even outside the windows). On a big bundle this is
a 10-100x token reduction with little recall loss.

Fail-open contract (load-bearing)
---------------------------------
A fetch failure must NEVER downgrade coverage. If a file cannot be fetched here,
its decision is `deep` with NO slicing and the default model — i.e. the exact
legacy behaviour (js-oracle fetches the URL itself and analyzes it whole). The
pre-filter only ever SAVES tokens on files it positively understood; it never
drops or truncates a file it failed to read. The same applies when the whole
stage is disabled (PREFILTER_ENABLED=0): every file falls through to legacy
`deep` analysis.

Everything here is deterministic and offline (no API key, no cost) EXCEPT the
one HTTP GET per file, which is injectable via the module-level
``_fetch_js_source`` (patched in tests) so the logic stays hermetically testable.

Tuning (all env-overridable, BOUNTYHUB_PREFILTER_* prefix)
----------------------------------------------------------
    PREFILTER_ENABLED         master on/off                       (default on)
    PREFILTER_DEEP_THRESHOLD  score >= this -> premium model       (default 5)
    PREFILTER_CHEAP_THRESHOLD score <  this -> skip (no LLM)        (default 1)
    PREFILTER_DEEP_MODEL      model for deep files ("" = js-oracle default/Opus)
    PREFILTER_CHEAP_MODEL     model for cheap files                (default claude-haiku-4-5)
    PREFILTER_SLICE_ENABLED   allow content slicing                (default on)
    PREFILTER_SLICE_MIN_CHARS only slice files bigger than this    (default 80000)
    PREFILTER_WINDOW_LINES    context lines kept around each hit    (default 40)
    PREFILTER_MAX_FETCH_BYTES hard read cap per file                (default 3000000)
    PREFILTER_FETCH_TIMEOUT   per-file GET timeout (seconds)        (default 10)
"""

import hashlib
import os
import re
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlparse

__all__ = ["Decision", "build_plan", "score_content", "slice_content",
           "build_offline", "PREFILTER_ENABLED"]


# ── env helpers (kept local so the module is standalone / unit-testable) ───────

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    return raw if raw is not None and raw.strip() != "" else default


# ── tunables ───────────────────────────────────────────────────────────────────

PREFILTER_ENABLED     = _env_bool("BOUNTYHUB_PREFILTER_ENABLED", True)
_DEEP_THRESHOLD       = _env_int("BOUNTYHUB_PREFILTER_DEEP_THRESHOLD", 5)
_CHEAP_THRESHOLD      = _env_int("BOUNTYHUB_PREFILTER_CHEAP_THRESHOLD", 1)
# Model per tier. Tier-specific env wins; else a global ANTHROPIC_MODEL (one knob
# flips every tier to e.g. claude-haiku-4-5); else the built-in default. "" for
# deep means "let js-oracle use its own default (Opus)".
_ANTHROPIC_MODEL      = os.environ.get("ANTHROPIC_MODEL", "").strip()
_DEEP_MODEL           = _env_str("BOUNTYHUB_PREFILTER_DEEP_MODEL", "") or _ANTHROPIC_MODEL
_CHEAP_MODEL          = _env_str("BOUNTYHUB_PREFILTER_CHEAP_MODEL", "") or _ANTHROPIC_MODEL or "claude-haiku-4-5"
_SLICE_ENABLED        = _env_bool("BOUNTYHUB_PREFILTER_SLICE_ENABLED", True)
_SLICE_MIN_CHARS      = _env_int("BOUNTYHUB_PREFILTER_SLICE_MIN_CHARS", 80_000)
_WINDOW_LINES         = _env_int("BOUNTYHUB_PREFILTER_WINDOW_LINES", 40)
_MAX_FETCH_BYTES      = _env_int("BOUNTYHUB_PREFILTER_MAX_FETCH_BYTES", 3_000_000)
_FETCH_TIMEOUT        = _env_int("BOUNTYHUB_PREFILTER_FETCH_TIMEOUT", 10)

# If, after building windows, they already cover this fraction of the file, the
# slice is not worth it — send the whole file (avoids a recall risk for no gain).
_SLICE_COVERAGE_CEILING = 0.70

_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


# ── signal patterns (mirror js-oracle/core/patterns.py; kept local on purpose so
#    scan-engine does not import across the js-oracle package boundary) ──────────

# High-confidence secret formats. A single hit is worth a deep look on its own.
# Every pattern is prefix/format-anchored to keep the false-positive rate near
# zero; kept in sync with js-oracle/core/patterns.py::_SECRET_PATTERNS.
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_key", re.compile(r"A(?:KIA|SIA)[0-9A-Z]{16}")),                         # AWS access key id
    ("api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),                           # Google API key
    ("token",   re.compile(r"gh[pousr]_[0-9A-Za-z]{36,255}")),                    # GitHub token
    ("token",   re.compile(r"glpat-[0-9A-Za-z_\-]{20}")),                         # GitLab PAT
    ("token",   re.compile(r"npm_[0-9A-Za-z]{36}")),                              # npm token
    ("token",   re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),                   # Slack token
    ("token",   re.compile(r"https://hooks\.slack\.com/services/"
                           r"T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+")),               # Slack webhook
    ("token",   re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),                         # Stripe secret key
    ("token",   re.compile(r"rk_live_[0-9a-zA-Z]{24,}")),                         # Stripe restricted key
    ("api_key", re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}")),       # SendGrid
    ("api_key", re.compile(r"SK[0-9a-fA-F]{32}")),                                # Twilio API key SID
    ("token",   re.compile(r"ya29\.[0-9A-Za-z\-_]{20,}")),                        # Google OAuth token
    ("jwt",     re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("other",   re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
]
_INTERNAL_IP_RE = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}"
    r"|192\.168(?:\.\d{1,3}){2}"
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
)

# App-relative endpoints — quoted paths that begin with an API-ish segment.
_REL_PATH_RE = re.compile(
    r"""['"](/(?:api|v\d+|graphql|gql|rest|auth|oauth|admin|internal|users?|accounts?|"""
    r"""session|token|login|logout|signup|register|payments?|webhooks?|upload|download|"""
    r"""profile|settings|search|orders?|invoices?|reports?)"""
    r"""[A-Za-z0-9_\-/.{}:]*)['"]"""
)
_FULL_URL_RE = re.compile(r"https?://[^\s\"'`<>()\[\]{}]{4,}")

# Auth handling — token storage / transmission.
_AUTH_RE = re.compile(
    r"(?:Authorization|Bearer\s|x-api-key|localStorage\.setItem|sessionStorage\.setItem|"
    r"document\.cookie|setToken|refresh[_-]?token|access[_-]?token|Set-Cookie)",
    re.IGNORECASE,
)
# Dangerous DOM / execution sinks.
_SINK_RE = re.compile(
    r"(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function\(|"
    r"setTimeout\(\s*['\"]|setInterval\(\s*['\"]|postMessage|dangerouslySetInnerHTML|"
    r"createContextualFragment)",
    re.IGNORECASE,
)
# Dynamic request construction — a hint that endpoints are built at runtime.
_DYNAMIC_RE = re.compile(
    r"(?:fetch\(|XMLHttpRequest|\.ajax\(|axios\.(?:get|post|put|delete|patch|request)\(|"
    r"\.open\(\s*['\"](?:GET|POST|PUT|DELETE|PATCH))",
    re.IGNORECASE,
)
# Source maps — free bonus intel (leak original source).
_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", re.IGNORECASE)

# Path-like string literals, for the compact recall-preserving table appended to
# every sliced file.
_STRING_PATH_RE = re.compile(
    r"""['"`](/[A-Za-z0-9_\-./{}:?=&%]{2,}|https?://[^\s'"`]+)['"`]"""
)

# (label, weight, patterns). Weights are additive per match; secrets dominate.
_SIGNAL_GROUPS: list[tuple[str, int, list[re.Pattern]]] = [
    ("secret",   5, [rx for _, rx in _SECRET_PATTERNS] + [_INTERNAL_IP_RE]),
    ("endpoint", 3, [_REL_PATH_RE]),
    ("auth",     2, [_AUTH_RE]),
    ("sink",     2, [_SINK_RE]),
    ("dynamic",  1, [_DYNAMIC_RE]),
]


# ── data structures ────────────────────────────────────────────────────────────

@dataclass
class Decision:
    """The pre-filter's verdict for a single JS URL.

    route        "skip" | "cheap" | "deep".
    score        Total deterministic signal score.
    model        Model override for the LLM call, or "" / None to use the
                 js-oracle default. Ignored when route == "skip".
    llm_content  The exact content to hand the LLM (full or sliced). None means
                 "no local content" — either a skip (no LLM) or a fail-open deep
                 where js-oracle should fetch the URL itself.
    offline      Free deterministic findings on the FULL content, in js-oracle's
                 result schema. Always merged, even for skipped files, so a
                 secret sliced out of the LLM window is still reported.
    signals      Per-group hit counts, for operator-facing logging.
    """
    url: str
    route: str
    score: int = 0
    model: str | None = None
    llm_content: str | None = None
    offline: dict | None = None
    signals: dict = field(default_factory=dict)


@dataclass
class _ScoreResult:
    score: int
    signals: dict
    hot_lines: set          # 0-based line indices near a signal match


# ── event helper (local; avoids an import cycle with core.js_oracle) ───────────

def _ev(level: str, msg: str) -> dict:
    return {"level": level, "msg": msg}


# ── scoring ────────────────────────────────────────────────────────────────────

def _line_starts(content: str) -> list[int]:
    """Byte-offset of the start of each line, for fast offset->line lookup."""
    starts = [0]
    idx = content.find("\n")
    while idx != -1:
        starts.append(idx + 1)
        idx = content.find("\n", idx + 1)
    return starts


def _line_of(pos: int, starts: list[int]) -> int:
    """0-based line index containing byte offset ``pos`` (binary search)."""
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= pos:
            lo = mid
        else:
            hi = mid - 1
    return lo


def score_content(content: str, window_lines: int = _WINDOW_LINES) -> _ScoreResult:
    """Run every signal group over ``content`` and return score + hot lines.

    The hot-line set is the union of ``±window_lines`` around each match; it is
    what :func:`slice_content` later extracts. Cheap and deterministic.
    """
    if not content:
        return _ScoreResult(0, {}, set())

    starts = _line_starts(content)
    total_lines = len(starts)
    score = 0
    signals: dict = {}
    hot: set = set()

    for label, weight, patterns in _SIGNAL_GROUPS:
        hits = 0
        for rx in patterns:
            for m in rx.finditer(content):
                hits += 1
                ln = _line_of(m.start(), starts)
                lo = max(0, ln - window_lines)
                hi = min(total_lines, ln + window_lines + 1)
                hot.update(range(lo, hi))
        if hits:
            signals[label] = hits
            score += weight * hits

    return _ScoreResult(score, signals, hot)


# ── slicing ────────────────────────────────────────────────────────────────────

def _merge_ranges(indices: set) -> list[tuple[int, int]]:
    """Collapse a set of line indices into sorted, contiguous (start, end) runs."""
    if not indices:
        return []
    ordered = sorted(indices)
    ranges: list[tuple[int, int]] = []
    run_start = prev = ordered[0]
    for i in ordered[1:]:
        if i == prev + 1:
            prev = i
            continue
        ranges.append((run_start, prev))
        run_start = prev = i
    ranges.append((run_start, prev))
    return ranges


def _path_table(content: str, limit: int = 400) -> list[str]:
    """Every distinct path-like string literal, deduped and capped.

    Appended to a sliced file so endpoint recall survives even for endpoints
    whose surrounding code never triggered a signal window.
    """
    seen: list[str] = []
    got: set = set()
    for m in _STRING_PATH_RE.finditer(content):
        val = m.group(1)
        if val not in got:
            got.add(val)
            seen.append(val)
            if len(seen) >= limit:
                break
    return seen


def slice_content(
    content: str,
    hot_lines: set,
    *,
    slice_enabled: bool = _SLICE_ENABLED,
    slice_min_chars: int = _SLICE_MIN_CHARS,
) -> str:
    """Return the content to send to the LLM: whole file, or hot windows only.

    Slicing is applied ONLY when it is both allowed and worthwhile:
      * the file is larger than ``slice_min_chars`` (small files: no benefit,
        and slicing them only risks recall), and
      * the hot windows cover less than ``_SLICE_COVERAGE_CEILING`` of the file.

    When sliced, the output is the concatenation of each hot window (with a line
    marker) followed by a table of every path-like string literal in the FULL
    file — so endpoints outside the windows are still visible to the model.
    """
    if not slice_enabled or len(content) < slice_min_chars or not hot_lines:
        return content

    lines = content.split("\n")
    total = len(lines)
    ranges = _merge_ranges({i for i in hot_lines if 0 <= i < total})
    covered = sum(end - start + 1 for start, end in ranges)
    if not ranges or covered >= total * _SLICE_COVERAGE_CEILING:
        return content  # not worth slicing — send whole

    parts: list[str] = [
        "// [prefilter] Sliced by BountyHub js_prefilter — hot regions only.",
        f"// [prefilter] {covered}/{total} lines kept across {len(ranges)} window(s).",
    ]
    for start, end in ranges:
        parts.append(f"\n// --- lines {start + 1}-{end + 1} ---")
        parts.extend(lines[start:end + 1])

    paths = _path_table(content)
    if paths:
        parts.append("\n// [prefilter] All path-like string literals in the full file:")
        parts.extend(f"// {p}" for p in paths)

    return "\n".join(parts)


# ── offline findings (free intel, js-oracle result schema) ─────────────────────

_EMPTY_RESULT = {
    "analysis_summary": {"total_findings": 0, "highest_severity": "none"},
    "endpoints": [],
    "secrets": [],
    "auth_logic": [],
    "suspicious_logic": [],
}


def _mask(value: str) -> str:
    v = value.strip()
    return (v[:8] + "***") if len(v) > 8 else (v[:2] + "***")


def build_offline(content: str, target: str = "") -> dict:
    """Deterministic findings on the FULL content, in js-oracle's result schema.

    Included regardless of routing so that skipped files still contribute their
    secrets / source-map leaks, and so a secret that a slice happened to drop is
    never lost. Endpoints are restricted to app-relative paths and same-target
    absolute URLs to keep third-party noise out of the merged output.
    """
    text = content or ""
    target_host = ""
    if target:
        try:
            target_host = (urlparse(target if "//" in target else f"https://{target}")
                           .hostname or target).lower()
        except Exception:
            target_host = target.lower()

    # secrets
    secrets: list[dict] = []
    seen_sec: set = set()

    def _add_secret(stype: str, value: str) -> None:
        key = (stype, value)
        if key in seen_sec:
            return
        seen_sec.add(key)
        secrets.append({"type": stype, "value_preview": _mask(value), "evidence": value[:120]})

    for stype, rx in _SECRET_PATTERNS:
        for m in rx.finditer(text):
            _add_secret(stype, m.group(0))
    for m in _INTERNAL_IP_RE.finditer(text):
        _add_secret("internal_ip", m.group(0))

    # endpoints (app-relative always; absolute only when same target host)
    endpoints: list[dict] = []
    seen_ep: set = set()

    def _add_ep(path: str, evidence: str) -> None:
        if path in seen_ep:
            return
        seen_ep.add(path)
        endpoints.append({
            "path": path, "method": "UNKNOWN", "parameters": [],
            "body_structure": None, "evidence": evidence[:120], "confidence": "low",
        })

    for m in _REL_PATH_RE.finditer(text):
        _add_ep(m.group(1), m.group(0))
    if target_host:
        for m in _FULL_URL_RE.finditer(text):
            url = m.group(0).rstrip("\\\",;)")
            try:
                host = (urlparse(url).hostname or "").lower()
            except Exception:
                continue
            if host and (host == target_host or host.endswith("." + target_host)):
                _add_ep(url, url)

    # source maps -> suspicious/info
    suspicious = []
    seen_map: set = set()
    for m in _SOURCEMAP_RE.finditer(text):
        url = m.group(1).strip().strip("\"'")
        if url and url not in seen_map:
            seen_map.add(url)
            suspicious.append({
                "description": f"Source map referenced ({url}) — may expose original source",
                "severity": "info",
                "evidence": (f"//# sourceMappingURL={url}")[:120],
            })

    return {
        **_EMPTY_RESULT,
        "endpoints": endpoints,
        "secrets": secrets,
        "suspicious_logic": suspicious,
    }


def _has_findings(offline: dict) -> bool:
    return bool(offline and (offline["endpoints"] or offline["secrets"]
                             or offline["suspicious_logic"]))


# ── fetch (injectable seam — patched in tests) ─────────────────────────────────

def _fetch_js_source(url: str) -> str | None:
    """GET ``url`` and return decoded text, or None on any failure.

    Bounded by a read cap and a timeout. Returning None triggers the fail-open
    path in :func:`build_plan` (the file is analyzed whole via js-oracle, exactly
    as before this module existed), so a flaky fetch can only ever cost tokens,
    never coverage.
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
        with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
            raw = resp.read(_MAX_FETCH_BYTES)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


# ── plan builder ───────────────────────────────────────────────────────────────

def build_plan(urls: list[str], target: str, events: list | None = None,
               fetch=None) -> dict[str, Decision]:
    """Score, route and (optionally) slice each URL; return {url: Decision}.

    ``events`` (if given) collects operator-facing event dicts in the same shape
    core modules use. ``fetch`` overrides the HTTP getter (tests inject a stub);
    it defaults to the module-level ``_fetch_js_source`` looked up at call time,
    so patching that global works.
    """
    plan: dict[str, Decision] = {}
    if events is None:
        events = []

    # Master kill-switch: fall through to legacy `deep` for everything.
    if not PREFILTER_ENABLED:
        for url in urls:
            plan[url] = Decision(url=url, route="deep")
        events.append(_ev("info", "JS pre-filter disabled (BOUNTYHUB_PREFILTER_ENABLED=0) "
                                  "— every live file analyzed whole."))
        return plan

    getter = fetch or _fetch_js_source
    n_skip = n_cheap = n_deep = n_failopen = 0
    chars_saved = 0                       # bytes NOT sent to the LLM vs. whole-file
    seen_hashes: set = set()

    for url in urls:
        content = getter(url)

        # Fail-open: a file we could not read is analyzed whole, default model.
        if content is None:
            plan[url] = Decision(url=url, route="deep")
            n_failopen += 1
            continue

        # Exact full-content dedup (liveness only hashed the first 64 KB).
        h = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
        if h in seen_hashes:
            plan[url] = Decision(
                url=url, route="skip", score=0,
                offline=None,
                signals={"duplicate": 1},
            )
            n_skip += 1
            chars_saved += len(content)
            events.append(_ev("info", f"JS pre-filter: {url} — identical to an "
                                      f"already-scored file, skipped (no LLM)."))
            continue
        seen_hashes.add(h)

        scored = score_content(content)
        offline = build_offline(content, target)
        offline_dict = offline if _has_findings(offline) else None

        if scored.score < _CHEAP_THRESHOLD:
            plan[url] = Decision(url=url, route="skip", score=scored.score,
                                 offline=offline_dict, signals=scored.signals)
            n_skip += 1
            chars_saved += len(content)
            events.append(_ev("info",
                f"JS pre-filter: {url} — score {scored.score} (no app signals) "
                f"-> SKIP LLM, offline-only."))
            continue

        llm_content = slice_content(content, scored.hot_lines)
        sliced = llm_content is not content and len(llm_content) < len(content)
        if sliced:
            chars_saved += len(content) - len(llm_content)

        if scored.score >= _DEEP_THRESHOLD:
            route, model, n = "deep", (_DEEP_MODEL or None), "deep"
            n_deep += 1
        else:
            route, model, n = "cheap", (_CHEAP_MODEL or None), "cheap"
            n_cheap += 1

        plan[url] = Decision(url=url, route=route, score=scored.score, model=model,
                             llm_content=llm_content, offline=offline_dict,
                             signals=scored.signals)
        events.append(_ev("info",
            f"JS pre-filter: {url} — score {scored.score} {dict(scored.signals)} "
            f"-> {route.upper()}"
            + (f" ({model})" if model else "")
            + (f", sliced {len(content)}->{len(llm_content)} chars" if sliced else "")))

    events.append(_ev("success",
        f"JS pre-filter: {len(urls)} live file(s) triaged — "
        f"{n_deep} deep, {n_cheap} cheap, {n_skip} skipped"
        + (f", {n_failopen} fail-open (unreadable, analyzed whole)" if n_failopen else "")
        + f" — ~{chars_saved // 4:,} est. input token(s) saved vs. analyzing "
          f"every file whole."))
    return plan
