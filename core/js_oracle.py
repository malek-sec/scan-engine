"""
BountyHub v3 — core.js_oracle
Module 4: JavaScript Analysis via JS-Oracle (Claude-powered)

Calls the JS-Oracle CLI in a subprocess using its dedicated venv, reads the
structured JSON output, and returns merged findings for Module 3 (AI advisor).

CDN filtering and a hard file cap keep API costs predictable:
  • Same-domain JS files are prioritised
  • Known CDN / analytics domains are skipped automatically
  • At most _MAX_JS_FILES files are submitted per scan
  • Hard wall-clock budget: _TOTAL_TIMEOUT seconds total

Public API
----------
JSOracle(output_dir).execute(target, js_urls) → dict:
{
    "status"            : "ok" | "partial" | "skipped" | "error",
    "events"            : [{"level": str, "msg": str}, ...],
    "endpoints"         : [...],
    "api_keys"          : [...],
    "auth_issues"       : [...],
    "sinks"             : [...],
    "business_logic"    : [...],
    "raw_findings_count": int,
    "highest_severity"  : str,
    "js_files_analyzed" : int,   # live files actually analyzed
    "js_live_count"     : int,   # files verified as still served
    "archived_endpoints": [ {url, status, content_type, reason}, ... ],
                                 # url is verbatim from the archive — see
                                 # "URL fidelity" below
    "archived_count"    : int,   # discovered but no longer served
}

Liveness gating
---------------
Historical URLs (Wayback/crt.sh) frequently point at assets deleted years ago.
Every candidate is probed against the CURRENT host and only files answering
2xx with a JavaScript content-type are analyzed. Dead ones are parked in
"archived_endpoints" (and js_archived_endpoints.json) — preserved as intel for
manual review, never fed to automated analysis as if they were live.

URL fidelity — archived URLs are kept AS-IS (deliberate)
--------------------------------------------------------
Archived candidates are probed and recorded exactly as the archive recorded
them: original scheme (often http://), original host (often a retired
www./legacy subdomain), original path and casing. They are NOT rewritten onto
the current canonical host before probing, and NOT normalised before being
written to the archived bucket.

This is a deliberate design decision, not an oversight:

  * The bucket's purpose is a faithful record of what the archive says once
    existed at a specific URL. Rewriting it would destroy the evidence — the
    host and scheme ARE part of the finding, and "this used to live on
    www.example.com over plain http" is often the interesting part.
  * Probing as-is answers "is this exact archived URL still served?", which is
    the question the liveness gate exists to answer. Rewriting would answer a
    different question ("does this PATH exist on today's canonical host?") and
    would silently promote a URL the archive never actually recorded.
  * Redirects are still followed by urllib, so a legacy host that now 301s to
    the canonical one is naturally resolved without us guessing.

If you ever want the other question answered — replaying archived PATHS
against the current host to hunt forgotten endpoints — add it as a SEPARATE
pass with its own bucket. Do not fold it into this one: the two produce
different evidence and conflating them makes both untrustworthy.
"""

import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

# The pre-filter ("purifier") — content-level triage that runs between liveness
# and the LLM call, so Opus tokens are spent only on files (and only the regions
# of files) that a free deterministic pass shows are worth it.
from core.js_prefilter import build_plan


# ── Paths ─────────────────────────────────────────────────────────────────────
# The JS-Oracle install is resolved, not hardcoded. Priority:
#   1. $JS_ORACLE_ROOT (or $BOUNTYHUB_JS_ORACLE_ROOT) — explicit operator override.
#   2. The sibling js-oracle/ next to this scan-engine checkout.
# The sibling default works both on the canonical Kali box (/home/kali/scan-engine
# + /home/kali/js-oracle) and on any mirror (…/Bug-Bounty/scan-engine + …/js-oracle),
# so Module 4 is no longer pinned to one machine's absolute path.

def _resolve_oracle_root() -> Path:
    override = (os.environ.get("JS_ORACLE_ROOT")
                or os.environ.get("BOUNTYHUB_JS_ORACLE_ROOT"))
    if override and override.strip():
        return Path(override.strip())
    # …/scan-engine/core/js_oracle.py -> parents[2] is the workspace root.
    return Path(__file__).resolve().parents[2] / "js-oracle"


def _resolve_oracle_python(root: Path) -> Path:
    # POSIX venvs put the interpreter in bin/, Windows venvs in Scripts/.
    leaf = "Scripts/python.exe" if os.name == "nt" else "bin/python"
    return root / ".venv" / leaf


_JS_ORACLE_ROOT   = _resolve_oracle_root()
_JS_ORACLE_PYTHON = _resolve_oracle_python(_JS_ORACLE_ROOT)
_JS_ORACLE_MAIN   = _JS_ORACLE_ROOT / "main.py"

# ── Analysis backend ────────────────────────────────────────────────────────
# How this bridge reaches js-oracle:
#   "subprocess" (default): spawn the js-oracle CLI once per file — zero setup,
#                           but pays interpreter + client init on every file.
#   "http":                 POST each file to a long-running js-oracle FastAPI
#                           service (js-oracle/service.py), so the AI layer can
#                           be scaled/replicated independently and no js-oracle
#                           venv is needed on this host.
# The default is unchanged behaviour; opt into HTTP with JS_ORACLE_MODE=http.
_JS_ORACLE_MODE = (os.environ.get("JS_ORACLE_MODE", "subprocess").strip().lower()
                   or "subprocess")
_JS_ORACLE_URL  = os.environ.get("JS_ORACLE_URL", "http://127.0.0.1:8787").strip()

# ── Limits ────────────────────────────────────────────────────────────────────

_MAX_JS_FILES     = 8     # maximum number of JS files to ANALYZE per scan
_TOTAL_TIMEOUT    = 280   # 4m40s wall-clock budget — leaves 20s headroom before 5m cap
_PER_FILE_TIMEOUT = 90    # per-file subprocess hard timeout (seconds)

# Liveness verification (runs BEFORE the analysis cap is applied, so dead
# archived files can never consume the analysis budget).
_MAX_LIVENESS_CANDIDATES = 120  # how many URLs to probe before picking winners
_MAX_VENDOR_COPIES       = 2    # probed copies kept per vendored library family
_LIVENESS_TIMEOUT        = 8    # per-probe connect+read timeout (seconds)
_LIVENESS_WORKERS        = 16   # concurrent probes
_LIVENESS_BUDGET         = 120  # overall wall-clock ceiling for all probes
_LIVENESS_READ_BYTES     = 65536  # bytes read on GET, for content hashing

_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# A file only counts as live if the server returns 2xx AND declares it as
# JavaScript. Both halves are load-bearing: single-page apps commonly answer
# ANY unmatched path with "200 text/html" (their index.html fallback), so a
# status-only check happily marks a long-deleted /ext/jquery/jquery-1.4.2.min.js
# as live and burns the analysis budget parsing an HTML page.
_JS_CONTENT_TYPE_RE = re.compile(
    r"^\s*(?:application|text)/(?:x-)?(?:java|ecma)script\b", re.IGNORECASE)

# Vendored third-party libraries. One copy is plenty — the analysis budget
# belongs to app-specific code, not the Nth minified jQuery.
_VENDOR_LIBS = frozenset({
    "jquery", "jquery-ui", "jqueryui", "bootstrap", "angular", "react",
    "react-dom", "vue", "lodash", "underscore", "moment", "d3", "backbone",
    "ember", "prototype", "mootools", "modernizr", "popper", "axios",
    "polyfill", "swiper", "slick", "fancybox", "cufon", "yui", "dojo",
    "handlebars", "knockout", "requirejs", "zepto", "normalize", "select2",
    "datatables", "highcharts", "chart", "tslib", "core-js", "regenerator",
})

# Broader "is this a self-hosted vendor library?" test, used for RANKING so the
# analysis budget goes to APP-SPECIFIC code. The exact set above only collapses
# duplicate copies; it misses libraries whose filename embeds a compound name or
# version the set never lists (greensock/gsap, owl-carousel, easing, fSelect,
# TimelineMax, ScrollToPlugin, aos, swiper, …). Matched on filename word
# boundaries to keep false positives on custom code low; a false positive only
# de-prioritises a file, it never drops it.
_VENDOR_LIB_RE = re.compile(
    r"(?:^|[/_.\-])(?:"
    r"jquery|bootstrap|popper|angular|react|vue|lodash|underscore|moment|backbone|"
    r"ember|prototype|mootools|modernizr|axios|zepto|"
    r"gsap|greensock|tweenmax|tweenlite|timelinemax|scrolltoplugin|scrollmagic|"
    r"owl[.\-]?carousel|slick|swiper|select2|selectwoo|fselect|"
    r"aos|wow|parallax|isotope|masonry|imagesloaded|waypoints|headroom|lazysizes|"
    r"hammer|velocity|anime|splide|flickity|glide|magnific|fancybox|lightbox|easing|"
    r"highcharts|chartjs|datatables|handlebars|mustache|knockout|requirejs|normalize|"
    r"polyfill|regenerator|core[.\-]?js|tslib|zxcvbn|hoverintent|clipboard|"
    r"fontawesome|font[.\-]?awesome|cufon|yui|dojo"
    r")(?:[.\-]|\d|$)",
    re.IGNORECASE,
)

# Build hashes / version suffixes to strip when deriving a library family:
#   jquery-1.4.2.min.js        -> jquery
#   jquery-ui-1.8.22.min.js    -> jquery-ui
#   index-CGupvGYo.js          -> index
_VERSION_SUFFIX_RE = re.compile(
    r"[-._]v?\d+(?:[._]\d+)*(?:[-._][A-Za-z0-9]+)?$")
# Only a HYPHEN-separated suffix is treated as a build hash (Vite/webpack emit
# "index-CGupvGYo.js"). A dot-separated suffix is a plugin name, not a hash —
# stripping those collapsed jquery.bxGallery / jquery.corner / jquery.fancybox
# all onto the "jquery" family and evicted real jQuery from the copy quota.
_HASH_SUFFIX_RE    = re.compile(r"-[A-Za-z0-9_-]{6,12}$")

# ── Classification helpers ────────────────────────────────────────────────────

_SINK_KEYWORDS = frozenset({
    "innerhtml", "outerhtml", "insertadjacenthtml",
    "document.write", "eval(", "settimeout(", "setinterval(",
    "execscript", "new function(", "createcontextualfragment",
})

_CDN_HOSTNAMES = frozenset({
    "googleapis.com", "gstatic.com", "cloudflare.com", "fastly.net",
    "akamaized.net", "bootstrapcdn.com", "cloudfront.net", "jsdelivr.net",
    "unpkg.com", "cdnjs.cloudflare.com", "jquery.com",
    "bunnycdn.com", "twimg.com", "facebook.net", "doubleclick.net",
    "analytics.google.com", "hotjar.com", "intercomcdn.com",
})

_SEVERITY_RANK = {
    "critical": 5, "high": 4, "medium": 3,
    "low": 2, "info": 1, "none": 0,
}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _ev(level: str, msg: str) -> dict:
    return {"level": level, "msg": msg}


def _http_post_json(url: str, payload: dict, timeout: float) -> dict:
    """POST ``payload`` as JSON to ``url`` and return the decoded JSON response.

    Uses only urllib (no new dependency for the engine). Raises on transport or
    decode errors; the caller turns that into a logged warning + graceful skip.
    """
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _http_get_ok(url: str, timeout: float = 5.0) -> bool:
    """True when a GET to ``url`` answers 2xx — used for the service health probe."""
    try:
        with urllib.request.urlopen(
                urllib.request.Request(url, method="GET"), timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def _is_cdn(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return any(cdn in host for cdn in _CDN_HOSTNAMES)
    except Exception:
        return False


def _lib_family(url: str) -> tuple:
    """
    Derive a (family, is_vendor) key used to collapse duplicate copies of the
    same library.

    "https://x/ext/jquery/jquery-1.4.2.min.js" -> ("jquery", True)
    "https://x/assets/index-CGupvGYo.js"       -> ("index",  False)
    """
    try:
        name = (urlparse(url).path or "").rsplit("/", 1)[-1]
    except Exception:
        return (url, False)

    _MARKERS = (".min", ".pack", ".slim", ".bundle", ".prod", ".production",
                ".es6", ".es5", ".esm", ".umd", ".cjs", ".mjs", ".module")

    def _strip_markers(text: str) -> str:
        changed = True
        while changed:
            changed = False
            for marker in _MARKERS:
                if text.lower().endswith(marker):
                    text = text[: -len(marker)]
                    changed = True
        return text

    stem = name[:-3] if name.lower().endswith(".js") else name
    # Strip markers, then version/hash, then markers again: a build hash can
    # sit *after* the module-format suffix ("tslib.es6-NPRqQeXK.js"), so one
    # pass alone leaves "tslib.es6" and misses the vendored library.
    stem = _strip_markers(stem)
    stem = _VERSION_SUFFIX_RE.sub("", stem)
    stem = _HASH_SUFFIX_RE.sub("", stem)
    stem = _strip_markers(stem)
    family = (stem or name).lower().strip("-._") or name.lower()

    base = family.replace("_", "-")
    # Vendor if the exact family is a known lib OR the filename matches the
    # broader self-hosted-library regex (greensock, owl-carousel, easing, fSelect…).
    is_vendor = base in _VENDOR_LIBS or bool(_VENDOR_LIB_RE.search(name.lower()))
    return (family, is_vendor)


def _probe_liveness(url: str) -> dict:
    """
    Ask the CURRENT host whether it still serves this URL as JavaScript.

    HEAD first (cheap); fall back to GET when HEAD is unsupported, blocked, or
    answers without a usable content-type — some servers only get the header
    right on a real GET.

    A file is live only when the response is 2xx AND the content-type declares
    JavaScript. Returns a record that is kept whether the probe passes or not,
    so dead archived URLs stay available as intel instead of being discarded.

    `url` is probed VERBATIM — original scheme, host, path and casing. Do not
    "helpfully" rewrite archived URLs onto the current canonical host here:
    that changes the question being asked (see "URL fidelity" in the module
    docstring) and corrupts the archived bucket's value as evidence. Redirects
    are followed, so a legacy host that now 301s resolves on its own.
    """
    record = {
        "url": url, "alive": False, "status": None,
        "content_type": "", "method": None, "reason": "", "sha256": None,
    }

    def _finish(status, ctype, method, body=None):
        record["status"], record["method"] = status, method
        record["content_type"] = (ctype or "").strip()
        if body:
            record["sha256"] = hashlib.sha256(body).hexdigest()
        if not isinstance(status, int):
            record["reason"] = f"unreachable ({status})"
        elif not (200 <= status < 300):
            record["reason"] = f"HTTP {status} — no longer served"
        elif not _JS_CONTENT_TYPE_RE.match(record["content_type"]):
            # The classic false positive: an SPA index.html served for a path
            # that was deleted years ago.
            record["reason"] = (
                f"HTTP {status} but content-type is "
                f"'{record['content_type'] or 'unset'}', not JavaScript "
                "(likely an SPA catch-all page, not the original file)")
        else:
            record["alive"] = True
            record["reason"] = f"HTTP {status} {record['content_type']}"
        return record

    def _request(method):
        req = urllib.request.Request(
            url, method=method, headers={"User-Agent": _UA, "Accept": "*/*"})
        with urllib.request.urlopen(req, timeout=_LIVENESS_TIMEOUT) as resp:
            body = (resp.read(_LIVENESS_READ_BYTES) if method == "GET" else None)
            return resp.status, resp.headers.get("Content-Type", ""), body

    try:
        status, ctype, _ = _request("HEAD")
        if 200 <= status < 300 and _JS_CONTENT_TYPE_RE.match(ctype or ""):
            return _finish(status, ctype, "HEAD")
    except urllib.error.HTTPError as exc:
        # 4xx/5xx on HEAD may just mean HEAD is unsupported — retry with GET.
        if exc.code not in (403, 405, 501):
            try:
                status, ctype, body = _request("GET")
                return _finish(status, ctype, "GET", body)
            except urllib.error.HTTPError as gexc:
                return _finish(gexc.code,
                               gexc.headers.get("Content-Type", "") if gexc.headers else "",
                               "GET")
            except Exception as gexc:
                return _finish(type(gexc).__name__, "", "GET")
    except Exception:
        pass  # fall through to GET

    try:
        status, ctype, body = _request("GET")
        return _finish(status, ctype, "GET", body)
    except urllib.error.HTTPError as exc:
        return _finish(exc.code,
                       exc.headers.get("Content-Type", "") if exc.headers else "",
                       "GET")
    except Exception as exc:
        return _finish(type(exc).__name__, "", "GET")


def _is_sink(finding: dict) -> bool:
    text = (
        finding.get("description", "") + " " + finding.get("evidence", "")
    ).lower()
    return any(kw in text for kw in _SINK_KEYWORDS)


def _higher_severity(a: str, b: str) -> str:
    return a if _SEVERITY_RANK.get(a, 0) >= _SEVERITY_RANK.get(b, 0) else b


def _merge_all(file_results: list[dict]) -> dict:
    """
    Deduplicate and merge per-file result dicts from JS-Oracle.

    Deduplication keys:
      endpoints        → (path, method)
      secrets          → (type, value_preview)
      auth_logic       → (mechanism.lower(), storage_location)
      suspicious_logic → evidence snippet (first 60 chars)
    """
    ep_seen:   dict = {}
    sec_seen:  dict = {}
    auth_seen: dict = {}
    susp_seen: dict = {}

    for r in file_results:
        for ep in r.get("endpoints", []):
            key = (ep.get("path", ""), ep.get("method", "UNKNOWN"))
            if key not in ep_seen:
                ep_seen[key] = ep
            else:
                # Keep higher confidence
                curr_rank = _SEVERITY_RANK.get(ep_seen[key].get("confidence", "low"), 0)
                new_rank  = _SEVERITY_RANK.get(ep.get("confidence", "low"), 0)
                if new_rank > curr_rank:
                    ep_seen[key] = ep

        for sec in r.get("secrets", []):
            key = (sec.get("type", ""), sec.get("value_preview", ""))
            if key not in sec_seen:
                sec_seen[key] = sec

        for auth in r.get("auth_logic", []):
            key = (
                auth.get("mechanism", "").lower(),
                auth.get("storage_location", ""),
            )
            if key not in auth_seen:
                auth_seen[key] = auth

        for susp in r.get("suspicious_logic", []):
            key = susp.get("evidence", "")[:60]
            if key not in susp_seen:
                susp_seen[key] = susp
            else:
                # Keep higher severity
                curr = _SEVERITY_RANK.get(susp_seen[key].get("severity", "info"), 0)
                new  = _SEVERITY_RANK.get(susp.get("severity", "info"), 0)
                if new > curr:
                    susp_seen[key] = susp

    return {
        "endpoints":        list(ep_seen.values()),
        "secrets":          list(sec_seen.values()),
        "auth_logic":       list(auth_seen.values()),
        "suspicious_logic": list(susp_seen.values()),
    }


# ── Module ────────────────────────────────────────────────────────────────────

class JSOracle:
    """
    Module 4 — JavaScript Analysis (JS-Oracle wrapper).

    Calls the JS-Oracle CLI process for each candidate JS URL, reads the
    structured JSON reports, merges and classifies findings, then returns
    a single result dict for Module 3 (AIAdvisorModule) to incorporate.
    """

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    # ── Availability check ────────────────────────────────────────────────

    def _check_available(self, events: list) -> bool:
        # HTTP backend: a reachable /health is all we need — no local venv.
        if _JS_ORACLE_MODE == "http":
            if _http_get_ok(f"{_JS_ORACLE_URL.rstrip('/')}/health"):
                return True
            events.append(_ev("warning",
                f"JS-Oracle HTTP service unreachable at {_JS_ORACLE_URL} — Module 4 "
                f"skipped. Start it (cd js-oracle && uvicorn service:app --port 8787), "
                f"or unset JS_ORACLE_MODE to use the subprocess backend."
            ))
            return False
        if not _JS_ORACLE_PYTHON.exists():
            events.append(_ev("warning",
                f"JS-Oracle venv not found at {_JS_ORACLE_PYTHON} — "
                "Module 4 skipped. Install: cd /home/kali/js-oracle && python -m venv .venv && .venv/bin/pip install -r requirements.txt"
            ))
            return False
        if not _JS_ORACLE_MAIN.exists():
            events.append(_ev("warning",
                f"JS-Oracle main.py not found at {_JS_ORACLE_MAIN} — Module 4 skipped"
            ))
            return False
        return True

    # ── URL prioritization ────────────────────────────────────────────────

    def _select_urls(self, target: str, js_urls: list, events: list,
                     limit: int = _MAX_JS_FILES) -> list:
        """
        Filter and rank JS URLs into an analysis candidate list.

        Priority: app-specific same-domain, then vendored same-domain, then
        off-domain. CDN hosts are skipped, and duplicate copies of the same
        vendored library (jquery-1.4.2 / jquery-1.8.0 / ...) collapse to one
        representative so the budget goes to app-specific code.

        `limit` caps the returned list. execute() deliberately passes a LARGE
        limit here and applies the real _MAX_JS_FILES cap only after liveness
        verification — otherwise dead archived files consume the analysis
        budget before anyone checks whether they still exist.
        """
        try:
            target_host = urlparse(f"https://{target}").hostname or target
        except Exception:
            target_host = target

        same_app, same_vendor, other = [], [], []
        vendor_counts: dict = {}
        seen_urls: set = set()
        deduped = 0
        cdn_skipped = 0

        for url in js_urls:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            if _is_cdn(url):
                cdn_skipped += 1
                continue
            try:
                host = urlparse(url).hostname or ""
            except Exception:
                continue

            family, is_vendor = _lib_family(url)

            # Only VENDORED families are collapsed here. App-specific files are
            # deliberately left alone until after the liveness probe: they are
            # build-hashed (Card-Ce6gTZY0.js / Card-DOuMEqSH.js) and only one
            # hash is still served, so collapsing them now lets a dead archived
            # copy shadow the live one — the exact failure this module exists
            # to prevent. A couple of copies per vendor family are still kept
            # so dead vendored files reach the archived bucket rather than
            # vanishing silently.
            if is_vendor:
                n = vendor_counts.get(family, 0)
                if n >= _MAX_VENDOR_COPIES:
                    deduped += 1
                    continue
                vendor_counts[family] = n + 1

            if target_host in host or host in target_host:
                (same_vendor if is_vendor else same_app).append(url)
            else:
                other.append(url)

        # Interleave so vendored files are never starved out by a long tail of
        # app-specific ones: app-specific keep priority, but vendored still get
        # probed and therefore still get bucketed.
        budget = max(limit, 0)
        vendor_quota = min(len(same_vendor), max(4, budget // 5))
        app_quota    = max(budget - vendor_quota, 0)
        ranked = same_app[:app_quota] + same_vendor[:vendor_quota]
        ranked += other[: max(budget - len(ranked), 0)]

        events.append(_ev("info",
            f"JS-Oracle: {len(ranked)} candidate(s) after filtering "
            f"({len(same_app)} app-specific, {len(same_vendor)} vendored, "
            f"{len(other)} off-domain, {cdn_skipped} CDN skipped, "
            f"{deduped} surplus vendored copies collapsed)"
        ))
        return ranked

    # ── Liveness verification ─────────────────────────────────────────────

    def _partition_by_liveness(self, candidates: list, events: list) -> tuple:
        """
        Split candidates into (live, archived) by asking the CURRENT host.

        Historical URLs come from Wayback/crt.sh and routinely point at assets
        deleted years ago. Analyzing those produces zero findings and a false
        sense of coverage, so only files the host still serves as JavaScript
        are analyzed. Dead ones are NOT discarded — they are returned as
        archived records for manual review of forgotten endpoints.

        Probes run concurrently with a hard per-probe timeout.
        """
        if not candidates:
            return [], []

        events.append(_ev("info",
            f"JS liveness — verifying {len(candidates)} candidate(s) are still "
            f"served (concurrent, {_LIVENESS_TIMEOUT}s timeout)"
        ))

        records: list = []
        try:
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=_LIVENESS_WORKERS) as pool:
                futures = {pool.submit(_probe_liveness, u): u for u in candidates}
                for fut in concurrent.futures.as_completed(
                        futures, timeout=_LIVENESS_BUDGET):
                    try:
                        records.append(fut.result())
                    except Exception as exc:
                        records.append({
                            "url": futures[fut], "alive": False, "status": None,
                            "content_type": "", "method": None,
                            "reason": f"probe failed: {exc.__class__.__name__}",
                            "sha256": None,
                        })
        except concurrent.futures.TimeoutError:
            events.append(_ev("warning",
                "JS liveness — overall probe budget exhausted; unprobed files "
                "are parked as archived rather than assumed live"
            ))

        done = {r["url"] for r in records}
        for url in candidates:
            if url not in done:
                records.append({
                    "url": url, "alive": False, "status": None,
                    "content_type": "", "method": None,
                    "reason": "not probed before the liveness budget expired",
                    "sha256": None,
                })

        # Preserve the ranking established by _select_urls.
        order = {u: i for i, u in enumerate(candidates)}
        records.sort(key=lambda r: order.get(r["url"], 1 << 30))

        live     = [r for r in records if r["alive"]]
        archived = [r for r in records if not r["alive"]]

        # Deduplicate only among files confirmed live, so a dead copy can never
        # displace a live one. Collapse by library family first (the Nth build
        # of the same component), then by exact content hash.
        deduped_live, seen_hashes, seen_families = [], set(), set()
        for r in live:
            family, is_vendor = _lib_family(r["url"])
            fam_key = ("vendor", family) if is_vendor else family
            h = r.get("sha256")
            if fam_key in seen_families:
                r["reason"] += f" (duplicate copy of live '{family}')"
                archived.append(r)
                continue
            if h and h in seen_hashes:
                r["reason"] += " (identical content to an already-selected file)"
                archived.append(r)
                continue
            seen_families.add(fam_key)
            if h:
                seen_hashes.add(h)
            deduped_live.append(r)

        events.append(_ev("success" if deduped_live else "warning",
            f"JS liveness — {len(deduped_live)} live, {len(archived)} archived/dead"
        ))
        return deduped_live, archived

    def _persist_archived(self, archived: list, events: list) -> None:
        """
        Park archived-but-dead JS URLs for manual review.

        These are real historical-URL intel — forgotten endpoints, old admin
        panels, retired API paths — and are deliberately kept out of automated
        analysis rather than thrown away.

        The file is written as a self-describing envelope. Someone opening it
        months from now sees a list dominated by 404s and text/html responses;
        without the note that reads like a scanner malfunction rather than the
        intended product. URLs are recorded exactly as the archive had them
        (see "URL fidelity" in the module docstring).
        """
        try:
            out = self.output_dir / "js_archived_endpoints.json"
            out.write_text(json.dumps({
                "_readme": {
                    "what": (
                        "JavaScript URLs discovered from historical sources "
                        "(Wayback/crt.sh) that the CURRENT host no longer "
                        "serves as JavaScript. They were NOT analyzed."
                    ),
                    "why_not_analyzed": (
                        "Analyzing dead files yields 0 findings and inflates "
                        "coverage with files that do not exist any more."
                    ),
                    "why_kept": (
                        "They are intel: forgotten endpoints, retired API "
                        "paths and old admin panels worth manual review."
                    ),
                    "urls_are_verbatim": (
                        "DELIBERATE: each URL is recorded and was probed "
                        "exactly as the archive had it — original scheme "
                        "(often http://), original host (often a retired "
                        "www./legacy subdomain), original path and casing. "
                        "They are intentionally NOT rewritten onto the current "
                        "canonical host, because the host and scheme are part "
                        "of the finding. A 404 or a text/html response here is "
                        "the expected, correct result — not a scanner bug."
                    ),
                    "reason_field": (
                        "'HTTP 404' = path gone. 'HTTP 200 but content-type is "
                        "text/html' = a single-page-app catch-all page served "
                        "for a deleted asset, which is why status alone is not "
                        "used to decide liveness."
                    ),
                },
                "archived_count": len(archived),
                "endpoints":      archived,
            }, indent=2))
            events.append(_ev("info",
                f"JS-Oracle: {len(archived)} archived endpoint(s) parked for "
                f"manual review → js_archived_endpoints.json "
                f"(URLs kept verbatim, not rewritten onto the live host)"
            ))
        except Exception as exc:
            events.append(_ev("warning",
                f"JS-Oracle: could not persist archived endpoints: {exc}"))

    # ── Per-file subprocess call ──────────────────────────────────────────

    def _analyze_url(
        self, url: str, target: str, out_dir: Path, events: list
    ) -> dict | None:
        """Analyze one JS URL, dispatching to the configured backend.

        JS_ORACLE_MODE selects "subprocess" (default — spawn the js-oracle CLI)
        or "http" (POST to a long-running js-oracle service). Both honour the
        pre-filter's per-file overrides (sliced content via a temp file, and the
        routed model).
        """
        override = getattr(self, "_analysis_override", {}).get(url, {})
        if _JS_ORACLE_MODE == "http":
            return self._analyze_via_http(url, target, override, events)
        return self._analyze_via_subprocess(url, target, out_dir, override, events)

    def _analyze_via_http(
        self, url: str, target: str, override: dict, events: list
    ) -> dict | None:
        """POST one file to the js-oracle HTTP service; return its findings dict.

        The pre-filter's sliced content (written to a temp file for the
        subprocess backend) is read back and sent inline as ``content`` so the
        service analyzes exactly what the pre-filter chose; otherwise the raw
        ``url`` is sent for the service to fetch. Never raises — a transport
        error degrades to a logged warning + skip, like the subprocess path.
        """
        payload: dict = {"domain": target}
        note = ""
        if override.get("file"):
            try:
                payload["content"] = Path(override["file"]).read_text(encoding="utf-8")
                note += " [sliced]"
            except OSError:
                payload["url"] = url
        else:
            payload["url"] = url
        if override.get("model"):
            payload["model"] = override["model"]
            note += f" [{override['model']}]"

        events.append(_ev("info", f"JS-Oracle(http) → {url}{note}"))
        try:
            data = _http_post_json(
                f"{_JS_ORACLE_URL.rstrip('/')}/analyze", payload, _PER_FILE_TIMEOUT)
        except Exception as exc:
            events.append(_ev("warning", f"JS-Oracle(http): {url} — {str(exc)[:120]}"))
            return None

        if not isinstance(data, dict) or "analysis_summary" not in data:
            events.append(_ev("warning",
                f"JS-Oracle(http): {url} — unexpected response shape"))
            return None

        total = data.get("analysis_summary", {}).get("total_findings", 0)
        sev   = data.get("analysis_summary", {}).get("highest_severity", "none")
        events.append(_ev("success",
            f"JS-Oracle(http): {url} → {total} finding(s), highest: {sev}"))
        return data

    def _analyze_via_subprocess(
        self, url: str, target: str, out_dir: Path, override: dict, events: list
    ) -> dict | None:
        """
        Run the js-oracle CLI for a single URL as a subprocess.
        Returns the parsed JSON result dict, or None on failure.
        """
        # The pre-filter may have decided to send pre-sliced local content (via
        # --file) instead of the raw URL, and/or to route this file to a cheaper
        # model (via --model). Absent an override (e.g. a fail-open file the
        # pre-filter could not read), fall back to the original --url behaviour.
        source_args = (["--file", override["file"]] if override.get("file")
                       else ["--url", url])
        model_args = ["--model", override["model"]] if override.get("model") else []

        note = ""
        if override.get("file"):
            note += " [sliced]"
        if override.get("model"):
            note += f" [{override['model']}]"
        events.append(_ev("info", f"JS-Oracle → {url}{note}"))

        cmd = [
            str(_JS_ORACLE_PYTHON),
            str(_JS_ORACLE_MAIN),
            "analyze",
            *source_args,
            "--domain", target,
            "--output", str(out_dir),
            *model_args,
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_PER_FILE_TIMEOUT,
                cwd=str(_JS_ORACLE_ROOT),
            )
            if proc.returncode != 0:
                # Non-zero exit is common for HTTP errors — log and continue
                err_line = (proc.stderr or proc.stdout or "").strip().splitlines()
                hint = err_line[-1] if err_line else "unknown error"
                events.append(_ev("warning", f"JS-Oracle: {url} — {hint[:120]}"))
                return None

        except subprocess.TimeoutExpired:
            events.append(_ev("warning",
                f"JS-Oracle: {url} — timed out after {_PER_FILE_TIMEOUT}s"
            ))
            return None
        except Exception as exc:
            events.append(_ev("warning", f"JS-Oracle subprocess error: {exc}"))
            return None

        # Find the JSON report JS-Oracle wrote (slug of URL + .json)
        json_files = sorted(out_dir.glob("*.json"))
        if not json_files:
            events.append(_ev("warning", f"JS-Oracle: no JSON output found for {url}"))
            return None

        # Take the newest file in case of multiple matches
        newest = max(json_files, key=lambda p: p.stat().st_mtime)
        try:
            data = json.loads(newest.read_text())
            total = data.get("analysis_summary", {}).get("total_findings", 0)
            sev   = data.get("analysis_summary", {}).get("highest_severity", "none")
            events.append(_ev("success",
                f"JS-Oracle: {url} → {total} finding(s), highest: {sev}"
            ))
            return data
        except (json.JSONDecodeError, Exception) as exc:
            events.append(_ev("warning", f"JS-Oracle: failed to parse output for {url}: {exc}"))
            return None

    # ── Public interface ──────────────────────────────────────────────────

    def execute(self, target: str, js_urls: list) -> dict:
        """
        Run JS-Oracle against the discovered JS files and return merged findings.
        Never raises — errors are logged as events and the module degrades gracefully.
        """
        events:      list = []
        _empty = {
            "status":             "skipped",
            "events":             events,
            "endpoints":          [],
            "api_keys":           [],
            "auth_issues":        [],
            "sinks":              [],
            "business_logic":     [],
            "raw_findings_count": 0,
            "highest_severity":   "none",
            "js_files_analyzed":  0,
            "js_live_count":      0,
            "archived_endpoints": [],
            "archived_count":     0,
        }

        events.append(_ev("info",
            f"Module 4 — JS-Oracle JavaScript analysis → {target}"
        ))

        if not js_urls:
            events.append(_ev("info",
                "JS-Oracle skipped — no JavaScript files in Module 1 output"
            ))
            return _empty

        if not self._check_available(events):
            return _empty

        candidates = self._select_urls(
            target, js_urls, events, limit=_MAX_LIVENESS_CANDIDATES)
        if not candidates:
            events.append(_ev("warning",
                "JS-Oracle: all discovered JS URLs were CDN/third-party — skipping"
            ))
            return _empty

        # Verify liveness BEFORE applying the analysis cap. Doing it the other
        # way round is what let 8 dead archived jQuery files consume the entire
        # budget and return "0 findings" as though the target were clean.
        live_records, archived_records = self._partition_by_liveness(
            candidates, events)

        _empty["archived_endpoints"] = archived_records
        _empty["archived_count"]     = len(archived_records)

        if archived_records:
            self._persist_archived(archived_records, events)

        if not live_records:
            events.append(_ev("warning",
                f"JS-Oracle: none of the {len(candidates)} candidate file(s) are "
                f"still served as JavaScript — nothing to analyze. "
                f"{len(archived_records)} archived endpoint(s) parked for manual "
                f"review; this is NOT evidence the target is clean."
            ))
            return _empty

        selected = [r["url"] for r in live_records[:_MAX_JS_FILES]]
        if len(live_records) > _MAX_JS_FILES:
            events.append(_ev("info",
                f"JS-Oracle: {len(live_records)} live file(s) found — analyzing "
                f"the top {_MAX_JS_FILES} by priority"
            ))

        # ── Pre-filter ("purifier") — content-level token triage ──────────────
        # BEFORE any LLM call: score each live file, SKIP the ones with zero app
        # signals (their free offline findings are still kept), route the rest to
        # a cheap or premium model, and slice oversized bundles down to their hot
        # regions. Fail-open: a file the pre-filter cannot read falls through to a
        # whole-file deep analysis (legacy behaviour), never dropped.
        plan = build_plan(selected, target, events)
        self._analysis_override: dict = {}
        analyzable = [u for u in selected
                      if plan.get(u) is None or plan[u].route != "skip"]

        # Use a per-run temp dir so JS-Oracle's report files don't collide
        with tempfile.TemporaryDirectory(prefix="jsoracle_") as tmp_str:
            tmp_dir   = Path(tmp_str)
            wall_start = time.monotonic()
            llm_results:     list[dict] = []
            offline_results: list[dict] = []

            for idx, url in enumerate(selected):
                decision = plan.get(url)

                # Free offline findings are merged for EVERY file, even skipped
                # ones, so a secret sliced out of an LLM window is never lost.
                if decision and decision.offline:
                    offline_results.append(decision.offline)

                # Skipped files never reach the LLM and cost no wall-clock time.
                if decision and decision.route == "skip":
                    continue

                elapsed = time.monotonic() - wall_start
                if elapsed >= _TOTAL_TIMEOUT:
                    remaining = sum(
                        1 for u in selected[idx:]
                        if plan.get(u) is None or plan[u].route != "skip")
                    events.append(_ev("warning",
                        f"JS-Oracle: wall-clock budget ({_TOTAL_TIMEOUT}s) reached — "
                        f"skipping remaining {remaining} file(s) to analyze"
                    ))
                    break

                # Per-file output dir — use loop index (not result count) to
                # avoid FileExistsError when earlier files fail.
                url_dir = tmp_dir / f"file_{idx:02d}"
                url_dir.mkdir()

                # Hand the LLM pre-sliced local content (--file) when we have it,
                # plus any model override; _analyze_url falls back to --url when
                # there is no override (the fail-open path).
                if decision and decision.llm_content is not None:
                    sliced_path = url_dir / "source.js"
                    sliced_path.write_text(decision.llm_content, encoding="utf-8")
                    self._analysis_override[url] = {
                        "file": str(sliced_path), "model": decision.model}
                elif decision and decision.model:
                    self._analysis_override[url] = {"file": None, "model": decision.model}

                result = self._analyze_url(url, target, url_dir, events)
                if result:
                    llm_results.append(result)

        # Merged findings = what the LLM returned + the free offline pass.
        file_results = llm_results + offline_results
        if not file_results:
            _empty["status"] = "error"
            events.append(_ev("warning",
                f"JS-Oracle: no findings produced — {len(analyzable)} file(s) were "
                f"sent to the LLM and {len(selected) - len(analyzable)} were skipped "
                f"as offline-empty by the pre-filter"
            ))
            return _empty

        # Merge across all files
        merged = _merge_all(file_results)

        # Classify suspicious_logic into sinks vs business logic
        sinks:          list = []
        business_logic: list = []
        for finding in merged["suspicious_logic"]:
            if _is_sink(finding):
                sinks.append(finding)
            else:
                business_logic.append(finding)

        # Compute highest severity across all suspicious findings
        highest = "none"
        for f in merged["suspicious_logic"]:
            highest = _higher_severity(highest, f.get("severity", "none"))

        raw_count = (
            len(merged["endpoints"])
            + len(merged["secrets"])
            + len(merged["auth_logic"])
            + len(merged["suspicious_logic"])
        )

        # Persist merged findings to output_dir for reference
        out_file = self.output_dir / "js_oracle_findings.json"
        out_file.write_text(json.dumps({
            "endpoints":    merged["endpoints"],
            "secrets":      merged["secrets"],
            "auth_logic":   merged["auth_logic"],
            "sinks":        sinks,
            "business_logic": business_logic,
            "highest_severity": highest,
            "js_files_analyzed": len(llm_results),
            "js_live_count":     len(live_records),
            "archived_count":    len(archived_records),
        }, indent=2))

        # "ok" only when every file the pre-filter kept for the LLM was analyzed
        # successfully; skipped files are intentional and never count against it.
        status = "ok" if len(llm_results) == len(analyzable) else "partial"

        events.append(_ev("success",
            f"Module 4 complete — live JS analyzed: {len(llm_results)}"
            f" | archived JS parked: {len(archived_records)}"
            f" — {raw_count} finding(s), highest severity: {highest} "
            f"→ js_oracle_findings.json"
        ))
        if archived_records:
            events.append(_ev("info",
                f"Coverage note: {len(file_results)} file(s) reflect CURRENTLY "
                f"served JavaScript. {len(archived_records)} archived file(s) "
                f"were NOT analyzed (no longer served) and are listed in "
                f"js_archived_endpoints.json for manual review."
            ))

        return {
            "status":             status,
            "events":             events,
            "endpoints":          merged["endpoints"],
            "api_keys":           merged["secrets"],
            "auth_issues":        merged["auth_logic"],
            "sinks":              sinks,
            "business_logic":     business_logic,
            "raw_findings_count": raw_count,
            "highest_severity":   highest,
            "js_files_analyzed":  len(llm_results),
            "js_live_count":      len(live_records),
            "archived_endpoints": archived_records,
            "archived_count":     len(archived_records),
        }
