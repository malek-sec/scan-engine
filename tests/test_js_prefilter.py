"""
Tests for the JS pre-filter ("purifier") — core.js_prefilter.

The pre-filter is the token-saving stage that decides, per live JS file, whether
it is worth an LLM call at all (and if so, which model, and how much of it). All
tests here are hermetic: the one network seam (_fetch_js_source) is injected, so
nothing touches the wire.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core import js_prefilter as pf
from core.js_prefilter import (build_plan, build_offline,
                               score_content, slice_content)
from core.js_oracle import JSOracle


# ── fixtures ───────────────────────────────────────────────────────────────────

SECRET_JS   = 'const k = "AKIA1234567890ABCDEF"; // aws key\n'
ENDPOINT_JS = 'var u = "/api/users"; renderTable(u);\n'
ZERO_JS     = 'var a = 1; var b = a + 2;\nfunction noop() { return b; }\n'
SOURCEMAP_JS = '//# sourceMappingURL=app.min.js.map\nvar a = 1;\n'


def _rec(url, alive=True, sha=None):
    return {"url": url, "alive": alive, "status": 200,
            "content_type": "application/javascript", "method": "HEAD",
            "reason": "ok", "sha256": sha or url}


# ── scoring ────────────────────────────────────────────────────────────────────

class TestScoring(unittest.TestCase):

    def test_secret_scores_deep(self):
        r = score_content(SECRET_JS)
        self.assertGreaterEqual(r.score, pf._DEEP_THRESHOLD)
        self.assertIn("secret", r.signals)

    def test_lone_endpoint_scores_cheap_band(self):
        r = score_content(ENDPOINT_JS)
        self.assertGreaterEqual(r.score, pf._CHEAP_THRESHOLD)
        self.assertLess(r.score, pf._DEEP_THRESHOLD)

    def test_inert_code_scores_zero(self):
        self.assertEqual(score_content(ZERO_JS).score, 0)

    def test_empty_content_scores_zero(self):
        self.assertEqual(score_content("").score, 0)


# ── offline findings ───────────────────────────────────────────────────────────

class TestOffline(unittest.TestCase):

    def test_secret_is_masked_not_leaked(self):
        off = build_offline(SECRET_JS, "x.com")
        self.assertEqual(len(off["secrets"]), 1)
        self.assertNotIn("AKIA1234567890ABCDEF", off["secrets"][0]["value_preview"])

    def test_relative_endpoint_is_captured(self):
        off = build_offline(ENDPOINT_JS, "x.com")
        self.assertTrue(any(e["path"] == "/api/users" for e in off["endpoints"]))

    def test_third_party_absolute_urls_are_dropped(self):
        js = 'a("https://evil-cdn.com/api/track");'
        self.assertEqual(build_offline(js, "x.com")["endpoints"], [])

    def test_same_target_absolute_url_is_kept(self):
        js = 'a("https://api.x.com/v2/orders");'
        off = build_offline(js, "x.com")
        self.assertTrue(any("api.x.com/v2/orders" in e["path"] for e in off["endpoints"]))

    def test_source_map_becomes_info_finding(self):
        off = build_offline(SOURCEMAP_JS, "x.com")
        self.assertTrue(off["suspicious_logic"])
        self.assertEqual(off["suspicious_logic"][0]["severity"], "info")


# ── slicing ────────────────────────────────────────────────────────────────────

class TestSlicing(unittest.TestCase):

    def test_small_files_are_never_sliced(self):
        self.assertEqual(slice_content(SECRET_JS, {0}), SECRET_JS)

    def test_large_file_is_sliced_but_keeps_signals_and_paths(self):
        filler = "var x = 0;\n"
        content = (filler * 3000
                   + 'var img = "/static/img/logo.png";\n'   # path, no signal window
                   + filler * 3000
                   + 'const k = "AKIA1234567890ABCDEF";\n'    # secret -> hot window
                   + filler * 3000)
        self.assertGreater(len(content), pf._SLICE_MIN_CHARS)

        scored = score_content(content)
        sliced = slice_content(content, scored.hot_lines)

        self.assertLess(len(sliced), len(content) // 2, "slice did not shrink the file")
        self.assertIn("AKIA1234567890ABCDEF", sliced, "sliced out the actual signal")
        self.assertIn("/static/img/logo.png", sliced,
                      "path-like literal outside the window was lost (recall gap)")


# ── plan building / routing ────────────────────────────────────────────────────

class TestBuildPlan(unittest.TestCase):

    def _plan(self, mapping, target="x.com"):
        return build_plan(list(mapping), target, [], fetch=lambda u: mapping.get(u))

    def test_routes_by_score(self):
        plan = self._plan({
            "https://x.com/secret.js":   SECRET_JS,
            "https://x.com/endpoint.js": ENDPOINT_JS,
            "https://x.com/inert.js":    ZERO_JS,
        })
        self.assertEqual(plan["https://x.com/secret.js"].route, "deep")
        self.assertEqual(plan["https://x.com/endpoint.js"].route, "cheap")
        self.assertEqual(plan["https://x.com/inert.js"].route, "skip")

    def test_cheap_route_gets_the_cheap_model(self):
        plan = self._plan({"https://x.com/endpoint.js": ENDPOINT_JS})
        self.assertEqual(plan["https://x.com/endpoint.js"].model, pf._CHEAP_MODEL)

    def test_skip_never_carries_llm_content(self):
        plan = self._plan({"https://x.com/inert.js": ZERO_JS})
        self.assertIsNone(plan["https://x.com/inert.js"].llm_content)

    def test_deep_carries_llm_content(self):
        plan = self._plan({"https://x.com/secret.js": SECRET_JS})
        self.assertIsNotNone(plan["https://x.com/secret.js"].llm_content)

    def test_fetch_failure_fails_open_to_deep(self):
        """A file the pre-filter cannot read must be analyzed whole, never dropped."""
        plan = build_plan(["https://x.com/gone.js"], "x.com", [],
                          fetch=lambda u: None)
        d = plan["https://x.com/gone.js"]
        self.assertEqual(d.route, "deep")
        self.assertIsNone(d.llm_content)   # -> js-oracle fetches the URL itself
        self.assertIsNone(d.model)         # -> default (premium) model

    def test_identical_content_is_deduped(self):
        plan = self._plan({
            "https://x.com/a.js": SECRET_JS,
            "https://x.com/b.js": SECRET_JS,
        })
        routes = sorted(d.route for d in plan.values())
        self.assertEqual(routes, ["deep", "skip"], "duplicate content was re-analyzed")

    def test_master_switch_off_routes_everything_deep_whole(self):
        with mock.patch.object(pf, "PREFILTER_ENABLED", False):
            plan = build_plan(["https://x.com/secret.js"], "x.com", [],
                              fetch=lambda u: SECRET_JS)
        d = plan["https://x.com/secret.js"]
        self.assertEqual(d.route, "deep")
        self.assertIsNone(d.llm_content)   # legacy: whole-file via --url
        self.assertIsNone(d.offline)


# ── integration with the JS-Oracle bridge ──────────────────────────────────────

class TestBridgeIntegration(unittest.TestCase):
    """The bridge must actually skip the LLM for zero-signal files."""

    def _run(self, url, content):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        analyzed = []

        def fake_analyze(u, target, out_dir, events):
            analyzed.append(u)
            return {"endpoints": [{"path": "/x", "method": "GET"}], "secrets": [],
                    "auth_logic": [], "suspicious_logic": []}

        with mock.patch.object(JSOracle, "_check_available", return_value=True), \
             mock.patch("core.js_oracle._probe_liveness", side_effect=lambda u: _rec(u)), \
             mock.patch("core.js_prefilter._fetch_js_source", return_value=content), \
             mock.patch.object(JSOracle, "_analyze_url", side_effect=fake_analyze):
            result = JSOracle(Path(tmp.name)).execute("x.com", [url])
        return result, analyzed

    def test_signal_rich_file_reaches_the_llm(self):
        result, analyzed = self._run("https://x.com/app.js", SECRET_JS)
        self.assertEqual(analyzed, ["https://x.com/app.js"])
        self.assertEqual(result["js_files_analyzed"], 1)

    def test_inert_file_is_skipped_no_llm_call(self):
        result, analyzed = self._run("https://x.com/vendor.js", SOURCEMAP_JS)
        self.assertEqual(analyzed, [], "an offline-empty file was still sent to the LLM")
        self.assertEqual(result["js_files_analyzed"], 0)
        # ...but its free offline finding (the source map) is still reported.
        self.assertTrue(result["business_logic"] or result["sinks"],
                        "the skipped file's offline finding was dropped")


class TestExpandedSecrets(unittest.TestCase):
    """The expanded, prefix-anchored secret formats must be detected + masked."""

    CASES = {
        "gitlab_pat":    "glpat-ABCDabcd1234EFGH5678",
        "npm_token":     "npm_abcdefghijklmnopqrstuvwxyz0123456789",
        "sendgrid":      "SG.abcdefghijklmnopqrstuv."
                         "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
        "stripe_rk":     "rk_live_abcdefghijklmnopqrstuvwx",
        "twilio_sid":    "SK0123456789abcdef0123456789abcdef",
        "google_oauth":  "ya29.a0ARdEfGhIjKlMnOpQrStUvWx",
        "slack_webhook": "https://hooks.slack.com/services/T00000000/B11111111/abcXYZ123",
    }

    def test_each_new_secret_is_detected_and_masked(self):
        for label, sample in self.CASES.items():
            off = build_offline(f'var x = "{sample}";', "x.com")
            self.assertTrue(off["secrets"], f"{label} not detected: {sample}")
            self.assertTrue(all(s["value_preview"] != sample for s in off["secrets"]),
                            f"{label} value was not masked")

    def test_a_secret_alone_routes_deep(self):
        plan = build_plan(["https://x.com/k.js"], "x.com", [],
                          fetch=lambda u: 'const t = "glpat-ABCDabcd1234EFGH5678";')
        self.assertEqual(plan["https://x.com/k.js"].route, "deep")


if __name__ == "__main__":
    unittest.main(verbosity=2)
