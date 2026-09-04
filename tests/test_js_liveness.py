"""
Regression tests for JS-Oracle liveness gating (core.js_oracle).

Background — the bug these tests lock shut
------------------------------------------
JS candidates come largely from Wayback/crt.sh historical URLs. On flagyard.com
that meant jquery-1.4.2 / jquery-ui-1.8.x from a site that no longer exists.
They were analyzed anyway, returned 0 findings, and produced a false sense of
coverage.

The trap: those dead files answer **HTTP 200 with text/html**, because the
current single-page app serves index.html for any unmatched path. A status-only
liveness check therefore marks them live. Both halves of "2xx AND JavaScript
content-type" are load-bearing.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.js_oracle import (JSOracle, _MAX_JS_FILES, _lib_family,
                            _probe_liveness)


def _rec(url, alive, status=200, ctype="application/javascript",
         reason="", sha=None):
    return {"url": url, "alive": alive, "status": status,
            "content_type": ctype, "method": "HEAD",
            "reason": reason or ("ok" if alive else "dead"), "sha256": sha}


class _FakeResp:
    """Minimal stand-in for the urlopen context manager."""

    def __init__(self, status, ctype, body=b""):
        self.status = status
        self.headers = {"Content-Type": ctype}
        self._body = body

    def read(self, n=None):
        return self._body[:n] if n else self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestLivenessProbeSemantics(unittest.TestCase):
    """2xx alone is not enough — the content-type must say JavaScript."""

    def _probe(self, status, ctype):
        with mock.patch("core.js_oracle.urllib.request.urlopen",
                        return_value=_FakeResp(status, ctype, b"var a=1;")):
            return _probe_liveness("https://x.com/app.js")

    def test_200_with_javascript_is_live(self):
        self.assertTrue(self._probe(200, "application/javascript")["alive"])

    def test_200_with_text_javascript_is_live(self):
        self.assertTrue(self._probe(200, "text/javascript; charset=UTF-8")["alive"])

    def test_200_with_html_is_not_live(self):
        """
        THE regression: an SPA catch-all page returned for a deleted asset.
        Marking this live is what burned the budget on dead jQuery.
        """
        r = self._probe(200, "text/html; charset=UTF-8")
        self.assertFalse(r["alive"])
        self.assertIn("not JavaScript", r["reason"])

    def test_200_with_no_content_type_is_not_live(self):
        self.assertFalse(self._probe(200, "")["alive"])

    def test_404_is_not_live(self):
        r = self._probe(404, "text/html")
        self.assertFalse(r["alive"])
        self.assertIn("404", r["reason"])

    def test_network_error_is_not_live(self):
        with mock.patch("core.js_oracle.urllib.request.urlopen",
                        side_effect=OSError("boom")):
            r = _probe_liveness("https://x.com/app.js")
        self.assertFalse(r["alive"])

    def test_record_is_returned_even_when_dead(self):
        """Dead files must stay inspectable, never be silently dropped."""
        r = self._probe(404, "text/html")
        self.assertEqual(r["url"], "https://x.com/app.js")
        self.assertEqual(r["status"], 404)
        self.assertTrue(r["reason"])


class TestPartitioning(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.oracle = JSOracle(Path(self._tmp.name))

    def _partition(self, mapping):
        """mapping: {url: alive_bool}"""
        def fake(u):
            return _rec(u, mapping[u])
        with mock.patch("core.js_oracle._probe_liveness", side_effect=fake):
            return self.oracle._partition_by_liveness(list(mapping), [])

    def test_live_and_dead_are_separated(self):
        live, arch = self._partition({
            "https://x.com/live.js": True,
            "https://x.com/dead.js": False,
        })
        self.assertEqual([r["url"] for r in live], ["https://x.com/live.js"])
        self.assertEqual([r["url"] for r in arch], ["https://x.com/dead.js"])

    def test_dead_files_are_preserved_not_discarded(self):
        live, arch = self._partition({f"https://x.com/d{i}.js": False
                                      for i in range(5)})
        self.assertEqual(live, [])
        self.assertEqual(len(arch), 5, "archived intel was thrown away")

    def test_unprobed_files_are_parked_not_assumed_live(self):
        """A probe that never completed must never count as live."""
        with mock.patch("core.js_oracle._probe_liveness",
                        side_effect=Exception("timeout")):
            live, arch = self.oracle._partition_by_liveness(
                ["https://x.com/a.js"], [])
        self.assertEqual(live, [])
        self.assertEqual(len(arch), 1)

    def test_identical_content_is_deduped_out_of_live(self):
        def fake(u):
            return _rec(u, True, sha="deadbeef")
        with mock.patch("core.js_oracle._probe_liveness", side_effect=fake):
            live, arch = self.oracle._partition_by_liveness(
                ["https://x.com/a.js", "https://x.com/b.js"], [])
        self.assertEqual(len(live), 1)
        self.assertEqual(len(arch), 1)

    def test_ranking_is_preserved(self):
        urls = [f"https://x.com/{c}.js" for c in "abcd"]
        live, _ = self._partition({u: True for u in urls})
        self.assertEqual([r["url"] for r in live], urls)


class TestVendorDedup(unittest.TestCase):
    """Analysis budget belongs to app-specific JS."""

    def test_versioned_copies_share_a_family(self):
        self.assertEqual(_lib_family("https://x/jquery-1.4.2.min.js")[0],
                         _lib_family("https://x/jquery-1.8.0.min.js")[0])

    def test_vendor_libraries_are_flagged(self):
        for u in ("jquery-1.4.2.min.js", "jquery-ui-1.8.22.min.js",
                  "react.production.min.js", "tslib.es6-NPRqQeXK.js"):
            self.assertTrue(_lib_family("https://x/" + u)[1], u)

    def test_app_specific_files_are_not_vendor(self):
        for u in ("index-CGupvGYo.js", "socketEvents-C4PXYrnS.js",
                  "AnimateOnScroll-Dwb7dOyl.js"):
            self.assertFalse(_lib_family("https://x/" + u)[1], u)

    def test_build_hashes_collapse_but_plugin_names_do_not(self):
        """
        Vite build hashes are hyphen-separated; jQuery plugin names are
        dot-separated. Collapsing the latter evicted real jQuery from the
        vendored copy quota, so it reached neither bucket.
        """
        self.assertEqual(_lib_family("https://x/Card-Ce6gTZY0.js")[0],
                         _lib_family("https://x/Card-DOuMEqSH.js")[0])
        self.assertNotEqual(_lib_family("https://x/jquery.corner.js")[0],
                            _lib_family("https://x/jquery-1.4.2.min.js")[0])
        self.assertNotEqual(_lib_family("https://x/jquery.bxGallery.1.1.min.js")[0],
                            _lib_family("https://x/jquery.fancybox-1.3.4.pack.js")[0])

    def test_vendored_files_still_reach_the_candidate_list(self):
        """
        Vendored files must not be starved out by a long tail of app-specific
        ones — otherwise dead jQuery lands in NEITHER bucket.
        """
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        js = [f"https://x.com/assets/app{i}-AAAAAAAA.js" for i in range(100)]
        js += ["https://x.com/ext/jquery/jquery-1.4.2.min.js",
               "https://x.com/ext/jquery/ui/jquery-ui-1.8.22.min.js"]
        got = JSOracle(Path(tmp.name))._select_urls("x.com", js, [], limit=20)
        self.assertTrue(any("jquery-1.4.2" in u for u in got))


class TestArchivedUrlsKeptVerbatim(unittest.TestCase):
    """
    Archived URLs are probed and recorded exactly as the archive had them.

    This is a DELIBERATE decision, not an omission: the original scheme and
    host are part of the finding, and rewriting them onto the current
    canonical host would answer a different question ("does this PATH exist
    today?") while silently promoting a URL the archive never recorded.

    These tests exist so nobody "fixes" the behaviour by adding normalisation.
    """

    LEGACY = "http://www.old.example.com/ext/jquery/jquery-1.4.2.min.js"

    def test_probe_targets_the_url_verbatim(self):
        seen = {}

        def capture(req, timeout=None):
            seen["url"] = req.full_url
            return _FakeResp(404, "text/html")

        with mock.patch("core.js_oracle.urllib.request.urlopen",
                        side_effect=capture):
            _probe_liveness(self.LEGACY)

        self.assertEqual(seen["url"], self.LEGACY,
                         "archived URL was rewritten before probing")

    def test_scheme_and_host_are_not_normalised(self):
        with mock.patch("core.js_oracle.urllib.request.urlopen",
                        return_value=_FakeResp(404, "text/html")):
            rec = _probe_liveness(self.LEGACY)
        self.assertEqual(rec["url"], self.LEGACY)
        self.assertTrue(rec["url"].startswith("http://"),
                        "original scheme was upgraded")
        self.assertIn("www.old.example.com", rec["url"],
                      "original host was replaced with the canonical one")

    def test_archived_record_keeps_the_original_url(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        oracle = JSOracle(Path(tmp.name))

        def fake(u):
            return _rec(u, False, status=404, ctype="text/html")

        with mock.patch("core.js_oracle._probe_liveness", side_effect=fake):
            live, arch = oracle._partition_by_liveness([self.LEGACY], [])

        self.assertEqual(live, [])
        self.assertEqual(arch[0]["url"], self.LEGACY,
                         "the archived bucket lost the original URL")

    def test_module_documents_the_decision(self):
        """A future reader must find the rationale in the source, not git log."""
        import core.js_oracle as mod
        doc = (mod.__doc__ or "").lower()
        self.assertIn("url fidelity", doc)
        self.assertIn("as-is", doc)
        self.assertIn("deliberate", doc)
        probe_doc = (_probe_liveness.__doc__ or "").lower()
        self.assertIn("verbatim", probe_doc,
                      "the probe site does not warn against rewriting URLs")


class TestExecuteGating(unittest.TestCase):

    JS = ["https://x.com/live.js", "https://x.com/dead.js"]

    def _run(self, alive_map, analyze=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name)

        def fake_probe(u):
            return _rec(u, alive_map[u],
                        status=200 if alive_map[u] else 200,
                        ctype="application/javascript" if alive_map[u] else "text/html")

        analyzed = []

        def fake_analyze(url, target, out_dir, events):
            analyzed.append(url)
            return analyze if analyze is not None else {
                "endpoints": [{"url": "/api"}], "secrets": [],
                "auth_logic": [], "suspicious_logic": []}

        # The pre-filter fetches each live file to score it. Stub that network
        # seam to return None so every file takes the fail-open path (analyzed
        # whole, exactly as before the pre-filter existed) — keeping these
        # liveness-gating assertions hermetic and unchanged.
        with mock.patch.object(JSOracle, "_check_available", return_value=True), \
             mock.patch("core.js_oracle._probe_liveness", side_effect=fake_probe), \
             mock.patch("core.js_prefilter._fetch_js_source", return_value=None), \
             mock.patch.object(JSOracle, "_analyze_url", side_effect=fake_analyze):
            result = JSOracle(self.out).execute("x.com", list(alive_map))
        self.analyzed = analyzed
        return result

    def test_only_live_files_are_analyzed(self):
        r = self._run({"https://x.com/live.js": True,
                       "https://x.com/dead.js": False})
        self.assertEqual(self.analyzed, ["https://x.com/live.js"])
        self.assertEqual(r["js_files_analyzed"], 1)

    def test_dead_files_are_reported_separately(self):
        r = self._run({"https://x.com/live.js": True,
                       "https://x.com/dead.js": False})
        self.assertEqual(r["archived_count"], 1)
        self.assertEqual(r["js_live_count"], 1)
        self.assertEqual(r["archived_endpoints"][0]["url"], "https://x.com/dead.js")

    def test_counts_are_reported_distinctly_in_events(self):
        r = self._run({"https://x.com/live.js": True,
                       "https://x.com/dead.js": False})
        text = " ".join(e["msg"] for e in r["events"])
        self.assertIn("live JS analyzed: 1", text)
        self.assertIn("archived JS parked: 1", text)

    def test_archived_bucket_is_persisted(self):
        self._run({"https://x.com/live.js": True,
                   "https://x.com/dead.js": False})
        f = self.out / "js_archived_endpoints.json"
        self.assertTrue(f.exists())
        doc = json.loads(f.read_text())
        self.assertEqual(doc["archived_count"], 1)
        self.assertEqual(len(doc["endpoints"]), 1)

    def test_archived_file_explains_itself(self):
        """
        The file is dominated by 404s and text/html hits. Without an embedded
        rationale a future reader reads that as a scanner malfunction rather
        than the intended output.
        """
        self._run({"https://x.com/live.js": True,
                   "https://x.com/dead.js": False})
        doc = json.loads((self.out / "js_archived_endpoints.json").read_text())
        self.assertIn("_readme", doc)
        readme = " ".join(str(v) for v in doc["_readme"].values()).lower()
        for expected in ("not analyzed", "manual review", "deliberate",
                         "not rewritten", "not a scanner bug"):
            self.assertIn(expected, readme,
                          f"archived output does not explain '{expected}'")

    def test_all_dead_analyzes_nothing_and_says_so(self):
        r = self._run({"https://x.com/a.js": False, "https://x.com/b.js": False})
        self.assertEqual(self.analyzed, [])
        self.assertEqual(r["js_files_analyzed"], 0)
        self.assertEqual(r["archived_count"], 2)
        text = " ".join(e["msg"] for e in r["events"])
        self.assertIn("NOT evidence the target is clean", text,
                      "zero live files was not flagged as a coverage gap")

    def test_all_dead_does_not_report_success(self):
        r = self._run({"https://x.com/a.js": False})
        self.assertNotEqual(r["status"], "ok")

    def test_analysis_cap_applies_to_live_files_only(self):
        """
        The cap must be applied AFTER liveness. Applying it first is what let
        8 dead archived files consume the whole budget.
        """
        alive = {f"https://x.com/dead{i}-AAAAAAAA.js": False for i in range(20)}
        alive.update({f"https://x.com/live{i}-BBBBBBBB.js": True for i in range(10)})
        r = self._run(alive)
        self.assertEqual(len(self.analyzed), _MAX_JS_FILES)
        self.assertTrue(all("live" in u for u in self.analyzed),
                        "a dead file consumed part of the analysis budget")
        self.assertEqual(r["archived_count"], 20)

    def test_empty_input_still_exposes_buckets(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        r = JSOracle(Path(tmp.name)).execute("x.com", [])
        self.assertEqual(r["archived_count"], 0)
        self.assertEqual(r["js_live_count"], 0)
        self.assertEqual(r["archived_endpoints"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
