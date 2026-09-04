"""
Tests for the HTTP analysis backend of the JS-Oracle bridge (core.js_oracle).

The bridge can reach js-oracle two ways — a subprocess CLI (default) or a
long-running HTTP service (JS_ORACLE_MODE=http). These tests exercise the HTTP
dispatch, payload construction (raw URL vs. pre-sliced content + routed model),
graceful failure, and the health-based availability check — all hermetically
(the network seam is mocked; nothing touches the wire).
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import core.js_oracle as jo
from core.js_oracle import JSOracle

_OK = {"analysis_summary": {"total_findings": 1, "highest_severity": "high"},
       "endpoints": [], "secrets": [], "auth_logic": [], "suspicious_logic": []}


class TestHttpBackend(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.out = Path(self._tmp.name)
        self.oracle = JSOracle(self.out)
        self.oracle._analysis_override = {}

    def _http(self):
        return mock.patch.object(jo, "_JS_ORACLE_MODE", "http")

    def test_subprocess_is_the_default_mode(self):
        self.assertEqual(jo._JS_ORACLE_MODE, "subprocess")

    def test_dispatch_posts_to_the_service(self):
        seen = {}

        def fake_post(url, payload, timeout):
            seen["url"], seen["payload"] = url, payload
            return _OK

        with self._http(), mock.patch.object(jo, "_http_post_json", side_effect=fake_post):
            out = self.oracle._analyze_url("https://x.com/a.js", "x.com", self.out, [])

        self.assertEqual(out["analysis_summary"]["total_findings"], 1)
        self.assertTrue(seen["url"].endswith("/analyze"))
        self.assertEqual(seen["payload"]["url"], "https://x.com/a.js")
        self.assertEqual(seen["payload"]["domain"], "x.com")
        self.assertNotIn("content", seen["payload"])

    def test_sliced_content_and_model_are_sent_inline(self):
        sliced = self.out / "source.js"
        sliced.write_text("var a = 1; // sliced by prefilter", encoding="utf-8")
        self.oracle._analysis_override = {
            "https://x.com/a.js": {"file": str(sliced), "model": "claude-haiku-4-5"}}
        seen = {}

        def fake_post(url, payload, timeout):
            seen.update(payload)
            return _OK

        with self._http(), mock.patch.object(jo, "_http_post_json", side_effect=fake_post):
            self.oracle._analyze_url("https://x.com/a.js", "x.com", self.out, [])

        self.assertEqual(seen.get("content"), "var a = 1; // sliced by prefilter")
        self.assertEqual(seen.get("model"), "claude-haiku-4-5")
        self.assertNotIn("url", seen, "content must win over url when both could apply")

    def test_transport_failure_degrades_to_none(self):
        with self._http(), mock.patch.object(
                jo, "_http_post_json", side_effect=OSError("connection refused")):
            out = self.oracle._analyze_url("https://x.com/a.js", "x.com", self.out, [])
        self.assertIsNone(out, "a transport error must skip the file, not raise")

    def test_malformed_response_degrades_to_none(self):
        with self._http(), mock.patch.object(
                jo, "_http_post_json", return_value={"oops": True}):
            out = self.oracle._analyze_url("https://x.com/a.js", "x.com", self.out, [])
        self.assertIsNone(out)

    def test_availability_follows_health(self):
        with self._http(), mock.patch.object(jo, "_http_get_ok", return_value=True):
            self.assertTrue(self.oracle._check_available([]))
        with self._http(), mock.patch.object(jo, "_http_get_ok", return_value=False):
            self.assertFalse(self.oracle._check_available([]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
