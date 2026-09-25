"""
Tests for JS discovery from httpx output (core.recon._discover_js_files).

The regression these lock shut: httpx's headless (-ss) mode writes a
`{"timestamp":…, "link_request":[…]}` object (every sub-resource the browser
fetched), NOT the standard one-object-per-line format. The old parser read it
line-by-line, found nothing, and reported "0 JS files" even though the browser
had just loaded a redirect target (nour.net.sa -> www.nournet.sa) full of JS.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.recon import ReconModule, _iter_httpx_objects

# The exact shape observed from a real scan (httpx -ss headless output).
_HEADLESS = {
    "timestamp": "2026-09-04T15:20:45Z",
    "link_request": [
        {"RequestID": "1", "URL": "https://www.nournet.sa/", "Method": "GET", "StatusCode": 200},
        {"RequestID": "2", "URL": "https://www.nournet.sa/wp-content/uploads/blocksy/css/global.css?ver=04021", "StatusCode": 200},
        {"RequestID": "3", "URL": "https://www.nournet.sa/wp-includes/js/jquery/jquery.min.js?ver=3.7.1", "StatusCode": 200},
        {"RequestID": "4", "URL": "https://www.nournet.sa/wp-content/themes/blocksy/static/bundle/main.js?ver=2.1.56", "StatusCode": 200},
    ],
}


class TestJsDiscovery(unittest.TestCase):

    def _discover(self, httpx_text: str, historical=None) -> list:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = Path(tmp.name)
        (out / "httpx_out.json").write_text(httpx_text, encoding="utf-8")
        return ReconModule("nour.net.sa", out)._discover_js_files(
            ["https://nour.net.sa"], historical or [], [])

    def test_extracts_js_from_headless_link_request(self):
        js = self._discover(json.dumps(_HEADLESS))
        self.assertIn("https://www.nournet.sa/wp-includes/js/jquery/jquery.min.js", js)
        self.assertIn("https://www.nournet.sa/wp-content/themes/blocksy/static/bundle/main.js", js)
        self.assertFalse(any(u.endswith(".css") for u in js),
                         "a .css resource was misclassified as JS")

    def test_pretty_printed_headless_also_parses(self):
        js = self._discover(json.dumps(_HEADLESS, indent=2))
        self.assertTrue(any(u.endswith("main.js") for u in js))

    def test_standard_jsonl_body_extraction_still_works(self):
        line = json.dumps({"url": "https://x.com/",
                           "body": '<script src="/assets/app.js"></script>'
                                   '<script src="https://cdn.x.com/lib.js?v=1"></script>'})
        js = self._discover(line)
        self.assertIn("https://x.com/assets/app.js", js)
        self.assertIn("https://cdn.x.com/lib.js", js)

    def test_protocol_relative_js_resolves_to_its_own_host(self):
        # //host/app.js must become scheme://host/app.js, NOT be glued onto the
        # page host as a path (the double-slash bug).
        line = json.dumps({"url": "http://x.com/",
                           "body": '<script src="//cdn.other.com/analytics.js"></script>'})
        js = self._discover(line)
        self.assertIn("http://cdn.other.com/analytics.js", js)
        self.assertFalse(any("x.com//cdn" in u for u in js),
                         "protocol-relative URL was glued onto the base host")

    def test_historical_js_included(self):
        js = self._discover("{}", historical=["https://x.com/old.js?v=2", "https://x.com/page.php"])
        self.assertIn("https://x.com/old.js", js)
        self.assertNotIn("https://x.com/page.php", js)

    def test_missing_or_empty_file_is_safe(self):
        self.assertEqual(self._discover(""), [])

    def test_iter_helper_handles_jsonl_and_whole_object(self):
        self.assertEqual(len(list(_iter_httpx_objects('{"a":1}\n{"b":2}'))), 2)   # JSONL
        self.assertEqual(len(list(_iter_httpx_objects('{"a":1}'))), 1)            # single
        self.assertEqual(len(list(_iter_httpx_objects('[{"a":1},{"b":2}]'))), 2)  # array
        self.assertEqual(list(_iter_httpx_objects("")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
