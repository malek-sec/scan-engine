"""
Tests for JS-Oracle OFFLINE mode ($0 path) and the deterministic report.

Guarantee locked here: when a scan runs in offline / FREE mode, JS-Oracle
extracts findings with the free regex pass ONLY and makes ZERO LLM calls
(_analyze_url must never fire), yet still writes js_oracle_findings.json and
returns real findings. core.offline_report then renders that file with no API.

Runs under pytest or as a plain script:  python tests/test_offline_mode.py
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.js_oracle import JSOracle
from core.js_prefilter import build_offline_plan
from core.offline_report import build_report

# JS content the free deterministic pass can mine: an endpoint literal, an AWS
# key (secret), and a source-map comment.
_SAMPLE_JS = (
    'const base="/api/v1/users/profile";\n'
    'fetch(base,{headers:{Authorization:"Bearer "+t}});\n'
    'const awsKey="AKIAIOSFODNN7EXAMPLE";\n'
    '//# sourceMappingURL=main.js.map\n'
)


def _rec(url, alive=True, status=200, ctype="application/javascript"):
    return {"url": url, "alive": alive, "status": status,
            "content_type": ctype, "method": "HEAD",
            "reason": "ok" if alive else "dead", "sha256": None}


class TestBuildOfflinePlan(unittest.TestCase):
    def test_extracts_findings_without_network(self):
        urls = ["https://x.com/a.js", "https://x.com/b.js"]
        with mock.patch("core.js_prefilter._fetch_js_source", return_value=_SAMPLE_JS):
            plan = build_offline_plan(urls, "x.com", [])
        # First file yields findings; second is an exact duplicate -> skipped.
        self.assertIsNotNone(plan.get("https://x.com/a.js"))
        off = plan["https://x.com/a.js"]
        self.assertTrue(off["endpoints"], "expected at least one endpoint")
        self.assertTrue(off["secrets"], "expected the AWS key as a secret")

    def test_unfetchable_url_is_dropped_not_raised(self):
        with mock.patch("core.js_prefilter._fetch_js_source", return_value=None):
            plan = build_offline_plan(["https://x.com/dead.js"], "x.com", [])
        self.assertEqual(plan, {})


class TestExecuteOfflineMakesNoLLMCall(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_offline_execute_zero_llm_calls_but_real_findings(self):
        urls = ["https://x.com/app.js"]

        def fake_probe(url, *a, **k):
            return _rec(url, alive=True)

        with mock.patch.object(JSOracle, "_check_available", return_value=True), \
             mock.patch("core.js_oracle._probe_liveness", side_effect=fake_probe), \
             mock.patch("core.js_prefilter._fetch_js_source", return_value=_SAMPLE_JS), \
             mock.patch.object(JSOracle, "_analyze_url") as analyze:
            result = JSOracle(self.out).execute("x.com", urls, offline=True)

        # The whole point: no per-file LLM call happened.
        analyze.assert_not_called()
        # ...yet we still produced findings from the free pass.
        self.assertTrue(result["endpoints"], "offline pass should yield endpoints")
        self.assertTrue(result["api_keys"], "offline pass should yield the secret")
        self.assertEqual(result["js_files_analyzed"], 0)   # 0 LLM-analyzed by design
        self.assertIn(result["status"], ("ok", "partial"))
        # ...and persisted them to disk for the offline report.
        saved = json.loads((self.out / "js_oracle_findings.json").read_text())
        self.assertTrue(saved["endpoints"])
        self.assertTrue(saved["secrets"])

    def test_report_renders_from_saved_findings(self):
        urls = ["https://x.com/app.js"]

        def fake_probe(url, *a, **k):
            return _rec(url, alive=True)

        with mock.patch.object(JSOracle, "_check_available", return_value=True), \
             mock.patch("core.js_oracle._probe_liveness", side_effect=fake_probe), \
             mock.patch("core.js_prefilter._fetch_js_source", return_value=_SAMPLE_JS), \
             mock.patch.object(JSOracle, "_analyze_url"):
            JSOracle(self.out).execute("x.com", urls, offline=True)

        md = build_report(self.out)
        self.assertIn("Recon Report", md)
        self.assertIn("API Endpoints", md)
        self.assertIn("no api call", md.lower())

    def test_report_survives_missing_findings_file(self):
        # A JS-less scan (no findings file) must still render, never raise.
        md = build_report(self.out)
        self.assertIn("Recon Report", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
