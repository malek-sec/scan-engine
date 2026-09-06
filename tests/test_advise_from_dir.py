"""
Tests for core.advise_from_dir — running the AI advisor on a saved scan dir,
reusing the JS findings already on disk. The advisor itself is mocked, so these
tests make NO API call and cost nothing.

What is locked in:
  * the on-disk js_oracle_findings.json schema (secrets/auth_logic) is mapped to
    the js_data envelope the advisor expects (api_keys/auth_issues + raw count);
  * fingerprint.json (a list) becomes fp_data; active_recon.json becomes active_data;
  * advise_from_dir assembles a combined Markdown report from the analyses;
  * a missing fingerprint file degrades to a clean error, never a crash.

Runs under pytest or as a script:  python tests/test_advise_from_dir.py
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.advise_from_dir import load_scan_inputs, advise_from_dir, _js_data_from_findings


_FINDINGS = {
    "endpoints": [{"path": "/api/v1/users/{id}", "method": "GET", "confidence": "high"}],
    "secrets":   [{"type": "api_key", "value_preview": "AKIA****", "evidence": "k=AKIA..."}],
    "auth_logic": [{"mechanism": "JWT", "storage_location": "localStorage"}],
    "sinks":     [{"description": "innerHTML sink", "severity": "high"}],
    "business_logic": [{"description": "client-side price", "severity": "medium"}],
    "highest_severity": "high",
    "js_files_analyzed": 4,
    "js_live_count": 4,
    "archived_count": 1,
}
_FINGERPRINT = [{"host": "https://x.com", "technologies": {}, "open_ports": [443]}]
_ACTIVE = {"crawl": {"count": 12}, "fuzz": {"count": 3}, "ports": {"count": 2},
           "params": {"count": 1}, "nuclei": {"count": 0}}


def _seed(d: Path):
    (d / "fingerprint.json").write_text(json.dumps(_FINGERPRINT))
    (d / "js_oracle_findings.json").write_text(json.dumps(_FINDINGS))
    (d / "active_recon.json").write_text(json.dumps(_ACTIVE))


class TestKeyMapping(unittest.TestCase):
    def test_findings_schema_maps_to_advisor_envelope(self):
        js = _js_data_from_findings(_FINDINGS)
        self.assertEqual(js["api_keys"], _FINDINGS["secrets"])       # secrets -> api_keys
        self.assertEqual(js["auth_issues"], _FINDINGS["auth_logic"])  # auth_logic -> auth_issues
        self.assertEqual(js["raw_findings_count"], 5)                 # 1+1+1+1+1
        self.assertEqual(js["endpoints"], _FINDINGS["endpoints"])

    def test_load_scan_inputs_reads_all_three(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            _seed(d)
            fp, js, active = load_scan_inputs(d)
            self.assertEqual(fp, _FINGERPRINT)
            self.assertEqual(js["api_keys"], _FINDINGS["secrets"])
            self.assertEqual(active["crawl"]["count"], 12)


class TestAdviseFromDir(unittest.TestCase):
    def test_runs_advisor_and_builds_report(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            _seed(d)

            captured = {}

            class _FakeAdvisor:
                def __init__(self, fp_data, output_dir, js_data=None, active_data=None):
                    captured["fp"] = fp_data
                    captured["js"] = js_data
                    captured["active"] = active_data

                def execute(self):
                    return {"status": "ok", "events": [],
                            "analyses": {"https://x.com": "### Confirmed\n- IDOR on /api/v1/users/{id}"}}

            with mock.patch("core.ai_advisor.AIAdvisorModule", _FakeAdvisor):
                res = advise_from_dir(d)

            # The advisor received the reconstructed, correctly-mapped inputs.
            self.assertEqual(captured["fp"], _FINGERPRINT)
            self.assertEqual(captured["js"]["api_keys"], _FINDINGS["secrets"])
            self.assertEqual(captured["active"]["crawl"]["count"], 12)
            # ...and we assembled a combined report.
            self.assertIn("## https://x.com", res["report"])
            self.assertIn("IDOR", res["report"])

    def test_missing_fingerprint_is_clean_error(self):
        with tempfile.TemporaryDirectory() as t:
            res = advise_from_dir(Path(t))   # empty dir
            self.assertEqual(res["status"], "error")
            self.assertEqual(res["report"], "")
            self.assertTrue(res["events"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
