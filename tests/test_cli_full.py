"""
Wiring tests for the CLI `full` pipeline (cli/main.py).

Locks in that `full` is the COMPREHENSIVE scan the web Deep scan is:
  * Active Recon (katana/ffuf/nuclei) runs by DEFAULT (skipped only with --fast);
  * JS from passive recon AND the active crawl are merged before JS-Oracle;
  * --offline makes JS-Oracle offline and writes offline_report.md, no advisor.

All external modules are mocked, so these tests run nothing and cost nothing.
"""

import argparse
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import cli.main as clim


def _args(**kw):
    ns = argparse.Namespace(command="full", target="example.com",
                            offline=True, fast=False)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


_RECON = {"events": [], "status": "ok", "fallback_used": False,
          "live_hosts": ["https://example.com"],
          "js_files": ["https://example.com/a.js"],
          "historical_urls": ["https://example.com/old"]}
_FP = {"events": [], "results": [{"host": "https://example.com"}]}
_ACTIVE = {"events": [], "crawl": {"count": 2, "js_files": ["https://example.com/b.js"]},
           "fuzz": {"count": 0}, "params": {"count": 0}, "ports": {"count": 0},
           "nuclei": {"count": 0}}


class _JS:
    """JSOracle stand-in that records what it was handed."""
    captured: dict = {}

    def __init__(self, output_dir):
        pass

    def execute(self, target, urls, offline=False):
        _JS.captured = {"urls": list(urls), "offline": offline}
        return {"events": [], "endpoints": [], "api_keys": []}


def _run_pipeline(out: Path, args) -> None:
    recon_m = mock.MagicMock();  recon_m.return_value.execute.return_value = _RECON
    fp_m = mock.MagicMock();     fp_m.return_value.execute.return_value = _FP
    active_m = mock.MagicMock(); active_m.return_value.execute.return_value = _ACTIVE
    with mock.patch.object(clim, "ReconModule", recon_m), \
         mock.patch.object(clim, "FingerprintModule", fp_m), \
         mock.patch.object(clim, "ActiveReconModule", active_m), \
         mock.patch.object(clim, "JSOracle", _JS), \
         mock.patch.object(clim.DependencyChecker, "verify", return_value=True), \
         mock.patch("core.offline_report.build_report", return_value="# report\n"):
        app = clim.BountyHub(args)
        app.output_dir = out
        app._full_pipeline()
    _run_pipeline.active_m = active_m   # expose for assertions


class TestFullPipeline(unittest.TestCase):
    def setUp(self):
        _JS.captured = {}

    def test_deep_default_runs_active_recon_and_merges_js(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)
            _run_pipeline(out, _args(offline=True, fast=False))
            _run_pipeline.active_m.assert_called_once()          # active recon ran by default
            urls = _JS.captured["urls"]
            self.assertIn("https://example.com/a.js", urls)       # passive-recon JS
            self.assertIn("https://example.com/b.js", urls)       # active-crawl JS merged in
            self.assertTrue(_JS.captured["offline"])              # offline propagated
            self.assertTrue((out / "offline_report.md").exists())  # $0 report written

    def test_fast_skips_active_recon(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)
            _run_pipeline(out, _args(offline=True, fast=True))
            _run_pipeline.active_m.assert_not_called()           # --fast => no active recon
            urls = _JS.captured["urls"]
            self.assertIn("https://example.com/a.js", urls)
            self.assertNotIn("https://example.com/b.js", urls)   # no crawl JS without active recon


if __name__ == "__main__":
    unittest.main(verbosity=2)
