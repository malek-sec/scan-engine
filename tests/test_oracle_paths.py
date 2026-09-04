"""
Tests for portable JS-Oracle path resolution (core.js_oracle).

The old code hardcoded /home/kali/js-oracle, so Module 4 silently self-skipped
on every machine that was not that one Kali box. Resolution is now: explicit env
override -> sibling js-oracle/ next to this scan-engine checkout.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.js_oracle import _resolve_oracle_root, _resolve_oracle_python


class TestOraclePaths(unittest.TestCase):

    def test_env_override_wins(self):
        with mock.patch.dict(os.environ, {"JS_ORACLE_ROOT": "/opt/js-oracle"}):
            self.assertEqual(_resolve_oracle_root(), Path("/opt/js-oracle"))

    def test_bountyhub_prefixed_alias_is_honoured(self):
        env = {k: v for k, v in os.environ.items() if k != "JS_ORACLE_ROOT"}
        env["BOUNTYHUB_JS_ORACLE_ROOT"] = "/srv/jso"
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(_resolve_oracle_root(), Path("/srv/jso"))

    def test_default_is_the_sibling_js_oracle_dir(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("JS_ORACLE_ROOT", "BOUNTYHUB_JS_ORACLE_ROOT")}
        with mock.patch.dict(os.environ, env, clear=True):
            root = _resolve_oracle_root()
        self.assertEqual(root.name, "js-oracle")
        # …/Bug-Bounty/scan-engine + …/Bug-Bounty/js-oracle are siblings; on the
        # canonical Kali box /home/kali/scan-engine + /home/kali/js-oracle too.
        self.assertEqual(root.parent, Path(__file__).resolve().parents[2])

    def test_blank_override_falls_back_to_default(self):
        with mock.patch.dict(os.environ, {"JS_ORACLE_ROOT": "   "}):
            self.assertEqual(_resolve_oracle_root().name, "js-oracle")

    def test_python_leaf_matches_the_host_os(self):
        py = _resolve_oracle_python(Path("/x"))
        self.assertIn(".venv", py.parts)
        if os.name == "nt":
            self.assertEqual(py.name, "python.exe")
            self.assertIn("Scripts", py.parts)
        else:
            self.assertEqual(py.name, "python")
            self.assertIn("bin", py.parts)


if __name__ == "__main__":
    unittest.main(verbosity=2)
