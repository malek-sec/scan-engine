"""
Regression tests for Pattern 1a — tool/binary name collisions.

Background
----------
/usr/bin/httpx is Debian's python3-httpx package: an unrelated HTTP-client CLI
that merely shares a filename with ProjectDiscovery's httpx. The recon layer
learned to reject it, but DependencyChecker.verify() still used a blind
shutil.which() and printed a green "httpx -> /usr/bin/httpx" for the exact
binary recon refuses — a pre-flight that greenlights a scan which cannot work.

These tests fail if any tool is ever accepted on filename alone again.
"""

import os
import re
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core import (DependencyChecker, TOOL_SIGNATURES, identify_tool,
                  resolve_tool)


PD_BANNER = "projectdiscovery.io\n[INF] Current Version: v1.9.0"
IMPOSTOR  = "Usage: httpx [OPTIONS] URL\n\nError: No such option: -e"


def _completed(rc=0, out="", err=""):
    return subprocess.CompletedProcess(args=["t"], returncode=rc,
                                       stdout=out, stderr=err)


class TestToolSignatures(unittest.TestCase):

    def test_every_shelled_out_tool_has_a_signature(self):
        """
        Any tool the project executes must be identifiable. If a new tool is
        added without a signature it can be impersonated silently.
        """
        for tool in ("httpx", "subfinder", "nmap", "whatweb", "openssl"):
            self.assertIn(tool, TOOL_SIGNATURES, f"{tool} has no signature")

    def test_signatures_are_compiled_regexes(self):
        for tool, (argv, pattern) in TOOL_SIGNATURES.items():
            self.assertIsInstance(argv, list, tool)
            self.assertTrue(hasattr(pattern, "search"), tool)


class TestIdentifyTool(unittest.TestCase):

    def test_real_httpx_accepted(self):
        with mock.patch("core.subprocess.run",
                        return_value=_completed(0, err=PD_BANNER)):
            ok, detail = identify_tool("httpx", "/anywhere/httpx")
        self.assertTrue(ok)
        self.assertIn("1.9.0", detail)

    def test_python3_httpx_impostor_rejected(self):
        """THE regression: filename matches, tool does not."""
        with mock.patch("core.subprocess.run",
                        return_value=_completed(2, err=IMPOSTOR)):
            ok, detail = identify_tool("httpx", "/usr/bin/httpx")
        self.assertFalse(ok)
        self.assertIn("impostor", detail)

    def test_wrong_tool_under_right_name_rejected(self):
        """A binary that exits 0 but prints nothing recognisable is refused."""
        with mock.patch("core.subprocess.run",
                        return_value=_completed(0, out="hello world")):
            ok, _ = identify_tool("nmap", "/usr/bin/nmap")
        self.assertFalse(ok)

    def test_nmap_signature_matches_real_output(self):
        with mock.patch("core.subprocess.run",
                        return_value=_completed(0, out="Nmap version 7.98 ( https://nmap.org )")):
            ok, detail = identify_tool("nmap", "/usr/bin/nmap")
        self.assertTrue(ok)
        self.assertIn("7.98", detail)

    def test_whatweb_signature_matches_real_output(self):
        with mock.patch("core.subprocess.run",
                        return_value=_completed(0, out="WhatWeb version 0.6.3 ( https://... )")):
            self.assertTrue(identify_tool("whatweb", "/usr/bin/whatweb")[0])

    def test_openssl_signature_matches_real_output(self):
        with mock.patch("core.subprocess.run",
                        return_value=_completed(0, out="OpenSSL 3.5.4 30 Sep 2025")):
            self.assertTrue(identify_tool("openssl", "/usr/bin/openssl")[0])

    def test_missing_binary_is_not_accepted(self):
        with mock.patch("core.subprocess.run", side_effect=FileNotFoundError):
            ok, detail = identify_tool("nmap", "/nope/nmap")
        self.assertFalse(ok)
        self.assertEqual(detail, "not present")

    def test_unregistered_tool_is_flagged_unverified_not_failed(self):
        """Absence of a signature must not masquerade as a failure."""
        ok, detail = identify_tool("some-new-tool", "/usr/bin/whatever")
        self.assertTrue(ok)
        self.assertIn("unverified", detail)


class TestPreflightAgreesWithRecon(unittest.TestCase):
    """
    DependencyChecker and the recon layer must never disagree about httpx.
    """

    def test_httpx_resolution_delegates_to_recon_resolver(self):
        with mock.patch("core.recon._resolve_httpx",
                        return_value=("/go/bin/httpx", None)) as resolver:
            path, reason = resolve_tool("httpx")
        resolver.assert_called_once()
        self.assertEqual(path, "/go/bin/httpx")
        self.assertIsNone(reason)

    def test_preflight_fails_when_recon_rejects_httpx(self):
        """
        The contradiction: pre-flight green while recon refuses the binary.
        """
        with mock.patch("core.recon._resolve_httpx",
                        return_value=(None, "python3-httpx impostor")), \
             mock.patch("core.Logger"):
            ok = DependencyChecker.verify(["httpx"], "Recon")
        self.assertFalse(ok, "pre-flight greenlit a binary recon rejects")

    def test_preflight_rejects_impostor_even_when_on_path(self):
        """shutil.which() finding something is NOT sufficient."""
        with mock.patch("core.shutil.which", return_value="/usr/bin/nmap"), \
             mock.patch("core.subprocess.run",
                        return_value=_completed(2, err=IMPOSTOR)), \
             mock.patch("core.Logger"):
            ok = DependencyChecker.verify(["nmap"], "Fingerprint")
        self.assertFalse(ok)

    def test_tool_exists_requires_validation(self):
        with mock.patch("core.shutil.which", return_value="/usr/bin/nmap"), \
             mock.patch("core.subprocess.run",
                        return_value=_completed(0, out="not nmap at all")):
            self.assertFalse(DependencyChecker.tool_exists("nmap"))

    def test_tool_exists_true_for_validated_tool(self):
        with mock.patch("core.shutil.which", return_value="/usr/bin/nmap"), \
             mock.patch("core.subprocess.run",
                        return_value=_completed(0, out="Nmap version 7.98")):
            self.assertTrue(DependencyChecker.tool_exists("nmap"))

    def test_missing_from_path_is_reported(self):
        with mock.patch("core.shutil.which", return_value=None):
            path, reason = resolve_tool("nmap")
        self.assertIsNone(path)
        self.assertIn("not found", reason)


class TestSubfinderResolvedBySignature(unittest.TestCase):
    """subfinder must not be executed by bare name off $PATH."""

    def test_run_subfinder_uses_resolved_path(self):
        import tempfile
        from pathlib import Path
        from core.recon import ReconModule

        with tempfile.TemporaryDirectory() as tmp:
            mod = ReconModule("example.com", Path(tmp))
            captured = {}

            def fake_run(cmd, **kw):
                captured["cmd"] = cmd
                mod.file_subs.write_text("a.example.com\n")
                return _completed(0)

            with mock.patch("core.resolve_tool",
                            return_value=("/validated/subfinder", None)), \
                 mock.patch("core.recon.subprocess.run", side_effect=fake_run):
                mod._run_subfinder([])

        self.assertEqual(captured["cmd"][0], "/validated/subfinder",
                         "subfinder was invoked by bare name off $PATH")

    def test_unusable_subfinder_falls_back_without_crashing(self):
        import tempfile
        from pathlib import Path
        from core.recon import ReconModule

        with tempfile.TemporaryDirectory() as tmp:
            mod = ReconModule("example.com", Path(tmp))
            events = []
            with mock.patch("core.resolve_tool",
                            return_value=(None, "impostor")):
                subs = mod._run_subfinder(events)
        self.assertEqual(subs, ["example.com"])
        self.assertTrue(any("unusable" in e.get("msg", "") for e in events))


class TestRequirementsCoverEveryImport(unittest.TestCase):
    """
    Pattern 1b — every third-party import must be pinned under its ACTUAL
    distribution name. `markdown` resolves to the "Markdown" distribution, NOT
    to "markdown-it-py"; pinning only the latter 500s a clean deploy.
    """

    REQUIREMENTS = os.path.join(
        os.path.dirname(__file__), "..", "..", "BountyHub", "requirements.txt")

    # Guarded, optional, CLI-only. Justified exception — see the audit report.
    OPTIONAL = {"google"}

    def _pinned(self):
        pins = set()
        with open(self.REQUIREMENTS) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    name = line.split("==")[0].split(">=")[0].split("[")[0]
                    pins.add(name.strip().lower().replace("_", "-"))
        return pins

    @unittest.skipUnless(os.path.exists(REQUIREMENTS), "requirements.txt absent")
    def test_markdown_pinned_under_real_distribution_name(self):
        pins = self._pinned()
        self.assertIn("markdown", pins,
                      "the 'markdown' import needs the 'Markdown' distribution; "
                      "'markdown-it-py' is a DIFFERENT package")

    @unittest.skipUnless(os.path.exists(REQUIREMENTS), "requirements.txt absent")
    def test_anthropic_pinned(self):
        self.assertIn("anthropic", self._pinned())

    @unittest.skipUnless(os.path.exists(REQUIREMENTS), "requirements.txt absent")
    def test_no_unpinned_third_party_imports(self):
        """Scan real source and diff every import against requirements.txt."""
        import ast
        import pathlib
        from importlib.metadata import packages_distributions

        roots = [pathlib.Path(__file__).resolve().parents[2] / "BountyHub",
                 pathlib.Path(__file__).resolve().parents[1]]
        stdlib = set(sys.stdlib_module_names)
        local = {"core", "cli", "routes", "models", "services", "extensions",
                 "config", "app", "tests", "migrations"}
        p2d = packages_distributions()
        pins = self._pinned()

        missing = {}
        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*.py"):
                sp = str(path)
                if any(x in sp for x in ("/venv/", "/.venv/", "__pycache__",
                                         ".bak", "/tests/")):
                    continue
                try:
                    tree = ast.parse(path.read_text(encoding="utf-8",
                                                    errors="replace"))
                except SyntaxError:
                    continue
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        names = [a.name.split(".")[0] for a in node.names]
                    elif isinstance(node, ast.ImportFrom) and not node.level:
                        names = [(node.module or "").split(".")[0]]
                    else:
                        continue
                    for mod in names:
                        if (not mod or mod in stdlib or mod in local
                                or mod in self.OPTIONAL):
                            continue
                        dists = p2d.get(mod)
                        if not dists:
                            continue
                        if not any(d.lower().replace("_", "-") in pins
                                   for d in dists):
                            missing[mod] = (dists[0], f"{path}:{node.lineno}")

        self.assertEqual(missing, {},
                         f"imports not pinned in requirements.txt: {missing}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
