"""
Regression tests for the httpx live-host detection contract in core.recon.

Background — the bug these tests lock shut
------------------------------------------
`httpx` on Debian resolves to /usr/bin/httpx, the python3-httpx package's
unrelated HTTP-client CLI. It rejects `-l` and exits 2 without writing an
output file. The original code called subprocess.run() and discarded the
return code, so a hard tool crash was indistinguishable from "the target has
no live hosts" — and the zero-host fallback then:

  * reported "0 live hosts — aggressive WAF or network filtering suspected",
    presenting a guess as a diagnosis;
  * wrote the RAW, SCHEME-LESS subdomain list to live_hosts.txt and forwarded
    it to Module 2, where whatweb silently rejected every entry for having
    "no http(s) scheme".

A broken run therefore looked like a successful one. These tests fail if that
behaviour is reintroduced in any form.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core import Config
from core.recon import ReconModule, _identify_httpx, _resolve_httpx, normalize_target


FAKE_HTTPX = "/fake/bin/httpx"


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=["httpx"], returncode=returncode, stdout=stdout, stderr=stderr)


class _ReconHttpxCase(unittest.TestCase):
    """Shared fixture: a ReconModule over a temp dir with one subdomain staged."""

    SUBDOMAINS = ["example.com"]

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out  = Path(self._tmp.name)
        self.mod  = ReconModule("example.com", self.out)
        # _run_httpx consumes the file subfinder would have written.
        self.mod.file_subs.write_text("\n".join(self.SUBDOMAINS) + "\n")
        self.addCleanup(self._tmp.cleanup)

    def run_httpx(self, proc_result, write_json=None):
        """
        Drive _run_httpx with a stubbed subprocess and a stubbed resolver.

        proc_result : CompletedProcess returned by the patched subprocess.run,
                      or an exception instance to raise instead.
        write_json  : text to write to httpx_out.json as httpx would, or None
                      to leave the file absent.
        """
        json_out = self.out / "httpx_out.json"

        def fake_run(cmd, **kwargs):
            self.captured_cmd = cmd
            if write_json is not None:
                json_out.write_text(write_json)
            if isinstance(proc_result, BaseException):
                raise proc_result
            return proc_result

        self.captured_cmd = None
        events = []
        with mock.patch("core.recon._resolve_httpx", return_value=(FAKE_HTTPX, None)), \
             mock.patch("core.recon.subprocess.run", side_effect=fake_run):
            result = self.mod._run_httpx(list(self.SUBDOMAINS), events)
        self.events = events
        return result

    # ── helpers ───────────────────────────────────────────────────────────
    def event_text(self):
        return " ".join(e.get("msg", "") for e in self.events).lower()

    def live_hosts_file(self):
        f = self.out / Config.FILE_LIVE_HOSTS
        return f.read_text() if f.exists() else ""


class TestHttpxToolFailureIsNeverDisguised(_ReconHttpxCase):
    """
    THE core regression: a non-zero httpx exit must halt the pipeline loudly.

    Every assertion here fails under the old swallow-the-return-code code,
    which returned (subdomains, {}, True, <no error>) and logged a WAF guess.
    """

    def setUp(self):
        super().setUp()
        # Exactly what the python3-httpx impostor does: exit 2, no output file.
        self.live, self.shots, self.fallback, self.probe_error = self.run_httpx(
            _completed(returncode=2,
                       stderr="Usage: httpx [OPTIONS] URL\nError: No such option: -l"),
            write_json=None,
        )

    def test_probe_error_is_set(self):
        """httpx_failed must be signalled, not swallowed."""
        self.assertIsNotNone(
            self.probe_error,
            "non-zero httpx exit was swallowed — the tool error is invisible")
        self.assertIn("2", self.probe_error)

    def test_no_hosts_are_forwarded(self):
        """No '0 hosts' style result: nothing at all may reach Module 2."""
        self.assertEqual(self.live, [], "hosts forwarded despite a tool failure")
        self.assertEqual(self.shots, {})

    def test_no_bare_domain_live_hosts_file(self):
        """
        live_hosts.txt must not contain the raw scheme-less subdomain list.

        This is the exact artefact that made whatweb skip every host with
        "has no http(s) scheme".
        """
        content = self.live_hosts_file()
        self.assertNotIn("example.com", content,
                         "raw subdomain list was written to live_hosts.txt")
        self.assertEqual(content.strip(), "")

    def test_no_waf_claim(self):
        """A tool crash must never be labelled a WAF."""
        text = self.event_text()
        self.assertNotIn("waf", text)
        self.assertNotIn("filtering suspected", text)

    def test_failure_is_reported_as_tool_error(self):
        text = self.event_text()
        self.assertTrue(
            any(k in text for k in ("tool error", "failed")),
            "the failure was not clearly reported as a tool error")

    def test_fallback_flag_not_set(self):
        """'fallback_used' must not be used to paper over a crash."""
        self.assertFalse(self.fallback)


class TestHttpxCleanRunWithZeroHosts(_ReconHttpxCase):
    """A correct httpx run that finds nothing is a real answer, not an error."""

    def setUp(self):
        super().setUp()
        # httpx exits 0 and creates an empty output file for a dead target.
        self.live, self.shots, self.fallback, self.probe_error = self.run_httpx(
            _completed(returncode=0), write_json="")

    def test_not_flagged_as_tool_error(self):
        self.assertIsNone(self.probe_error)

    def test_reports_dead_not_waf(self):
        text = self.event_text()
        self.assertNotIn("waf", text)
        self.assertIn("inconclusive", text)

    def test_no_hosts_and_no_bare_domains(self):
        self.assertEqual(self.live, [])
        self.assertNotIn("example.com", self.live_hosts_file())


class TestHttpxTimeoutIsAToolError(_ReconHttpxCase):
    """A timeout with no results is a tooling failure, not a dead target."""

    def test_timeout_sets_probe_error(self):
        live, _shots, _fb, probe_error = self.run_httpx(
            subprocess.TimeoutExpired(cmd="httpx", timeout=600), write_json=None)
        self.assertIsNotNone(probe_error)
        self.assertEqual(live, [])
        self.assertNotIn("waf", self.event_text())


class TestHttpxSuccessParsing(_ReconHttpxCase):
    """Positive path: valid httpx JSON is parsed into scheme-prefixed hosts."""

    SUBDOMAINS = ["example.com", "api.example.com"]

    def setUp(self):
        super().setUp()
        lines = "\n".join(json.dumps(o) for o in (
            {"url": "https://example.com", "input": "example.com",
             "status_code": 200},
            {"url": "http://api.example.com", "input": "api.example.com",
             "status_code": 403},
            # No "url" key — httpx fell back to the input host only.
            {"input": "legacy.example.com", "status_code": 200},
        ))
        self.live, self.shots, self.fallback, self.probe_error = self.run_httpx(
            _completed(returncode=0), write_json=lines + "\n")

    def test_hosts_parsed(self):
        self.assertEqual(
            self.live,
            ["https://example.com", "http://api.example.com",
             "https://legacy.example.com"])

    def test_no_error_signalled(self):
        self.assertIsNone(self.probe_error)
        self.assertFalse(self.fallback)

    def test_every_host_has_a_scheme(self):
        """Module 2 (whatweb/TLS) rejects anything without an explicit scheme."""
        for host in self.live:
            self.assertRegex(host, r"^https?://")

    def test_explicit_http_scheme_is_preserved(self):
        """https must not be forced onto a host httpx reported as plain http."""
        self.assertIn("http://api.example.com", self.live)

    def test_live_hosts_file_written_with_schemes(self):
        content = self.live_hosts_file()
        self.assertIn("https://example.com", content)
        self.assertNotIn("\nexample.com\n", "\n" + content)


class TestExecuteEnvelopeSignals(unittest.TestCase):
    """execute() must expose a branchable signal distinguishing the outcomes."""

    def _execute_with(self, run_httpx_result):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        mod = ReconModule("example.com", Path(tmp.name))
        with mock.patch.object(ReconModule, "_run_subfinder",
                               return_value=["example.com"]), \
             mock.patch.object(ReconModule, "_run_httpx",
                               return_value=run_httpx_result), \
             mock.patch.object(ReconModule, "_collect_http_responses", return_value=[]), \
             mock.patch.object(ReconModule, "_query_crtsh", return_value=[]), \
             mock.patch.object(ReconModule, "_fetch_historical_urls", return_value=[]), \
             mock.patch.object(ReconModule, "_discover_js_files", return_value=[]):
            return mod.execute()

    def test_tool_error_gives_nonzero_signal(self):
        r = self._execute_with(([], {}, False, "httpx exited 2 — boom"))
        self.assertEqual(r["status"], "error")
        self.assertEqual(r["exit_signal"], 2)
        self.assertTrue(r["degraded"])
        self.assertEqual(r["error_reason"], "httpx exited 2 — boom")
        self.assertEqual(r["live_hosts"], [])

    def test_dead_target_is_zero_signal_and_not_an_error(self):
        r = self._execute_with(([], {}, False, None))
        self.assertEqual(r["status"], "empty")
        self.assertEqual(r["exit_signal"], 0)
        self.assertFalse(r["degraded"])
        self.assertIsNone(r["error_reason"])

    def test_success_is_ok(self):
        r = self._execute_with((["https://example.com"], {}, False, None))
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["exit_signal"], 0)
        self.assertFalse(r["degraded"])

    def test_error_and_success_signals_differ(self):
        """The caller must be able to branch; both must not look alike."""
        err = self._execute_with(([], {}, False, "broken"))
        ok  = self._execute_with((["https://example.com"], {}, False, None))
        self.assertNotEqual(err["exit_signal"], ok["exit_signal"])


class TestRoEFlagsComeFromConfig(_ReconHttpxCase):
    """Concurrency/rate knobs must be live config, not hardcoded literals."""

    def _flag_value(self, cmd, flag):
        return cmd[cmd.index(flag) + 1]

    def test_threads_and_rl_track_config(self):
        with mock.patch.object(Config, "HTTPX_THREADS", 17), \
             mock.patch.object(Config, "HTTPX_RL", 42), \
             mock.patch.object(Config, "HTTPX_TIMEOUT", 7):
            self.run_httpx(_completed(returncode=0), write_json="")
        cmd = self.captured_cmd
        self.assertEqual(self._flag_value(cmd, "-threads"), "17")
        self.assertEqual(self._flag_value(cmd, "-rl"), "42")
        self.assertEqual(self._flag_value(cmd, "-timeout"), "7")

    def test_removed_concurrency_flag_is_not_passed(self):
        """
        httpx v1.9 deleted -c; passing it aborts the run with
        'flag provided but not defined: -c'.
        """
        self.run_httpx(_completed(returncode=0), write_json="")
        self.assertNotIn("-c", self.captured_cmd)
        self.assertFalse(hasattr(Config, "HTTPX_CONCURRENCY"),
                         "dead HTTPX_CONCURRENCY knob is back")

    def test_resolved_binary_is_used_not_bare_name(self):
        """The command must invoke the validated absolute path, not 'httpx'."""
        self.run_httpx(_completed(returncode=0), write_json="")
        self.assertEqual(self.captured_cmd[0], FAKE_HTTPX)


class TestResolverRejectsImpostors(unittest.TestCase):
    """_resolve_httpx must never return an unvalidated binary."""

    PD_BANNER = "projectdiscovery.io\n[INF] Current Version: v1.9.0"
    IMPOSTOR  = "Usage: httpx [OPTIONS] URL\n\nError: No such option: -e"

    def test_identifies_real_httpx(self):
        with mock.patch("core.recon.subprocess.run",
                        return_value=_completed(0, stderr=self.PD_BANNER)):
            ok, detail = _identify_httpx("/anywhere/httpx")
        self.assertTrue(ok)
        self.assertIn("v1.9.0", detail)

    def test_identifies_python3_httpx_impostor(self):
        with mock.patch("core.recon.subprocess.run",
                        return_value=_completed(2, stderr=self.IMPOSTOR)):
            ok, detail = _identify_httpx("/usr/bin/httpx")
        self.assertFalse(ok)
        self.assertIn("impostor", detail)

    def test_zero_exit_without_pd_signature_is_rejected(self):
        """A binary that exits 0 but isn't PD httpx must still be refused."""
        with mock.patch("core.recon.subprocess.run",
                        return_value=_completed(0, stdout="hello world")):
            ok, _ = _identify_httpx("/some/other/httpx")
        self.assertFalse(ok)

    def test_configured_binary_that_is_an_impostor_fails_loud(self):
        """An explicit HTTPX_BINARY must never silently fall back to search."""
        with mock.patch.object(Config, "HTTPX_BINARY", "/usr/bin/httpx"), \
             mock.patch("core.recon.subprocess.run",
                        return_value=_completed(2, stderr=self.IMPOSTOR)), \
             mock.patch("core.recon._httpx_candidates",
                        side_effect=AssertionError(
                            "fell back to auto-detection after an explicit "
                            "HTTPX_BINARY was rejected")):
            path, reason = _resolve_httpx()
        self.assertIsNone(path)
        self.assertIn("HTTPX_BINARY", reason)
        self.assertIn("impostor", reason)

    def test_configured_valid_binary_is_used(self):
        with mock.patch.object(Config, "HTTPX_BINARY", "/opt/httpx"), \
             mock.patch("core.recon.subprocess.run",
                        return_value=_completed(0, stderr=self.PD_BANNER)):
            path, reason = _resolve_httpx()
        self.assertEqual(path, "/opt/httpx")
        self.assertIsNone(reason)

    def test_search_skips_impostor_and_finds_real_one(self):
        """PATH order must not decide the winner — validation does."""
        def fake_run(cmd, **kwargs):
            if cmd[0] == "/usr/bin/httpx":
                return _completed(2, stderr=self.IMPOSTOR)
            if cmd[0] == "/home/u/go/bin/httpx":
                return _completed(0, stderr=self.PD_BANNER)
            raise FileNotFoundError(cmd[0])

        with mock.patch.object(Config, "HTTPX_BINARY", None), \
             mock.patch("core.recon._httpx_candidates",
                        return_value=["/usr/bin/httpx", "/home/u/go/bin/httpx"]), \
             mock.patch("core.recon.subprocess.run", side_effect=fake_run):
            path, reason = _resolve_httpx()
        self.assertEqual(path, "/home/u/go/bin/httpx")
        self.assertIsNone(reason)

    def test_no_valid_binary_fails_loud(self):
        with mock.patch.object(Config, "HTTPX_BINARY", None), \
             mock.patch("core.recon._httpx_candidates",
                        return_value=["/usr/bin/httpx"]), \
             mock.patch("core.recon.subprocess.run",
                        return_value=_completed(2, stderr=self.IMPOSTOR)):
            path, reason = _resolve_httpx()
        self.assertIsNone(path)
        self.assertIn("no valid projectdiscovery/httpx", reason)
        self.assertIn("BOUNTYHUB_HTTPX_BINARY", reason)

    def test_resolver_failure_halts_run_httpx(self):
        """A resolver failure must produce a probe_error, not an empty result."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        mod = ReconModule("example.com", Path(tmp.name))
        mod.file_subs.write_text("example.com\n")
        events = []
        with mock.patch("core.recon._resolve_httpx",
                        return_value=(None, "no valid httpx")):
            live, shots, fallback, probe_error = mod._run_httpx(["example.com"], events)
        self.assertIsNotNone(probe_error)
        self.assertEqual(live, [])
        text = " ".join(e.get("msg", "") for e in events).lower()
        self.assertNotIn("waf", text)


class TestNormalizeTargetBoundary(unittest.TestCase):
    """The scheme contract downstream tools depend on."""

    def test_bare_form_for_subfinder_and_httpx(self):
        self.assertEqual(normalize_target("https://a.example.com/x?y=1",
                                          with_scheme=False), "a.example.com")

    def test_scheme_added_for_whatweb(self):
        self.assertEqual(normalize_target("example.com"), "https://example.com")

    def test_existing_scheme_preserved(self):
        self.assertEqual(normalize_target("http://example.com"),
                         "http://example.com")

    def test_empty_input_is_filtered(self):
        self.assertEqual(normalize_target("   "), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
