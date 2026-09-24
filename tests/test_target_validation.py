"""Tests for target validation (argument-injection guard)."""

import pytest

from core.recon import is_valid_target, ReconModule


def test_accepts_normal_targets():
    assert is_valid_target("example.com")
    assert is_valid_target("sub.example.com")
    assert is_valid_target("https://example.com/path")   # scheme/path stripped
    assert is_valid_target("192.168.1.1")
    assert is_valid_target("EXAMPLE.COM")


def test_rejects_argument_injection_and_junk():
    assert not is_valid_target("-oN")            # leading dash -> tool flag
    assert not is_valid_target("--data-binary")
    assert not is_valid_target("")
    assert not is_valid_target("   ")
    assert not is_valid_target("a b.com")        # space
    assert not is_valid_target("example.com;id") # shell metachar
    assert not is_valid_target("$(whoami).com")
    assert not is_valid_target("a`id`.com")


def test_recon_module_rejects_bad_target(tmp_path):
    with pytest.raises(ValueError, match="Invalid target"):
        ReconModule("--output", tmp_path)
