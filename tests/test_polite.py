"""Tests for the --polite preset: it only lowers rates, and never overrides an
explicit operator env var."""

import json
import os
import subprocess
import sys
from pathlib import Path

from cli.main import _POLITE_ENV

_ROOT = Path(__file__).resolve().parent.parent
_ATTRS = {k: k.replace("BOUNTYHUB_", "") for k in _POLITE_ENV}


def _config_values(extra_env: dict) -> dict:
    """Import Config in a clean subprocess and read the rate attributes."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("BOUNTYHUB_")}
    env["PYTHONPATH"] = str(_ROOT)
    env.update(extra_env)
    code = (
        "import json; from core import Config; "
        f"print(json.dumps({{a: getattr(Config, a) for a in {list(_ATTRS.values())!r}}}))"
    )
    out = subprocess.check_output([sys.executable, "-c", code], env=env, cwd=str(_ROOT))
    return json.loads(out.decode())


def test_polite_only_lowers_never_raises():
    defaults = _config_values({})
    polite = _config_values(dict(_POLITE_ENV))
    for env_key, attr in _ATTRS.items():
        assert polite[attr] <= defaults[attr], f"{attr}: polite {polite[attr]} > default {defaults[attr]}"
        assert polite[attr] == int(_POLITE_ENV[env_key])


def test_explicit_env_overrides_polite():
    # An operator who exports an even stricter value keeps it (setdefault semantics).
    polite_and_user = dict(_POLITE_ENV)
    polite_and_user["BOUNTYHUB_ACTIVE_FFUF_RATE"] = "3"  # user-exported, stricter
    vals = _config_values(polite_and_user)
    assert vals["ACTIVE_FFUF_RATE"] == 3
