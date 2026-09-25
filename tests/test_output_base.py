"""OUTPUT_BASE anchors results to the project root regardless of the cwd."""

import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _output_base(extra_env: dict) -> str:
    env = {k: v for k, v in os.environ.items() if k != "BOUNTYHUB_OUTPUT_BASE"}
    env["PYTHONPATH"] = str(_ROOT)
    env.update(extra_env)
    # cwd=/tmp on purpose: proves the path does NOT depend on where you run from.
    out = subprocess.check_output(
        [sys.executable, "-c", "from core import Config; print(Config.OUTPUT_BASE)"],
        env=env, cwd="/tmp",
    )
    return out.decode().strip()


def test_output_base_anchored_to_project_root():
    val = _output_base({})
    assert val == str(_ROOT / "bountyhub_output")
    assert os.path.isabs(val)


def test_output_base_env_override_wins():
    assert _output_base({"BOUNTYHUB_OUTPUT_BASE": "/tmp/custom_out"}) == "/tmp/custom_out"
