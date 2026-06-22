"""The scripted wedge demo runs end-to-end (SEC-13, Phase 3 success criterion 5)."""

import subprocess
import sys
from pathlib import Path

import pytest

from _opa import find_opa

pytestmark = pytest.mark.skipif(find_opa() is None, reason="no OPA binary")

REPO = Path(__file__).resolve().parents[2]


def test_wedge_demo_script_runs_and_denies_the_sequence():
    proc = subprocess.run(
        [sys.executable, str(REPO / "examples" / "wedge_demo.py")],
        capture_output=True, text=True, timeout=300, cwd=str(REPO),
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "outcome: allow" in out          # the individually-permitted steps
    assert "outcome: deny" in out           # the forbidden sequence
    assert "3.5" in out and "remediation:" in out
    assert "audit-chain tail" in out and "hash=" in out   # the evidence leg
