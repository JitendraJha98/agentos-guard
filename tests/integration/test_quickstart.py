"""SDK-05 zero-infra quickstart tests.

The quickstart ships a COMMITTED demo `policy.wasm` (built once at authoring time via the vendored
OPA CLI) plus a `demo_constitution.yaml`, and at run time loads the committed wasm + derives all other
policy metadata in-process via the pure-Python compiler — NO OPA CLI at run time. These tests prove:
  - the package data ships and loads (Task 1),
  - `run()` executes the full governed loop with `build_wasm` monkeypatched to raise (Task 2 — no CLI),
  - committed-vs-rebuilt behavioral parity when an OPA CLI is present (Task 3 — drift guard).
"""

from __future__ import annotations

from importlib.resources import files

from agentos_constitution import load_constitution


def test_quickstart_package_data_ships() -> None:
    """The committed policy.wasm + demo_constitution.yaml ship as importable package data."""
    pkg = files("agentos_sdk.quickstart")
    wasm = pkg / "policy.wasm"
    assert wasm.is_file()
    assert len(wasm.read_bytes()) > 0
    constitution = load_constitution(str(pkg / "demo_constitution.yaml"))
    assert constitution.principles  # the demo constitution parses + has principles
