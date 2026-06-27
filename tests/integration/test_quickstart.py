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
from pathlib import Path
from tempfile import mkdtemp

import pytest

from agentos_constitution import load_constitution
from agentos_contract import Outcome


def test_quickstart_package_data_ships() -> None:
    """The committed policy.wasm + demo_constitution.yaml ship as importable package data."""
    pkg = files("agentos_sdk.quickstart")
    wasm = pkg / "policy.wasm"
    assert wasm.is_file()
    assert len(wasm.read_bytes()) > 0
    constitution = load_constitution(str(pkg / "demo_constitution.yaml"))
    assert constitution.principles  # the demo constitution parses + has principles


def test_quickstart_run_governs_allow_and_deny_with_no_opa_cli(monkeypatch, tmp_path) -> None:
    """run() drives the full governed loop on the COMMITTED wasm — proven CLI-free.

    The committed-wasm decision means run() must never shell out to OPA. We monkeypatch
    `agentos_constitution.wasm.build_wasm` to raise: if run() touched the CLI build path it would
    blow up here. It does not — it loads the committed wasm and derives the rest in-process.
    """
    import agentos_constitution.wasm as wasm_mod

    def _no_cli(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("quickstart must NOT invoke the OPA CLI build path at run time")

    monkeypatch.setattr(wasm_mod, "build_wasm", _no_cli)

    from agentos_sdk.quickstart import run

    result = run(db_path=str(tmp_path / "quickstart.db"))

    assert result.allow_outcome is Outcome.allow
    assert result.deny_outcome is Outcome.deny
    assert result.audit_records == 2  # one allow + one deny, hash-chained + signed
    assert result.api_token  # a dev API token is surfaced


def _policy_input(host: str) -> dict:
    """A minimal valid tool_call policy-input doc (the egress principle keys on egress.host)."""
    return {
        "type": "tool_call",
        "target": "http_get",
        "intent": {"class": ""},
        "guardrails": {},
        "sequence": {"matched_refs": []},
        "egress": {"host": host},
    }


def test_quickstart_wasm_drift_guard_behavioral_parity() -> None:
    """Committed wasm vs. wasm REBUILT from the shipped source must behave identically (SDK-05).

    The committed binary is a drift risk: it could lag the source it claims to compile. When an OPA
    CLI is available we rebuild from `demo_constitution.yaml` and assert BEHAVIORAL equivalence —
    same matched-effect / no_match on the demo allow + deny inputs AND the same constitution_version.
    We do NOT byte-compare the wasm (bytes legitimately differ across OPA versions/platforms; behavior
    must not). Skips cleanly when no OPA CLI is present.
    """
    from _opa import build_constitution_wasm, find_opa

    if find_opa() is None:
        pytest.skip("no OPA CLI (vendored tools/opa/opa.exe or PATH) — cannot rebuild for the drift guard")

    from agentos_sdk.quickstart import _PKG, _build_engine

    committed_engine, allow_host = _build_engine()

    rebuilt = build_constitution_wasm(
        Path(str(_PKG / "demo_constitution.yaml")),
        Path(mkdtemp(prefix="agentos_drift_")),
    )
    from agentos_pipeline.policy import ConstitutionPolicyEngine

    rebuilt_engine = ConstitutionPolicyEngine(
        wasm_path=str(rebuilt.wasm_path),
        lists=rebuilt.bundle.lists,
        constitution_version=rebuilt.bundle.constitution_version,
        principles_meta=rebuilt.principles_meta,
    )

    for host in (allow_host, "attacker.example"):
        committed = committed_engine.evaluate(_policy_input(host))
        rebuilt_res = rebuilt_engine.evaluate(_policy_input(host))
        assert committed.no_match == rebuilt_res.no_match
        assert sorted((m.principle_ref, m.effect) for m in committed.matched) == sorted(
            (m.principle_ref, m.effect) for m in rebuilt_res.matched
        )

    assert committed_engine.constitution_version == rebuilt_engine.constitution_version
