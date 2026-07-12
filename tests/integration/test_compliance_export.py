"""CMP-03 — export_compliance_evidence() emits the full framework bundle + evidence pointers,
and with a live signed audit store adds record/checkpoint counts and a chain_verifies flag.
A `python -m agentos_controlplane.compliance --db ...` CLI prints the bundle as JSON.
"""

import asyncio
import json

import pytest

from agentos_controlplane.compliance import _main, export_compliance_evidence


# --- static bundle (no store) ----------------------------------------------


def test_bundle_has_all_three_framework_sections():
    b = export_compliance_evidence()
    fw = b["frameworks"]

    owasp = fw["owasp_agentic_2026"]
    assert set(owasp) == {f"ASI{n:02d}" for n in range(1, 11)}  # exactly 10 ASI keys
    for code, entry in owasp.items():
        assert entry["name"] and isinstance(entry["controls"], list)

    nist = fw["nist_ai_rmf"]
    assert set(nist) == {"GOVERN", "MAP", "MEASURE", "MANAGE"}  # 4 functions
    for controls in nist.values():
        assert isinstance(controls, list)

    eu = fw["eu_ai_act"]
    assert set(eu) == {"Art.12", "Art.26"}
    assert len(eu["Art.12"]["controls"]) >= 1  # record-keeping backed by >=1 control
    assert len(eu["Art.26"]["controls"]) >= 1  # human oversight backed by >=1 control


def test_bundle_has_controls_list_and_evidence_pointers():
    b = export_compliance_evidence()
    assert isinstance(b["controls"], list) and b["controls"]
    sample = b["controls"][0]
    assert {"control", "name", "owasp", "nist_rmf", "eu_ai_act", "evidence"} <= set(sample)
    ev = b["evidence"]
    assert ev["eu_art12_record_keeping"]  # concrete Art.12 evidence pointer
    assert ev["eu_art26_human_oversight"]  # concrete Art.26 evidence pointer


def test_bundle_without_store_has_no_live_counts():
    b = export_compliance_evidence()
    assert "audit_records" not in b["evidence"]
    assert "chain_verifies" not in b["evidence"]


def test_bundle_is_json_serializable():
    json.dumps(export_compliance_evidence())  # no exception


# --- live signed audit store -----------------------------------------------


def _identity_engine():
    from agentos_controlplane.identity_engine import IdentityEngine

    return IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)


def _file_store(tmp_path):
    from sqlalchemy import create_engine

    from agentos_controlplane.store.engine import create_all, create_session_factory

    db_path = tmp_path / "compliance.db"
    engine = create_engine(f"sqlite+pysqlite:///{db_path}")
    create_all(engine)
    return create_session_factory(engine), str(db_path)


def _action(target: str):
    from agentos_contract import ActionType, AgentAction

    return AgentAction(
        agent_id="agent-1",
        type=ActionType.tool_call,
        target=target,
        payload={"url": "https://api.example.com/x", "content": "hello"},
    )


def _decision(action):
    from agentos_contract import Decision, Outcome

    return Decision(action_id=action.id, outcome=Outcome.allow)


def _seed_two_records(session_factory, engine):
    from agentos_controlplane.audit import AuditWriter

    writer = AuditWriter(session_factory, signer=engine)

    async def _run():
        for tgt in ("http_get", "http_post"):
            a = _action(tgt)
            await writer.append(a, _decision(a))

    asyncio.run(_run())


def test_live_store_adds_audit_counts_and_chain_verifies(tmp_path):
    sf, _ = _file_store(tmp_path)
    eng = _identity_engine()
    _seed_two_records(sf, eng)

    b = export_compliance_evidence(sf, public_key_pem=eng.public_key_pem)
    ev = b["evidence"]
    assert ev["audit_records"] >= 2
    assert "checkpoints" in ev
    assert ev["chain_verifies"] is True
    # the static bundle is still present alongside the live evidence
    assert set(b["frameworks"]) == {"owasp_agentic_2026", "nist_ai_rmf", "eu_ai_act"}


# --- CLI --------------------------------------------------------------------


def test_cli_prints_valid_json(tmp_path, capsys):
    sf, db_path = _file_store(tmp_path)
    eng = _identity_engine()
    _seed_two_records(sf, eng)

    rc = _main(["--db", db_path])
    assert rc == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)  # valid JSON
    assert set(parsed["frameworks"]) == {"owasp_agentic_2026", "nist_ai_rmf", "eu_ai_act"}
    assert parsed["evidence"]["audit_records"] >= 2
    assert parsed["evidence"]["chain_verifies"] is True


def test_cli_without_db_prints_static_bundle(capsys):
    rc = _main([])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert "audit_records" not in parsed["evidence"]
