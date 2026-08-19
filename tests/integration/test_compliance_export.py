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

    # The EU article map lives under `eu_ai_act`, NEVER under `frameworks` — `frameworks` holds
    # only the two taxonomies with no legal weight, so there is no copy of the articles that a
    # consumer can lift for a coverage view without the disclaimer that travels with them.
    assert "eu_ai_act" not in fw
    eu = b["eu_ai_act"]["articles"]
    # CMP-04 widened Phase 6's minimal Art.12/26 pointer to the article set a high-risk deployment
    # actually faces. Art.5 and Art.6 are here as explicit NON-claims (see the mapping tests).
    assert set(eu) == {
        "Art.5", "Art.6", "Art.9", "Art.10", "Art.11", "Art.12", "Art.13", "Art.14", "Art.15",
        "Art.26", "Art.72",
    }
    assert len(eu["Art.12"]["controls"]) >= 1  # record-keeping backed by >=1 control
    assert len(eu["Art.14"]["controls"]) >= 1  # human oversight (Art.14) backed by >=1 control
    assert len(eu["Art.26"]["controls"]) >= 1  # deployer obligations backed by >=1 control


def test_bundle_has_controls_list_and_evidence_pointers():
    b = export_compliance_evidence()
    assert isinstance(b["controls"], list) and b["controls"]
    sample = b["controls"][0]
    assert {"control", "name", "owasp", "nist_rmf", "eu_ai_act", "evidence"} <= set(sample)
    # Article-keyed pointers sit inside the disclaimed section, not beside it under a generic key.
    ptr = b["eu_ai_act"]["evidence_pointers"]
    assert ptr["eu_art12_record_keeping"]  # concrete Art.12 evidence pointer
    assert ptr["eu_art14_human_oversight"]  # concrete Art.14 evidence pointer


def test_bundle_without_store_has_no_live_counts():
    """Omitted, not empty: with no store we know nothing about any fleet, and `evidence: {}` reads
    as "we have no evidence" — the same false silence an empty `risk_classifications` would be."""
    assert "evidence" not in export_compliance_evidence()


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
    assert set(b["frameworks"]) == {"owasp_agentic_2026", "nist_ai_rmf"}


# --- CLI --------------------------------------------------------------------


def test_cli_prints_valid_json(tmp_path, capsys):
    sf, db_path = _file_store(tmp_path)
    eng = _identity_engine()
    _seed_two_records(sf, eng)

    rc = _main(["--db", db_path])
    assert rc == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)  # valid JSON
    assert set(parsed["frameworks"]) == {"owasp_agentic_2026", "nist_ai_rmf"}
    assert parsed["evidence"]["audit_records"] >= 2
    assert parsed["evidence"]["chain_verifies"] is True


def test_cli_without_db_prints_static_bundle(capsys):
    rc = _main([])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert "evidence" not in parsed
    assert parsed["eu_ai_act"]["articles"]
