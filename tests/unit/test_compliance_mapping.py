"""CMP-01/02 coverage — the control->framework registry is complete and typo-free.

This test DISCOVERS the live detector classes from their real modules (never a
hand-maintained list) and asserts each is mapped, that LIVE_DETECTOR_CONTROLS
equals exactly that discovered set (so a new detector shipped without a mapping
fails CI), that every referenced OWASP / NIST / EU code is a valid constant (no
typos), and that the graduated-outcome families + P0 audit/approval/identity
capabilities are all represented.
"""

import inspect

import agentos_pipeline.enrichment as _enrichment_mod
import agentos_pipeline.risk as _risk_pkg
import agentos_pipeline.sequence as _sequence_mod
import pytest
from agentos_contract.decision import Outcome
from agentos_controlplane.compliance import (
    CONTROL_MAPPINGS,
    EU_AI_ACT,
    LIVE_DETECTOR_CONTROLS,
    NIST_RMF,
    OWASP_AGENTIC,
    RISK_CLASSIFICATIONS,
    export_compliance_evidence,
)

_CONTROL_KEYS = {m.control for m in CONTROL_MAPPINGS}


def _has_risk_scorer_surface(obj: object) -> bool:
    """The agentos_contract.risk.RiskScorer contract: a ``score`` method + an ``inline`` flag."""
    return inspect.isclass(obj) and hasattr(obj, "score") and hasattr(obj, "inline")


def _discover_live_detectors() -> dict[str, type]:
    """Discover the shipped detector classes from their LIVE modules — never a hand-list.

    So a NEW detector shipped without a ControlMapping fails this test (the exact
    CMP-01/02 drift the slice guards):

      * risk package — every EXPORTED (``__all__``) class implementing the RiskScorer
        surface (``score`` + ``inline``);
      * enrichment's guardrail tier — the scorers `enrich()` actually RUNS. The Phase-8
        detectors (SEC-04/05/09/11) are wired there without being re-exported from
        ``risk.__all__``, so a package-exports-only discovery declared them absent and
        four live detectors sat unmapped. What runs is the authority on what is live;
      * sequence module — every public class DEFINED there (SequenceCorrelator has
        ``observe()``, not ``score()``, so it is not a RiskScorer and is discovered
        structurally rather than by the scorer surface).
    """
    found: dict[str, type] = {}
    for name in _risk_pkg.__all__:
        obj = getattr(_risk_pkg, name)
        if _has_risk_scorer_surface(obj):
            found[obj.__name__] = obj
    for scorer in _enrichment_mod._GUARDRAIL_SCORERS:
        found[type(scorer).__name__] = type(scorer)
    for _name, obj in inspect.getmembers(_sequence_mod, inspect.isclass):
        if obj.__module__ == _sequence_mod.__name__ and not obj.__name__.startswith("_"):
            found[obj.__name__] = obj
    return found


_LIVE_DETECTOR_CLASSES = _discover_live_detectors()


# --- (a) no typo'd framework codes -----------------------------------------


def test_every_owasp_code_is_valid():
    for m in CONTROL_MAPPINGS:
        for code in m.owasp:
            assert code in OWASP_AGENTIC, f"{m.control}: unknown OWASP code {code!r}"


def test_every_nist_function_is_valid():
    for m in CONTROL_MAPPINGS:
        for fn in m.nist_rmf:
            assert fn in NIST_RMF, f"{m.control}: unknown NIST RMF function {fn!r}"


def test_every_eu_article_is_valid():
    for m in CONTROL_MAPPINGS:
        for art in m.eu_ai_act:
            assert art in EU_AI_ACT, f"{m.control}: unknown EU AI Act article {art!r}"


def test_every_mapping_carries_at_least_one_framework_tag():
    for m in CONTROL_MAPPINGS:
        assert m.owasp, f"{m.control}: no OWASP tag"
        assert m.nist_rmf, f"{m.control}: no NIST RMF tag"
        assert m.evidence, f"{m.control}: no evidence pointer"


# --- (b) control keys are unique -------------------------------------------


def test_control_keys_are_unique():
    keys = [m.control for m in CONTROL_MAPPINGS]
    assert len(keys) == len(set(keys)), "duplicate control key in CONTROL_MAPPINGS"


# --- (c) COVERAGE: every live (discovered) detector class is mapped --------


def test_discovery_finds_the_live_detectors():
    # Guards the discovery itself: a broken enumeration returning {} must not let the
    # coverage assertions below pass vacuously.
    assert _LIVE_DETECTOR_CLASSES, "no live detectors discovered — discovery is broken"


def test_every_live_detector_class_is_mapped():
    for name in _LIVE_DETECTOR_CLASSES:
        assert name in _CONTROL_KEYS, f"{name} has no compliance mapping"


def test_live_detector_controls_matches_shipped_classes():
    discovered = set(_LIVE_DETECTOR_CLASSES)
    assert LIVE_DETECTOR_CONTROLS == discovered, (
        "LIVE_DETECTOR_CONTROLS is out of sync with the detectors discovered from their "
        f"live modules; reconcile (declare + add mapping): {discovered ^ LIVE_DETECTOR_CONTROLS}"
    )


def test_live_detector_controls_are_all_mapped():
    assert LIVE_DETECTOR_CONTROLS <= _CONTROL_KEYS


# --- (d) graduated outcomes + P0 audit/approval/identity capabilities ------


def test_graduated_outcome_families_are_mapped():
    assert "graduated_response" in _CONTROL_KEYS
    assert "approvals" in _CONTROL_KEYS  # Outcome.require_approval (POL-07)
    # controls named after real Outcome members — catches an enum-vs-registry typo
    assert Outcome.temporary_exception.value in _CONTROL_KEYS
    assert Outcome.governance_review.value in _CONTROL_KEYS


def test_p0_audit_and_identity_capabilities_are_mapped():
    for key in (
        "audit_chain",
        "audit_signatures",
        "audit_verifier",
        "redaction",
        "identity_engine",
        "interception_coverage",
        "kill_switch",
        "constitution_policy_floor",
    ):
        assert key in _CONTROL_KEYS, f"missing P0 capability mapping: {key}"


# --- (e) CMP-04: the widened EU AI Act article mapping ---------------------


def test_each_article_we_list_has_a_control_behind_it_or_says_it_has_none():
    """A silently empty article reads as an oversight — an auditor sees a heading with nothing
    under it and cannot tell whether we forgot or whether there is genuinely nothing to show. An
    explicitly empty one is a statement."""
    for art, entry in export_compliance_evidence()["eu_ai_act"]["articles"].items():
        assert entry["controls"] or entry.get("note"), f"{art} is silently empty"


def test_article_5_is_a_non_claim_about_use_rather_than_a_borrowed_control():
    """Prohibited practices are about what a system is USED for, not about controls a runtime can
    implement. Pointing any shipped control at Art. 5 would be a claim about a deployment we
    cannot observe."""
    entry = export_compliance_evidence()["eu_ai_act"]["articles"]["Art.5"]

    assert entry["controls"] == []
    assert "prohibited" in entry["name"].lower()
    assert "use" in entry["note"].lower()


def test_article_6_defers_classification_to_the_operator_rather_than_evidencing_it():
    """Art. 6 is where a tool would be most tempted to infer a customer's regulatory class."""
    entry = export_compliance_evidence()["eu_ai_act"]["articles"]["Art.6"]

    assert entry["controls"] == []
    assert "declared" in entry["note"].lower()


def test_the_bundle_never_claims_conformity():
    """D-8, asserted mechanically over the SERIALIZED bundle. The single largest reputational risk
    in this phase is emitting something a customer forwards to a regulator as a certificate, and a
    reviewer reading strings one at a time is exactly how that ships."""
    import json

    blob = json.dumps(export_compliance_evidence()).lower()

    for forbidden in (
        "is compliant",
        "fully compliant",
        "certified",
        "conformity assessment passed",
        "guarantees compliance",
        "compliance certificate",
        "attests compliance",
    ):
        assert forbidden not in blob, forbidden
    assert "not a conformity assessment" in blob
    assert "not a claim of compliance" in blob


def test_merkle_inclusion_proofs_are_cited_under_record_keeping():
    """AUD-06 landed in Slice 11a; Art. 12 is the article where it earns its keep — it is what
    lets a deployer evidence ONE record to an auditor without disclosing the rest of the log."""
    bundle = export_compliance_evidence()
    assert "merkle_evidence" in bundle["eu_ai_act"]["articles"]["Art.12"]["controls"]

    evidence = {m["control"]: m["evidence"] for m in bundle["controls"]}
    assert "inclusion proof" in evidence["merkle_evidence"].lower()


def test_human_oversight_cites_the_oversight_controls_that_actually_ship():
    """CMP-04 names human oversight explicitly, and Art. 14 is where it lives."""
    controls = set(export_compliance_evidence()["eu_ai_act"]["articles"]["Art.14"]["controls"])

    assert {"approvals", "temporary_exception", "governance_review", "kill_switch"} <= controls


def test_the_disclaimer_travels_inside_the_article_section():
    """So the articles cannot be lifted out of the bundle and forwarded on their own."""
    section = export_compliance_evidence()["eu_ai_act"]

    assert "articles" in section and "disclaimer" in section


# --- (f) CMP-04: the OPERATOR-DECLARED risk classification -----------------


@pytest.fixture
def registry():
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool

    from agentos_controlplane.registry import Registry
    from agentos_controlplane.store.engine import create_all, create_session_factory

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    return Registry(create_session_factory(engine))


def _classifications(registry) -> dict:
    return export_compliance_evidence(registry._session_factory)["eu_ai_act"][
        "risk_classifications"
    ]


def test_an_undeclared_agent_is_reported_as_undeclared_not_defaulted(registry):
    """Defaulting a legal classification is the single most harmful thing this module could do:
    a false 'high_risk' burdens a deployer with obligations they do not have, and a false
    'minimal_risk' tells them to skip ones they do. 'We do not know' must survive to the export."""
    registry.register("a1")

    assert _classifications(registry)["a1"] == "undeclared"


def test_a_declared_classification_is_echoed_verbatim(registry):
    registry.register("a2")
    registry.declare_risk_classification("a2", "high_risk")

    assert _classifications(registry)["a2"] == "high_risk"


def test_a_declaration_can_be_withdrawn_back_to_undeclared(registry):
    """An operator who realises they classified a deployment wrongly must be able to say so.
    Withdrawal returns the agent to 'undeclared' — not to a 'safe' default class, which would be
    the same fabrication in the opposite direction."""
    registry.register("a3")
    registry.declare_risk_classification("a3", "prohibited")

    registry.declare_risk_classification("a3", None)

    assert _classifications(registry)["a3"] == "undeclared"


def test_an_unknown_classification_is_refused(registry):
    """The column is a plain string on every backend, so this setter is the only gate. A typo'd
    'high-risk' stored verbatim would be echoed into a regulator-facing bundle as if it were the
    Act's own vocabulary."""
    registry.register("a4")

    with pytest.raises(ValueError, match="risk classification"):
        registry.declare_risk_classification("a4", "high-risk")

    assert _classifications(registry)["a4"] == "undeclared"


def test_declaring_for_an_unregistered_agent_is_refused(registry):
    """Silently accepting it would leave an operator believing a classification is on file for an
    agent that has none."""
    with pytest.raises(ValueError, match="not registered"):
        registry.declare_risk_classification("never-registered", "minimal_risk")


def test_the_accepted_vocabulary_is_the_acts_own_risk_tiers():
    assert RISK_CLASSIFICATIONS == frozenset(
        {"prohibited", "high_risk", "limited_risk", "minimal_risk"}
    )


def test_without_a_registry_the_bundle_claims_nothing_about_any_fleet():
    """An empty `risk_classifications: {}` reads as 'this fleet has no agents'. With no store
    supplied we know nothing about any fleet, and the honest output is to say nothing at all."""
    assert "risk_classifications" not in export_compliance_evidence()["eu_ai_act"]
