"""CMP-01/02 coverage — the control->framework registry is complete and typo-free.

This test DISCOVERS the live detector classes from their real modules (never a
hand-maintained list) and asserts each is mapped, that LIVE_DETECTOR_CONTROLS
equals exactly that discovered set (so a new detector shipped without a mapping
fails CI), that every referenced OWASP / NIST / EU code is a valid constant (no
typos), and that the graduated-outcome families + P0 audit/approval/identity
capabilities are all represented.
"""

import asyncio
import inspect
import json
import re

import agentos_pipeline.enrichment as _enrichment_mod
import agentos_pipeline.risk as _risk_pkg
import agentos_pipeline.sequence as _sequence_mod
import pytest
from agentos_contract.decision import Outcome
from agentos_controlplane.compliance import (
    CONTROL_MAPPINGS,
    EU_AI_ACT,
    EU_AI_ACT_DISCLAIMER,
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


def test_the_bundle_never_claims_conformity(assert_no_conformity_claim):
    """D-8, asserted mechanically over the SERIALIZED bundle. The single largest reputational risk
    in this phase is emitting something a customer forwards to a regulator as a certificate, and a
    reviewer reading strings one at a time is exactly how that ships."""
    blob = json.dumps(export_compliance_evidence()).lower()

    assert_no_conformity_claim(blob)
    assert "not a conformity assessment" in blob
    assert "not a claim of compliance" in blob


def test_the_store_backed_bundle_never_claims_conformity(registry, assert_no_conformity_claim):
    """The store-backed half was never scanned: the guard called the export with NO store, so
    `risk_classifications` — the one part of the bundle carrying operator-supplied text — was the
    one part no guard read."""
    registry.register("a1")
    registry.register("a2")
    asyncio.run(registry.declare_risk_classification("a2", "high_risk", declared_by="op"))

    assert_no_conformity_claim(json.dumps(export_compliance_evidence(registry._session_factory)))


# An object keyed BY article is an article map or an article-keyed claim — the forwardable shape.
# A control that merely TAGS articles in a list value is not, which is why the pattern matches keys.
_ARTICLE_KEYED = re.compile(r"^(Art\.\d+$|eu_art\d+_)")


def _keys_by_article(node) -> bool:
    return isinstance(node, dict) and any(_ARTICLE_KEYED.match(k) for k in node)


def _contains_article_keyed_object(node) -> bool:
    if _keys_by_article(node):
        return True
    children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
    return any(_contains_article_keyed_object(c) for c in children)


def test_no_liftable_section_carries_articles_without_the_disclaimer():
    """The guarantee the module docstring makes, asserted over the lift a consumer actually
    performs: `jq '.frameworks'` for a coverage slide, `jq '.evidence'` for the pointers.

    A second, disclaimer-free copy of the article map shipped under `frameworks` for exactly this
    reason — the old guard only checked that ONE section had both keys, and the whole-bundle
    conformity scan passed because the disclaimer was present somewhere. Neither could see a
    duplicate."""
    bundle = export_compliance_evidence()

    lifted = 0
    for key, section in bundle.items():
        if not _contains_article_keyed_object(section):
            continue
        lifted += 1
        assert EU_AI_ACT_DISCLAIMER in json.dumps(section, ensure_ascii=False), (
            f"bundle[{key!r}] can be lifted out with EU AI Act articles and no statement of what "
            "it is not"
        )
    assert lifted == 1, f"the article map must appear in exactly one section, found {lifted}"


def test_the_articles_are_reachable_only_through_the_disclaimed_section():
    bundle = export_compliance_evidence()

    assert set(bundle["frameworks"]) == {"owasp_agentic_2026", "nist_ai_rmf"}
    assert set(bundle["eu_ai_act"]["articles"]) == set(EU_AI_ACT)


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


def test_the_human_oversight_pointer_names_article_14_not_article_26():
    """Art. 14 IS "Human oversight"; Art. 26 is "Obligations of deployers of high-risk AI systems"
    (both verified against the consolidated text on EUR-Lex, 2026-08-19). The pointer lists the
    four oversight controls this slice files under Art. 14, so naming it after Art. 26 sent an
    auditor to the wrong article for the obligation it names — the exact citation error a
    compliance bundle exists to avoid."""
    pointers = export_compliance_evidence()["eu_ai_act"]["evidence_pointers"]

    assert "eu_art14_human_oversight" in pointers
    assert "eu_art26_human_oversight" not in pointers


# Frozen on 2026-08-19. Art. 5-15 verified verbatim against the CONSOLIDATED Official Journal text
# on EUR-Lex (eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27/eng); Art. 26 and Art. 72 against two
# independent reproductions of it (ai-act-law.eu, artificialintelligenceact.eu), because the
# EUR-Lex renderer truncates mid-recital before reaching them. Re-verify against a primary source
# before editing this list — a heading nobody checked is how a wrong article reaches a regulator.
_VERIFIED_EU_HEADINGS = {
    "Art.5": "Prohibited AI practices",
    "Art.6": "Classification rules for high-risk AI systems",
    "Art.9": "Risk management system",
    "Art.10": "Data and data governance",
    "Art.11": "Technical documentation",
    "Art.12": "Record-keeping",
    "Art.13": "Transparency and provision of information to deployers",
    "Art.14": "Human oversight",
    "Art.15": "Accuracy, robustness and cybersecurity",
    "Art.26": "Obligations of deployers of high-risk AI systems",
    "Art.72": (
        "Post-market monitoring by providers and post-market monitoring plan for high-risk AI "
        "systems"
    ),
}


def test_every_shipped_article_heading_matches_the_verified_text():
    """Nothing else pins a heading to a checked value: `test_every_eu_article_is_valid` only asks
    that a cited id EXISTS in the map, so relabelling Art. 26 "Human oversight" shipped green."""
    assert EU_AI_ACT == _VERIFIED_EU_HEADINGS


# --- (f) CMP-04: the OPERATOR-DECLARED risk classification -----------------


@pytest.fixture
def registry():
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool

    from agentos_controlplane.audit import AuditWriter
    from agentos_controlplane.registry import Registry
    from agentos_controlplane.store.engine import create_all, create_session_factory

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    sf = create_session_factory(engine)
    return Registry(sf, audit=AuditWriter(sf))


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


def test_no_observable_signal_is_ever_turned_into_a_classification(registry):
    """The guard above registers ONE agent with zero observable signal, so any heuristic keyed on
    trust, on a certificate, or on the agent's own denies in the log would pass it. Inference is
    forbidden HOWEVER indirect, so the fixtures below span the state space a heuristic would key
    on: floor and ceiling trust, an agent with a real deny on its record, and a declared neighbour
    whose class must not spread to anyone else."""
    from agentos_contract import ActionType, AgentAction, Decision, Outcome
    from agentos_controlplane.audit import AuditWriter

    registry.register("untrusted", trust_score=0.0)
    registry.register("trusted", trust_score=1.0)
    registry.register("denied", trust_score=0.0)
    registry.register("neighbour")
    asyncio.run(registry.declare_risk_classification("neighbour", "high_risk", declared_by="op"))

    writer = AuditWriter(registry._session_factory)
    action = AgentAction(
        agent_id="denied",
        type=ActionType.tool_call,
        target="http_post",
        payload={"url": "https://api.example.com/x", "content": "hello"},
    )
    asyncio.run(writer.append(action, Decision(action_id=action.id, outcome=Outcome.deny)))

    reported = _classifications(registry)
    for agent_id in ("untrusted", "trusted", "denied"):
        assert reported[agent_id] == "undeclared", agent_id
    assert reported["neighbour"] == "high_risk"


def test_a_declared_classification_is_echoed_verbatim(registry):
    registry.register("a2")
    asyncio.run(registry.declare_risk_classification("a2", "high_risk", declared_by="op"))

    assert _classifications(registry)["a2"] == "high_risk"


def test_a_declaration_can_be_withdrawn_back_to_undeclared(registry):
    """An operator who realises they classified a deployment wrongly must be able to say so.
    Withdrawal returns the agent to 'undeclared' — not to a 'safe' default class, which would be
    the same fabrication in the opposite direction."""
    registry.register("a3")
    asyncio.run(
        registry.declare_risk_classification("a3", "unacceptable_risk", declared_by="op")
    )

    asyncio.run(registry.declare_risk_classification("a3", None, declared_by="op"))

    assert _classifications(registry)["a3"] == "undeclared"


def test_an_unknown_classification_is_refused(registry):
    """The column is a plain string on every backend, so this setter is the first gate. A typo'd
    'high-risk' stored verbatim would be echoed into a regulator-facing bundle as if it were a
    recognised tier."""
    registry.register("a4")

    with pytest.raises(ValueError, match="risk classification"):
        asyncio.run(registry.declare_risk_classification("a4", "high-risk", declared_by="op"))

    assert _classifications(registry)["a4"] == "undeclared"


def test_declaring_for_an_unregistered_agent_is_refused(registry):
    """Silently accepting it would leave an operator believing a classification is on file for an
    agent that has none."""
    with pytest.raises(ValueError, match="not registered"):
        asyncio.run(
            registry.declare_risk_classification(
                "never-registered", "minimal_risk", declared_by="op"
            )
        )


# --- CMP-04: the declaration is AUDITED, and the export re-gates the column ---


def _events(registry, kind: str) -> list[dict]:
    from sqlalchemy import select

    from agentos_controlplane.store.models import AuditRecord

    with registry._session_factory() as s:
        return [
            r.body
            for r in s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
            if (r.body or {}).get("kind") == kind
        ]


def test_declaring_a_classification_is_audited_with_its_author_and_what_it_replaced(registry):
    """Changing a deployment's legal risk class is an operator change to enforcement configuration
    and is audited like every other one (kill_switch_set, privilege_ring_set, resource_limit_set) —
    more than they need it, because this one is a legal claim. The column holds only the CURRENT
    value, so without this an operator who declares high_risk in March and minimal_risk in
    September exports a bundle saying minimal_risk with nothing recording that it ever said
    otherwise, who changed it, or when."""
    registry.register("a5")

    asyncio.run(registry.declare_risk_classification("a5", "high_risk", declared_by="alice"))
    asyncio.run(registry.declare_risk_classification("a5", "minimal_risk", declared_by="bob"))
    asyncio.run(registry.declare_risk_classification("a5", None, declared_by="carol"))

    bodies = _events(registry, "risk_classification_declared")
    assert [(b["previous"], b["classification"], b["declared_by"]) for b in bodies] == [
        ("undeclared", "high_risk", "alice"),
        ("high_risk", "minimal_risk", "bob"),
        ("minimal_risk", "undeclared", "carol"),
    ]
    assert all(b["agent_id"] == "a5" for b in bodies)


def test_a_declaration_that_cannot_be_recorded_is_refused_outright():
    """Fail-closed, like the AUD-04 body gate: an unrecorded legal classification is worse than
    none, so a registry with no audit writer refuses rather than writing the column silently."""
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
    unaudited = Registry(create_session_factory(engine))
    unaudited.register("a6")

    with pytest.raises(ValueError, match="audit writer"):
        asyncio.run(unaudited.declare_risk_classification("a6", "high_risk", declared_by="op"))

    assert _classifications(unaudited)["a6"] == "undeclared"


def test_an_anonymous_declaration_is_refused(registry):
    registry.register("a7")

    with pytest.raises(ValueError, match="declared_by"):
        asyncio.run(registry.declare_risk_classification("a7", "high_risk", declared_by=""))


def test_a_value_written_around_the_setter_never_reaches_the_bundle(registry):
    """The export is the LAST boundary before a regulator-facing artifact, and the setter gates
    only the path that goes through it — a direct UPDATE, a migration, or the API route 11f will
    add can all put an invented tier in the column. Refusing to emit is the honest failure:
    rewriting it to 'undeclared' would replace one false statement with another."""
    from sqlalchemy import update

    from agentos_controlplane.store.models import Agent

    registry.register("a8")
    with registry._session_factory() as s:
        s.execute(
            update(Agent)
            .where(Agent.agent_id == "a8")
            .values(risk_classification="CERTIFIED COMPLIANT - Art. 43 conformity assessed")
        )
        s.commit()

    with pytest.raises(ValueError, match="unrecognised EU AI Act risk classification"):
        export_compliance_evidence(registry._session_factory)


def test_the_accepted_vocabulary_names_its_provenance_rather_than_borrowing_the_acts():
    """Only `high_risk` names a determination the Act's OPERATIVE text defines (Art. 6 + Annex III,
    which produce exactly one answer — high-risk or not). Art. 5 prohibits PRACTICES rather than
    creating a system tier, and neither "limited risk" nor "minimal risk" appears in the operative
    text at all; the other three values are the European Commission's own explanatory labels
    ("Unacceptable risk / High risk / Transparency risk / Minimal or no risk", verified 2026-08-19
    at digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai). "limited_risk" is gone
    because it is not even the Commission's current term. Calling all four "the Act's own risk
    tiers" attributed to the Regulation a vocabulary it does not use."""
    assert RISK_CLASSIFICATIONS == frozenset(
        {"unacceptable_risk", "high_risk", "transparency_risk", "minimal_risk"}
    )


def test_the_source_string_does_not_claim_the_act_names_every_tier():
    from agentos_controlplane.compliance import RISK_CLASSIFICATION_SOURCE

    assert "Commission" in RISK_CLASSIFICATION_SOURCE  # provenance of the non-Art.6 tiers
    assert "Art. 6" in RISK_CLASSIFICATION_SOURCE  # the one tier the operative text defines
    # One row per AGENT, not per deployment — the same agent can serve two use cases in different
    # tiers, which is the module's own reason classification cannot be inferred.
    assert "per deployment" in RISK_CLASSIFICATION_SOURCE


def test_without_a_registry_the_bundle_claims_nothing_about_any_fleet():
    """An empty `risk_classifications: {}` reads as 'this fleet has no agents'. With no store
    supplied we know nothing about any fleet, and the honest output is to say nothing at all."""
    assert "risk_classifications" not in export_compliance_evidence()["eu_ai_act"]
