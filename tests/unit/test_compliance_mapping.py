"""CMP-01/02 coverage — the control->framework registry is complete and typo-free.

This test DISCOVERS the live detector classes from their real modules (never a
hand-maintained list) and asserts each is mapped, that LIVE_DETECTOR_CONTROLS
equals exactly that discovered set (so a new detector shipped without a mapping
fails CI), that every referenced OWASP / NIST / EU code is a valid constant (no
typos), and that the graduated-outcome families + P0 audit/approval/identity
capabilities are all represented.
"""

import inspect

import agentos_pipeline.risk as _risk_pkg
import agentos_pipeline.sequence as _sequence_mod
from agentos_contract.decision import Outcome
from agentos_controlplane.compliance import (
    CONTROL_MAPPINGS,
    EU_AI_ACT,
    LIVE_DETECTOR_CONTROLS,
    NIST_RMF,
    OWASP_AGENTIC,
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
      * sequence module — every public class DEFINED there (SequenceCorrelator has
        ``observe()``, not ``score()``, so it is not a RiskScorer and is discovered
        structurally rather than by the scorer surface).
    """
    found: dict[str, type] = {}
    for name in _risk_pkg.__all__:
        obj = getattr(_risk_pkg, name)
        if _has_risk_scorer_surface(obj):
            found[obj.__name__] = obj
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
