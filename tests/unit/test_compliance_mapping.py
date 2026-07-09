"""CMP-01/02 coverage — the control->framework registry is complete and typo-free.

This test imports the LIVE detector classes from their real modules and asserts
each is mapped, that LIVE_DETECTOR_CONTROLS equals exactly that set (so a new
detector shipped without a mapping fails CI), that every referenced OWASP /
NIST / EU code is a valid constant (no typos), and that the graduated-outcome
families + P0 audit/approval/identity capabilities are all represented.
"""

from agentos_contract.decision import Outcome
from agentos_controlplane.compliance import (
    CONTROL_MAPPINGS,
    EU_AI_ACT,
    LIVE_DETECTOR_CONTROLS,
    NIST_RMF,
    OWASP_AGENTIC,
)

# The live, shipped detector classes — imported from their REAL modules.
from agentos_pipeline.risk import (
    FormatViolationScorer,
    IntentScorer,
    PiiScorer,
    PromptInjectionScorer,
    UnsafeContentScorer,
)
from agentos_pipeline.sequence import SequenceCorrelator

_CONTROL_KEYS = {m.control for m in CONTROL_MAPPINGS}
_LIVE_DETECTOR_CLASSES = (
    PromptInjectionScorer,
    PiiScorer,
    UnsafeContentScorer,
    FormatViolationScorer,
    IntentScorer,
    SequenceCorrelator,
)


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


# --- (c) COVERAGE: every live detector class is mapped ---------------------


def test_every_live_detector_class_is_mapped():
    for cls in _LIVE_DETECTOR_CLASSES:
        assert cls.__name__ in _CONTROL_KEYS, f"{cls.__name__} has no compliance mapping"


def test_live_detector_controls_matches_shipped_classes():
    shipped = {cls.__name__ for cls in _LIVE_DETECTOR_CLASSES}
    assert LIVE_DETECTOR_CONTROLS == shipped, (
        "LIVE_DETECTOR_CONTROLS is out of sync with the shipped detector classes; "
        f"add the mapping for {shipped - LIVE_DETECTOR_CONTROLS or LIVE_DETECTOR_CONTROLS - shipped}"
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
