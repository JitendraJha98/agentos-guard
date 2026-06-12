"""The 5-minute wedge demo (SEC-13, ROADMAP Phase 3 success criterion 5).

Every individual action below is ALLOWED by the Constitution -- there is no
single-action rule against destruction. But `rename_table` followed by
`drop_table` in the same conversation matches forbidden-sequence principle 3.5
(`rename_then_drop`), and the SEQUENCE is denied with a cited principle and
concrete remediation. Per-action string matching cannot express this; the
windowed sequence-intent correlator over conversation lineage can.

Run from the repo root:  .venv/Scripts/python.exe examples/wedge_demo.py
Requires the vendored OPA CLI (tools/opa/opa.exe) or `opa` on PATH.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))  # reuse the OPA locator/build helper

from _opa import build_constitution_wasm, find_opa  # noqa: E402

from sqlalchemy import create_engine  # noqa: E402

from agentos_contract import ActionContext, ActionType, AgentAction, Outcome  # noqa: E402
from agentos_controlplane.audit import AuditWriter  # noqa: E402
from agentos_controlplane.registry import Registry  # noqa: E402
from agentos_controlplane.store.engine import create_all, create_session_factory  # noqa: E402
from agentos_pipeline.identity import IdentityStage  # noqa: E402
from agentos_pipeline.policy import ConstitutionPolicyEngine  # noqa: E402
from agentos_pipeline.risk import PromptInjectionScorer  # noqa: E402
from agentos_pipeline.runner import Pipeline  # noqa: E402

ALLOWED_URL = "https://api.example.com/db"


def _print_decision(step: str, decision) -> None:
    print(f"\n=== {step}")
    print(f"    outcome: {decision.outcome.value}")
    for r in decision.reasons:
        if r.stage == "policy" and r.principle_ref:
            print(f"    fired principle {r.principle_ref}: {r.rationale}")
    for hint in decision.remediation:
        print(f"    remediation: {hint}")


async def main() -> int:
    if find_opa() is None:
        print("OPA binary not found (tools/opa/opa.exe or PATH) -- cannot run the demo.")
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        built = build_constitution_wasm(REPO / "examples" / "wedge_constitution.yaml", Path(tmp))
        engine = create_engine("sqlite+pysqlite:///:memory:")
        create_all(engine)
        sessions = create_session_factory(engine)
        registry = Registry(sessions)
        token = registry.register("wedge-agent")
        pipeline = Pipeline(
            identity=IdentityStage(registry.identity),
            policy=ConstitutionPolicyEngine(
                wasm_path=str(built.wasm_path),
                lists=built.bundle.lists,
                constitution_version=built.bundle.constitution_version,
                principles_meta=built.principles_meta,
            ),
            scorers=[PromptInjectionScorer()],
            audit=AuditWriter(sessions),
            sequences=built.bundle.sequences,  # SEC-13: the declared forbidden sequences
        )

        def act(target: str, conversation: str) -> AgentAction:
            return AgentAction(
                agent_id="wedge-agent",
                type=ActionType.tool_call,
                target=target,
                payload={"url": ALLOWED_URL},
                context=ActionContext(conversation_id=conversation),
                identity_token=token,
            )

        print("agentos-guard wedge demo -- rename_then_drop (SEC-13)")
        print(f"constitution: {built.bundle.constitution_version}")

        d1 = await pipeline.evaluate(act("drop_table", "conversation-solo"))
        _print_decision("1. drop_table ALONE (fresh conversation)", d1)
        assert d1.outcome is Outcome.allow, "destruction alone is individually permitted"

        d2 = await pipeline.evaluate(act("rename_table", "conversation-evasion"))
        _print_decision("2. rename_table (same conversation as step 3)", d2)
        assert d2.outcome is Outcome.allow, "the rename alone is individually permitted"

        d3 = await pipeline.evaluate(act("drop_table", "conversation-evasion"))
        _print_decision("3. drop_table AFTER the rename -- the forbidden SEQUENCE", d3)
        assert d3.outcome is Outcome.deny, "the sequence must be denied"
        assert any(r.principle_ref == "3.5" for r in d3.reasons), "3.5 must be cited"

        print("\nEvery action above was individually allowed; the SEQUENCE was denied")
        print("with principle 3.5 cited and concrete remediation -- the durable gap")
        print("a stateless, per-action policy kernel cannot close. Audit evidence is")
        print("hash-chained; decision ids:", d1.action_id, d2.action_id, d3.action_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
