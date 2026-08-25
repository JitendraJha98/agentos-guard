# Phase 10 · Slice 10a — Framework-Agnostic Gateway PEP (INT-07) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. (`-m latency` is wall-clock and marginal on this box —
> cached-path mean ~3.9–6.5 ms against a 5 ms budget — so it flakes under load. If it fails, re-run
> when idle and compare against a scratch worktree at the Phase-9 base before claiming a regression.
> NEVER loosen the budget.)

**Goal (INT-07):** A network gateway PEP governs agent actions **with no SDK changes** — an agent
adopts it by pointing its `base_url` at the gateway — behind the same
`evaluate(AgentAction) -> Decision` contract, and a blocked request never reaches upstream.

**Architecture:** A new `agentos-gateway` workspace package exposes an ASGI app that reverse-proxies
an upstream base URL. Each request is normalized into an `AgentAction`, then handed to the SAME
`agentos_sdk.enforce.governed_call` every other PEP form uses — the run callable is "forward upstream
via httpx". So `allow` proxies and returns the upstream response, while every governed block
(`deny`, quarantine, budget breach, missing consensus) raises before the forward and returns a
governed HTTP error. The gateway adds **normalization + transport only**; it never re-implements the
outcome map, so Phase-9 containment cannot be lost.

**Tech Stack:** FastAPI + httpx (both already workspace deps), `agentos-sdk` (enforcement core),
`agentos-contract`, pytest + `httpx.ASGITransport`.

> First commit in this slice: `docs(phase-10): Slice 10a plan` for this file, then the tasks below.

## Header contract (decided, not implicit)
- `X-Agentos-Token` — the agent's **agentos identity token** (the one `Registry.register` issues).
  It is CONSUMED by the gateway and **never forwarded upstream**, never logged, never audited.
- `Authorization` — the **upstream** credential (e.g. the real OpenAI key). Forwarded unchanged.

This split matters: an OpenAI-compatible client already puts its provider key in `Authorization`, so
governance needs its own header, and mixing them would leak the governance token to the upstream
provider.

## File structure
- Create `packages/gateway/pyproject.toml` — the `agentos-gateway` workspace package.
- Create `packages/gateway/src/agentos_gateway/__init__.py` — public exports.
- Create `packages/gateway/src/agentos_gateway/normalize.py` — `normalize_gateway_model_call`,
  `normalize_gateway_tool_call` (both `@covers`-registered).
- Create `packages/gateway/src/agentos_gateway/app.py` — `create_gateway(...)` ASGI app + routes.
- Modify `packages/sdk/src/agentos_sdk/coverage.py` — registry records MULTIPLE entrypoints per type.
- Modify `tests/unit/test_coverage.py` — adapt to the set-valued registry.
- Modify root `pyproject.toml` — add `agentos-gateway` to deps + `[tool.uv.sources]`.
- Tests: `tests/unit/test_gateway_normalize.py`, `tests/integration/test_gateway_pep.py`.

---

### Task 1: coverage registry records every PEP form

**Files:**
- Modify: `packages/sdk/src/agentos_sdk/coverage.py`
- Modify: `tests/unit/test_coverage.py`

**Why this changes:** `_REGISTRY` is `dict[ActionType, str]` and `covers()` **overwrites**, so a second
PEP form registering `tool_call` would silently replace the LangChain entry — the matrix would then
claim the gateway is the only tool-call path. Phase 10 adds PEP forms for types that already have one,
so coverage must record ALL entrypoints or it stops reflecting reality (the whole point of INT-06).

```python
# ActionType -> the fully-qualified entrypoints that intercept/normalize it. A SET, not a single
# string: from Phase 10 an action type legitimately has SEVERAL PEP forms (SDK middleware, SDK
# wrappers, the network gateway), and overwriting would hide all but the last one registered.
_REGISTRY: dict[ActionType, set[str]] = {}


def covers(action_type: ActionType) -> Callable[[_F], _F]:
    """Register `fn` as AN interception/normalization path for `action_type` (several may exist)."""

    def _register(fn: _F) -> _F:
        _REGISTRY.setdefault(action_type, set()).add(f"{fn.__module__}.{fn.__qualname__}")
        return fn

    return _register


def covered_types() -> set[ActionType]:
    """The set of action types that currently have at least one registered PEP path."""
    return {t for t, entries in _REGISTRY.items() if entries}


def coverage_matrix() -> dict[ActionType, set[str]]:
    """A copy of the full {action_type -> {entrypoints}} map (for inspection/reporting)."""
    return {t: set(entries) for t, entries in _REGISTRY.items()}
```

`verify_coverage()` is unchanged (it uses `covered_types()`).

**Steps (TDD):**
- [ ] Read `tests/unit/test_coverage.py` first. Update the two places that assume a scalar value:
  the monkeypatch-based gap test, and the probe assertion at ~line 60
  (`assert _REGISTRY[ActionType.tool_call].endswith("_probe")` becomes
  `assert any(e.endswith("_probe") for e in _REGISTRY[ActionType.tool_call])`).
- [ ] Add a NEW failing test asserting the multi-PEP property — the actual regression this guards:
```python
def test_two_peps_for_one_action_type_are_both_recorded():
    """A second PEP form must not evict the first: with the gateway and the SDK both covering
    tool_call, the matrix has to show BOTH or INT-06 stops reflecting reality."""
    from agentos_sdk.coverage import _REGISTRY, covers, coverage_matrix
    before = {t: set(v) for t, v in _REGISTRY.items()}
    try:
        @covers(ActionType.tool_call)
        def _pep_one(): ...

        @covers(ActionType.tool_call)
        def _pep_two(): ...

        entries = coverage_matrix()[ActionType.tool_call]
        assert any(e.endswith("_pep_one") for e in entries)
        assert any(e.endswith("_pep_two") for e in entries)
    finally:
        _REGISTRY.clear()
        _REGISTRY.update(before)
```
  Run → fails (a set-valued registry does not exist yet).
- [ ] Implement the `coverage.py` change. Run the file → passes; run the FULL suite → green.
- [ ] Commit `feat(sdk): coverage registry records every PEP form per action type (INT-06/INT-07)`.

---

### Task 2: the `agentos-gateway` package + normalizers

**Files:**
- Create: `packages/gateway/pyproject.toml`,
  `packages/gateway/src/agentos_gateway/__init__.py`,
  `packages/gateway/src/agentos_gateway/normalize.py`
- Modify: root `pyproject.toml`
- Test: `tests/unit/test_gateway_normalize.py`

`packages/gateway/pyproject.toml` (mirror `packages/sdk/pyproject.toml`'s shape):

```toml
[project]
name = "agentos-gateway"
version = "0.1.0"
description = "INT-07 — the framework-agnostic network gateway PEP. A reverse proxy that normalizes every request into an AgentAction and enforces the decision through the SAME agentos_sdk.enforce.governed_call core the SDK PEPs use, so an agent in ANY framework is governed with no SDK changes."
readme = "README.md"
requires-python = ">=3.12"
dependencies = [
    "agentos-contract",
    "agentos-sdk",
    "fastapi>=0.115",
    "httpx>=0.27",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/agentos_gateway"]
```

Create `packages/gateway/README.md` with one paragraph describing the package (hatchling needs the
readme file to exist).

Root `pyproject.toml`: add `"agentos-gateway"` to `[project] dependencies` and
`agentos-gateway = { workspace = true }` to `[tool.uv.sources]`. Then run `uv sync --all-packages`.

`normalize.py`:

```python
"""INT-07 — normalize an intercepted HTTP request into the contract's AgentAction.

The gateway is a PEP, so it does exactly what every other PEP form does: translate its native
request shape into an `AgentAction` and hand it to the ONE enforcement core. Registering with
`@covers` keeps INT-06 honest — the gateway is a real interception path, and the matrix says so.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from agentos_contract import ActionType, AgentAction
from agentos_sdk.coverage import covers


def agent_id_from_token(token: str) -> str:
    """The `sub` claim, WITHOUT verifying the signature — stage 1 does the verifying.

    Reading it here only labels the action; a forged token yields an agent_id the identity stage
    then rejects, so nothing is trusted on the strength of this parse.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return str(json.loads(base64.urlsafe_b64decode(payload)).get("sub", ""))
    except Exception:
        return ""


def _join_messages(messages: list[dict[str, Any]] | None) -> str:
    """Flatten chat messages to one inspectable string so the SEC-01 risk stage can scan them —
    an OpenAI-compatible body is exactly where indirect prompt injection arrives."""
    parts: list[str] = []
    for m in messages or []:
        content = m.get("content") if isinstance(m, dict) else None
        parts.append(content if isinstance(content, str) else json.dumps(content, default=str))
    return "\n".join(parts)


@covers(ActionType.model_invocation)
def normalize_gateway_model_call(body: dict[str, Any], token: str) -> AgentAction:
    """An OpenAI-compatible chat-completions request -> a model_invocation AgentAction."""
    model = str(body.get("model", "unknown"))
    return AgentAction(
        agent_id=agent_id_from_token(token),
        type=ActionType.model_invocation,
        target=model,
        payload={"model": model, "messages": _join_messages(body.get("messages"))},
        identity_token=token,
    )


@covers(ActionType.tool_call)
def normalize_gateway_tool_call(tool_name: str, body: dict[str, Any], token: str) -> AgentAction:
    """A gateway tool invocation -> a tool_call AgentAction. The JSON body IS the tool args."""
    return AgentAction(
        agent_id=agent_id_from_token(token),
        type=ActionType.tool_call,
        target=tool_name,
        payload=dict(body),
        identity_token=token,
    )
```

`__init__.py` exports `create_gateway`, `normalize_gateway_model_call`, `normalize_gateway_tool_call`.
(Import `create_gateway` from `.app`, which Task 3 creates — write `__init__.py` in Task 3 to avoid an
import error in Task 2; in Task 2 export only the two normalizers.)

**Steps (TDD):**
- [ ] Failing test `tests/unit/test_gateway_normalize.py`: build a token via a real
  `Registry(sf).register("gw-agent")` (mirror `tests/conftest.py::_new_store`), then assert
  `normalize_gateway_model_call({"model": "gpt-4o", "messages": [{"role":"user","content":"hi"}]}, token)`
  yields `type is ActionType.model_invocation`, `target == "gpt-4o"`, `agent_id == "gw-agent"`,
  `identity_token == token`, and `"hi" in payload["messages"]`;
  `normalize_gateway_tool_call("http_get", {"url": "https://x/"}, token)` yields
  `type is ActionType.tool_call`, `target == "http_get"`, `payload == {"url": "https://x/"}`;
  a garbage token yields `agent_id == ""` (and does NOT raise — stage 1 owns rejection).
  Run → fails.
- [ ] Create the package + normalizers + root pyproject wiring; `uv sync --all-packages`. Run → passes.
- [ ] Commit `feat(gateway): agentos-gateway package + AgentAction normalizers (INT-07)`.

---

### Task 3: the gateway app — govern, then proxy

**Files:**
- Create: `packages/gateway/src/agentos_gateway/app.py`
- Modify: `packages/gateway/src/agentos_gateway/__init__.py`
- Test: `tests/integration/test_gateway_pep.py`

```python
"""INT-07 — the framework-agnostic gateway PEP.

An agent adopts governance by pointing its `base_url` here; nothing in the agent changes. Every
request is normalized into an `AgentAction` and passed to `agentos_sdk.enforce.governed_call` — the
SAME outcome map the LangChain middleware and the SDK wrappers use. That is the whole design: the
gateway contributes normalization and transport, never a second enforcement path, so Phase-9
containment (sandbox quarantine, consensus quorum, resource budgets, breaker reporting) applies here
for free and cannot drift.

The forward is the `run` callable, so a governed block raises BEFORE any upstream request exists —
the no-egress contract holds at the network edge, not merely in the response body.
"""
from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse

from agentos_contract import PipelineProtocol
from agentos_sdk.enforce import GovernanceDenied, governed_call

from agentos_gateway.normalize import normalize_gateway_model_call, normalize_gateway_tool_call

TOKEN_HEADER = "x-agentos-token"
# Headers the gateway must never pass upstream: the governance token is ours alone, and hop-by-hop
# headers belong to this connection. host/content-length are recomputed by httpx.
_STRIP = frozenset({TOKEN_HEADER, "host", "content-length", "connection", "transfer-encoding"})


def _forward_headers(request: Request) -> dict[str, str]:
    return {k: v for k, v in request.headers.items() if k.lower() not in _STRIP}


def _denied_response(exc: GovernanceDenied) -> JSONResponse:
    """A governed block, surfaced in the caller's language. 403 (not 500): the request was
    understood and refused. The fired reasons travel; raw payload never does."""
    return JSONResponse(
        status_code=403,
        content={
            "error": {
                "type": "agentos_guard_blocked",
                "message": str(exc),
                "reasons": [
                    {"stage": r.stage, "code": r.code} for r in exc.decision.reasons
                ],
                "action_id": str(exc.decision.action_id),
            }
        },
    )


def create_gateway(
    pipeline: PipelineProtocol,
    *,
    upstream_base_url: str,
    client: httpx.AsyncClient | None = None,
    coordinator: Any | None = None,
    sandbox: Any | None = None,
    governor: Any | None = None,
    reporter: Any | None = None,
    consensus: Any | None = None,
) -> FastAPI:
    """Build the gateway ASGI app. The Phase-9 seams are pass-through parameters so a deployment
    gets identical containment here and in the SDK — a gateway wired without them fails CLOSED on
    those outcomes, exactly like an unwired SDK PEP."""
    app = FastAPI(title="agentos-guard gateway", version="0.1.0")
    router = APIRouter()
    http = client or httpx.AsyncClient(base_url=upstream_base_url, timeout=30.0)

    async def _proxy(path: str, request: Request, body: bytes) -> JSONResponse:
        upstream = await http.post(path, content=body, headers=_forward_headers(request))
        return JSONResponse(status_code=upstream.status_code, content=upstream.json())

    @router.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        token = request.headers.get(TOKEN_HEADER, "")
        body: dict[str, Any] = await request.json()
        action = normalize_gateway_model_call(body, token)
        raw = await request.body()
        try:
            return await governed_call(
                pipeline,
                action,
                lambda: _proxy("/v1/chat/completions", request, raw),
                coordinator=coordinator,
                sandbox=sandbox,
                governor=governor,
                reporter=reporter,
                consensus=consensus,
            )
        except GovernanceDenied as denied:
            return _denied_response(denied)

    @router.post("/tools/{tool_name}")
    async def tool_call(tool_name: str, request: Request) -> JSONResponse:
        token = request.headers.get(TOKEN_HEADER, "")
        body: dict[str, Any] = await request.json()
        action = normalize_gateway_tool_call(tool_name, body, token)
        raw = await request.body()
        try:
            return await governed_call(
                pipeline,
                action,
                lambda: _proxy(f"/tools/{tool_name}", request, raw),
                coordinator=coordinator,
                sandbox=sandbox,
                governor=governor,
                reporter=reporter,
                consensus=consensus,
            )
        except GovernanceDenied as denied:
            return _denied_response(denied)

    app.include_router(router)
    return app
```

> Read `packages/sdk/src/agentos_sdk/enforce.py` and pass exactly the keyword seams `governed_call`
> actually accepts at this commit; if a name differs, match the source rather than this snippet.

`__init__.py`:
```python
"""agentos-gateway — the INT-07 framework-agnostic network PEP."""
from agentos_gateway.app import TOKEN_HEADER, create_gateway
from agentos_gateway.normalize import normalize_gateway_model_call, normalize_gateway_tool_call

__all__ = [
    "create_gateway",
    "TOKEN_HEADER",
    "normalize_gateway_model_call",
    "normalize_gateway_tool_call",
]
```

**Steps (TDD):**
- [ ] Failing test `tests/integration/test_gateway_pep.py` using the REAL governed stack (mirror
  `tests/integration/test_kill_switch_api.py` for shared-store wiring and the compiled-constitution
  pipeline). Build a **stub upstream** as its own tiny FastAPI app whose handler increments
  `calls["n"]` and returns `{"ok": True}`, mounted behind an
  `httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream), base_url="http://upstream")`, and
  pass that client into `create_gateway(...)`. Drive the gateway with
  `fastapi.testclient.TestClient`. Assert:
  - **allow proxies**: a benign allowlisted tool call with a valid `X-Agentos-Token` → 200, body
    `{"ok": True}`, and `calls["n"] == 1`;
  - **deny never egresses** (the load-bearing assertion): an exfil call to a non-allowlisted host →
    403, `error.type == "agentos_guard_blocked"`, a `constitution_principle_fired` reason present,
    and **`calls["n"]` unchanged** — the upstream was never contacted;
  - **no token → denied unproxied**: omit `X-Agentos-Token` → 403 with a
    `forged_or_unknown_identity` reason and `calls["n"]` unchanged;
  - **the governance token is not forwarded**: capture the headers the stub upstream received on the
    allowed call and assert `x-agentos-token` is absent while `authorization` (set to a dummy
    upstream key) IS present;
  - **model route**: an OpenAI-compatible `/v1/chat/completions` body whose message carries an
    injection string is denied with a risk reason and `calls["n"]` unchanged;
  - **coverage**: `verify_coverage()` does not raise and `coverage_matrix()[ActionType.tool_call]`
    contains an entry ending in `normalize_gateway_tool_call`.
  Run → fails.
- [ ] Implement `app.py` + `__init__.py`. Run → passes.
- [ ] Commit `feat(gateway): govern-then-proxy PEP — a block never reaches upstream (INT-07)`.

---

### Task 4: full gate
- [ ] `./.venv/Scripts/python.exe -m pytest -q` green; `-m floor_invariant`, `-m regression_lock`
  green. Run `-m latency`; if a wall-clock benchmark fails, re-run when idle and compare against a
  scratch worktree at the Phase-9 base before attributing it (the gateway adds nothing to the PDP hot
  path).
- [ ] Confirm the wheel builds: `uv build --wheel --package agentos-gateway` succeeds.
- [ ] Commit only if incidental fixes were needed.

## Self-review
INT-07 is realized: a network PEP governs actions with no SDK changes (an agent just repoints
`base_url`), behind the same `evaluate(AgentAction) -> Decision` contract. It contributes
normalization + transport only — enforcement goes through the one `governed_call` core, so Phase-9
containment applies unchanged and cannot drift, and the Phase-9 seams are pass-through so an unwired
gateway fails closed exactly like an unwired SDK PEP. The no-egress contract is asserted at the
network edge with an upstream call counter, not from the response body. The governance token is
consumed and provably not forwarded; the upstream credential passes through untouched. INT-06 stays
honest: the registry now records EVERY PEP form per action type instead of letting the newest
registration evict the others, with a test that pins the multi-PEP property. Gates green; nothing
added to the per-action hot path.
