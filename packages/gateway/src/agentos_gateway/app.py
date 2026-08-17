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
from agentos_sdk.enforce import (
    ApprovalCoordinator,
    CircuitReporter,
    ConsensusCoordinator,
    GovernanceDenied,
    ResourceGovernor,
    SandboxRunner,
    SideEffectDispatcher,
    governed_call,
)

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
                "reasons": [{"stage": r.stage, "code": r.code} for r in exc.decision.reasons],
                "action_id": str(exc.decision.action_id),
            }
        },
    )


def create_gateway(
    pipeline: PipelineProtocol,
    *,
    upstream_base_url: str,
    client: httpx.AsyncClient | None = None,
    coordinator: ApprovalCoordinator | None = None,
    dispatcher: SideEffectDispatcher | None = None,
    sandbox: SandboxRunner | None = None,
    consensus: ConsensusCoordinator | None = None,
    governor: ResourceGovernor | None = None,
    reporter: CircuitReporter | None = None,
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

    async def _govern(action, path: str, request: Request) -> JSONResponse:
        """The ONE enforcement site: `governed_call` decides, the forward is its `run`."""
        raw = await request.body()
        try:
            return await governed_call(
                pipeline,
                action,
                lambda: _proxy(path, request, raw),
                coordinator=coordinator,
                dispatcher=dispatcher,
                sandbox=sandbox,
                consensus=consensus,
                governor=governor,
                reporter=reporter,
            )
        except GovernanceDenied as denied:
            # Covers deny, quarantine, a missing quorum and a budget breach alike: every one of
            # them means "no usable result", and on all but a post-hoc budget breach the forward
            # above was never even constructed.
            return _denied_response(denied)

    @router.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        token = request.headers.get(TOKEN_HEADER, "")
        body: dict[str, Any] = await request.json()
        return await _govern(
            normalize_gateway_model_call(body, token), "/v1/chat/completions", request
        )

    @router.post("/tools/{tool_name}")
    async def tool_call(tool_name: str, request: Request) -> JSONResponse:
        token = request.headers.get(TOKEN_HEADER, "")
        body: dict[str, Any] = await request.json()
        return await _govern(
            normalize_gateway_tool_call(tool_name, body, token), f"/tools/{tool_name}", request
        )

    app.include_router(router)
    return app
