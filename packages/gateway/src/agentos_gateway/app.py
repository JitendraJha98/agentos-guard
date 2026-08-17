"""INT-07 — the framework-agnostic gateway PEP.

An agent adopts governance by pointing its `base_url` here; nothing in the agent changes. Every
request is normalized into an `AgentAction` and passed to `agentos_sdk.enforce.governed_call` — the
SAME outcome map the LangChain middleware and the SDK wrappers use. That is the whole design: the
gateway contributes normalization and transport, never a second enforcement path, so Phase-9
containment (sandbox quarantine, consensus quorum, resource budgets, breaker reporting) applies here
for free and cannot drift.

The forward is the `run` callable, so a governed block raises BEFORE any upstream request exists —
the no-egress contract holds at the network edge, not merely in the response body.

Two properties carry that contract across the transport boundary and are asserted as such: the
string handed to the PDP is the SAME string the upstream is asked for (a proxy that governs one
name and requests another enforces nothing), and a request the gateway cannot normalize is
refused with a 400 rather than raising — a PEP an agent can fuzz into tracebacks is a PEP it can
probe for free, leaving no decision and no evidence behind.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
from fastapi import APIRouter, FastAPI, Request, Response
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
# Headers the gateway must never pass upstream. The governance token is ours alone; the rest is the
# RFC 7230 6.1 hop-by-hop set, which belongs to THIS connection and must not cross a proxy boundary
# — `upgrade`/`te` are protocol-confusion primitives, `proxy-authorization` is credential
# forwarding, and `expect: 100-continue` (not hop-by-hop, but equally undeliverable) would stall a
# compliant upstream until our timeout because httpx does not implement it, which is a free
# client-driven DoS. host/content-length are recomputed by httpx.
#
# `authorization` and `cookie` are deliberately NOT stripped: they are the CALLER's credential for
# the upstream it chose, and a PEP that ate them would break every real deployment.
_STRIP = frozenset(
    {
        TOKEN_HEADER,
        "host",
        "content-length",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "expect",
    }
)

# A tool name is an identifier, not a URL fragment. It has to survive into the upstream path
# UNCHANGED, so the string the PDP governed and the resource the upstream serves are ONE string:
# `#` truncates the path httpx builds and `?` turns the tail into a query (so the gated
# `/tools/x` would run under the ungoverned name `x#y`), a `.`/`..` segment collapses out of the
# path entirely, and an unbounded name is an attacker-controlled label on every audit record,
# breaker key and privilege lookup. The leading character excludes `.`, so both dot segments are
# refused by the pattern itself.
_TOOL_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}")


def _forward_headers(request: Request) -> dict[str, str]:
    # RFC 7230 6.1: every token NAMED in `Connection` is hop-by-hop for this connection too, so
    # the strip set is per-request, not static.
    connection = request.headers.get("connection", "")
    named = {t.strip().lower() for t in connection.split(",") if t.strip()}
    return {k: v for k, v in request.headers.items() if k.lower() not in _STRIP | named}


def _bad_request(message: str) -> JSONResponse:
    """A request the gateway cannot turn into an `AgentAction` at all — 400, never a traceback.

    Nothing is governed on this path because there is nothing to govern: no action was
    normalized, so nothing reached the PDP and nothing left the gateway. Answering a malformed
    probe with a 500 would let an agent fuzz the PEP for free at the cost of a traceback each.
    """
    return JSONResponse(
        status_code=400,
        content={"error": {"type": "agentos_guard_bad_request", "message": message}},
    )


async def _json_object(request: Request) -> dict[str, Any] | None:
    """The body as a JSON object, or None when it is anything else (unparseable, a list, a
    scalar, empty). Normalizing a non-object would fabricate an action nobody requested."""
    try:
        body = await request.json()
    except Exception:
        return None
    return body if isinstance(body, dict) else None


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
    http = client or httpx.AsyncClient(timeout=30.0)
    # The DECLARED destination is the one permitted egress target, so every forward is built from
    # it as an ABSOLUTE url. Resolving the path against an injected client's own `base_url`
    # instead would let a misconfigured client silently redirect governed traffic elsewhere, with
    # no error — which would make `upstream_base_url` advisory.
    upstream_url = upstream_base_url.rstrip("/")

    async def _proxy(path: str, request: Request, body: bytes) -> Response:
        # A transport fault must PROPAGATE out of the `run` callable: `governed_call` reports a
        # raising execution to the RUN-06 CircuitReporter, which is how repeated upstream failures
        # trip the breaker. Swallowing it here and returning 502 made the run callable always
        # succeed, so gateway traffic could never trip a breaker — RUN-06 silently did not apply
        # to this PEP form. The 502 surface is built OUTSIDE governed_call instead (see _govern),
        # so the caller still gets an honest upstream error AND the breaker still sees the failure.
        upstream = await http.post(
            upstream_url + path, content=body, headers=_forward_headers(request)
        )
        # Relay BYTES, not JSON. An upstream legitimately answers HTML, an empty 204 or an SSE
        # stream, and re-parsing every response as JSON turned each of those into a gateway 500 —
        # including every `"stream": true` request. (SSE is relayed complete rather than
        # incrementally: the governed forward is one awaited call, so the body is buffered here.)
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type"),
        )

    async def _govern(action, path: str, request: Request) -> Response:
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
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            # The UPSTREAM failed, not governance — and by the time we are here `governed_call`
            # has ALREADY reported the failure to the circuit breaker (that is why _proxy lets it
            # propagate). A 500 would blame the gateway for a transport fault and hide the real
            # one. `InvalidURL` is NOT an httpx.HTTPError subclass, so it is named explicitly —
            # a malformed upstream_base_url would otherwise escape as an un-audited 500.
            return JSONResponse(
                status_code=502,
                content={
                    "error": {
                        "type": "agentos_guard_upstream_unreachable",
                        "message": "upstream request failed",
                        # The class name only — a message can quote the request back.
                        "reason": type(exc).__name__,
                    }
                },
            )

    @router.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        body = await _json_object(request)
        if body is None:
            return _bad_request("body must be a JSON object")
        token = request.headers.get(TOKEN_HEADER, "")
        return await _govern(
            normalize_gateway_model_call(body, token), "/v1/chat/completions", request
        )

    @router.post("/tools/{tool_name}")
    async def tool_call(tool_name: str, request: Request) -> Response:
        if not _TOOL_NAME.fullmatch(tool_name):
            # Refused BEFORE governing: a name that cannot be forwarded verbatim would be
            # governed as one resource and requested as another.
            return _bad_request("tool name must match [A-Za-z0-9_-][A-Za-z0-9._-]{0,127}")
        body = await _json_object(request)
        if body is None:
            return _bad_request("body must be a JSON object")
        token = request.headers.get(TOKEN_HEADER, "")
        return await _govern(
            normalize_gateway_tool_call(tool_name, body, token), f"/tools/{tool_name}", request
        )

    app.include_router(router)
    return app
