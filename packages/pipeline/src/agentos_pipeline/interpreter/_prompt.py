"""Shared prompt fragments for interpreter adapters (POL-04). The action-sourced
values are XML-escaped so payload text cannot break out of the labelled block
(Pitfall 5); the runner's restrict-only clamp backstops the verdict regardless."""
from __future__ import annotations
from xml.sax.saxutils import escape
from agentos_pipeline.interpreter.protocol import InterpretationRequest

_ATTR_QUOTE = {'"': "&quot;"}


def principles_block(request: InterpretationRequest) -> str:
    return "\n".join(
        f'  <principle ref="{ref}" title="{title}">{statement}</principle>'
        for ref, title, statement in request.principles
    )


def data_block(request: InterpretationRequest) -> str:
    guardrails = ",".join(f"{name}={flag}" for name, flag in request.guardrails)
    return (
        f'<action_data type="{request.action_type}" '
        f'target="{escape(request.target, _ATTR_QUOTE)}" '
        f'intent="{escape(request.intent_class, _ATTR_QUOTE)}" '
        f'guardrails="{guardrails}">\n'
        f"<payload_excerpt>{escape(request.payload_excerpt)}</payload_excerpt>\n"
        "</action_data>\n"
        "Return the verdict."
    )
