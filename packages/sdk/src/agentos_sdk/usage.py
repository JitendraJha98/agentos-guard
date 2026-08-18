"""Reported usage, read off a framework's return value (ECON-01, PEP side).

It sits beside `normalize.py` because it is the same job in the other direction: `normalize` turns a
framework's call into the contract's `AgentAction` on the way IN, this turns a framework's result
into the contract's `Usage` on the way OUT. Both are framework-shape knowledge, and both belong on
the PEP side so the control plane never learns what an `AIMessage` is.

Usage is REPORTED, never inferred (spec D-7). The tempting alternative — estimate tokens by counting
characters — produces a number that looks authoritative, is provider-specific, and is wrong in ways
the operator cannot see. So when nothing recognizable is there this returns None, and the caller
records NOTHING rather than a zero.
"""

from __future__ import annotations

from agentos_contract import Usage


def _field(obj: object, name: str) -> object | None:
    """Read `name` from a mapping key or an attribute.

    LangChain reports usage as a dict (`AIMessage.usage_metadata`) and the OpenAI Agents SDK as a
    dataclass (`agents.usage.Usage`); both use the same field names. One duck-typed reader beats two
    provider-specific branches that drift apart the first time a third framework lands.
    """
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _reported_by(obj: object) -> Usage | None:
    """Usage carried by `obj` ITSELF, in one of the two shapes a provider reports it in.

    The object is only ever consulted through a NAMED usage holder — never duck-typed as a whole.
    An earlier version fell back to reading `input_tokens`/`output_tokens` off the returned value
    directly, which meant any tool or MCP result shaped like usage wrote the ledger: a `count_tokens`
    tool billed its own answer, and an attacker-influenced MCP response could post a negative row.
    A provider reports usage under `usage`/`usage_metadata`; a tool return value is not a provider.
    """
    for holder in (
        _field(obj, "usage_metadata"),  # LangChain AIMessage
        _field(obj, "usage"),  # OpenAI Agents RunResult / Anthropic Message / gateway mapper
    ):
        if holder is None:
            continue
        if isinstance(holder, Usage):
            # Already normalized by a caller that knows the wire format (the gateway's response
            # mapper). Returned UNCHANGED: rebuilding it would re-read the served model off the
            # outer object, which does not carry one, and silently record a priced model as unpriced.
            return holder
        usage = Usage.reported(
            _field(holder, "input_tokens"), _field(holder, "output_tokens"), _model(obj)
        )
        if usage is not None:
            return usage
    return None


def extract_usage(result: object) -> Usage | None:
    """Pull reported usage off a returned object, or None when nothing recognizable is there.

    Returning None is the load-bearing behavior: a caller must be able to tell 'no usage reported'
    from 'zero tokens used', because only one of those means the action was free.
    """
    usage = _reported_by(result)
    if usage is not None:
        return usage
    # langchain 1.x does NOT hand the model hook the message. `awrap_model_call`'s handler returns a
    # `ModelResponse` dataclass whose `.result` is the message list, and that object carries no
    # usage of its own — so reading only the outer value metered NOTHING on the one action type that
    # has a token cost, for the flagship PEP. The usage (and the served model) are on the messages.
    messages = _field(result, "result")
    if isinstance(messages, list):
        for message in messages:
            usage = _reported_by(message)
            if usage is not None:
                return usage
    return None


def _model(result: object) -> str | None:
    """The model the provider says it SERVED, or None. Never guessed — an absent name lets the
    recorder fall back to the model the action REQUESTED, which is a different (weaker) claim and
    is made in one place rather than fabricated here."""
    meta = _field(result, "response_metadata")
    if meta is None:
        return None
    model = _field(meta, "model_name") or _field(meta, "model")
    return model if isinstance(model, str) else None
