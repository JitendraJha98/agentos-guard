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


def extract_usage(result: object) -> Usage | None:
    """Pull reported usage off a returned object, or None when nothing recognizable is there.

    Returning None is the load-bearing behavior: a caller must be able to tell 'no usage reported'
    from 'zero tokens used', because only one of those means the action was free.
    """
    for holder in (
        _field(result, "usage_metadata"),  # LangChain AIMessage
        _field(result, "usage"),  # OpenAI Agents RunResult / raw response
        result,  # a Usage-shaped object returned directly
    ):
        if holder is None:
            continue
        inp, out = _field(holder, "input_tokens"), _field(holder, "output_tokens")
        if isinstance(inp, int) and isinstance(out, int):
            return Usage(input_tokens=inp, output_tokens=out, model=_model(result))
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
