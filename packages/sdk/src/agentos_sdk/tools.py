"""The single governed tool: http_get (D-01).

This is a TEST FIXTURE, not the product — the whole point of Phase 1 is governing it,
not building a featureful HTTP client. It is a LangChain tool over the stdlib
`urllib` (no extra dependency) that fetches a URL and returns its body text. Egress
governance lives in the PEP/pipeline, NOT here: the tool only ever runs when the PDP
already returned `allow` (a `deny` short-circuits in the middleware before `handler`
is ever called), so the tool body deliberately performs no allowlisting of its own.
"""

from __future__ import annotations

from urllib.request import urlopen

from langchain.tools import tool


@tool
def http_get(url: str) -> str:
    """Fetch the given URL and return its response body as text (the governed tool)."""
    with urlopen(url, timeout=10) as resp:  # noqa: S310 — governed upstream by the PEP
        return resp.read().decode("utf-8", "replace")
