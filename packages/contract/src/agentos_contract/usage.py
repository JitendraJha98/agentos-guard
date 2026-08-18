"""Usage — what a provider REPORTED for one call (ECON-01).

It lives in the contract for the same reason `SandboxResult` does: both sides of the metering seam
need it. The PEP reads it off a framework's return value (`agentos_sdk.usage.extract_usage`) and the
control plane's `CostRecorder` persists it, and `agentos-controlplane` depends on `agentos-contract`
only — so putting it in the SDK would make the control plane import upwards.

There is no `total_tokens` field on purpose. Providers do not agree on what a total includes (cached
reads, reasoning tokens), so a persisted total would be a number whose meaning varies by provider
while looking comparable across them; input + output are the two figures every provider reports the
same way, and they are the two a price book charges against.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Usage:
    """Reported token usage for one call. `model` is what the provider says it SERVED, when it says
    so at all — an alias can resolve to a dated snapshot, and the served name is the one a bill has
    to be written against."""

    input_tokens: int
    output_tokens: int
    model: str | None = None
