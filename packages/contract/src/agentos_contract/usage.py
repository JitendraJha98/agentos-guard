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

# A token count has to survive the BigInteger column the ledger is stored in. A provider will never
# report 2^63 tokens, but an attacker-influenced result can SAY it did, and an int that overflows on
# INSERT makes the whole record vanish through the PEP's metering swallow — a one-call primitive for
# turning your own metering off. So the bound is enforced where the value is born, not at the insert.
_MAX_TOKENS = 2**63 - 1


def _is_reported_count(value: object) -> bool:
    """A count a provider could actually have reported: a plain non-negative int that fits the
    ledger column.

    `type(...) is int`, not `isinstance`, because `bool` IS an int in Python and
    `{"input_tokens": True}` would otherwise bill one token. Negatives are the load-bearing half:
    `PriceBook` multiplies straight through and `totals()` SUMs, so one result claiming
    -10,000,000 input tokens moves an agent's ledger arbitrarily negative — a budget-evasion
    primitive for Slice 11c, and the exact inverse of D-7's "never fabricate a figure".
    """
    return type(value) is int and 0 <= value <= _MAX_TOKENS


@dataclass(frozen=True)
class Usage:
    """Reported token usage for one call. `model` is what the provider says it SERVED, when it says
    so at all — an alias can resolve to a dated snapshot, and the served name is the one a bill has
    to be written against."""

    input_tokens: int
    output_tokens: int
    model: str | None = None

    def __post_init__(self) -> None:
        for name in ("input_tokens", "output_tokens"):
            value = getattr(self, name)
            if not _is_reported_count(value):
                raise ValueError(
                    f"Usage.{name} must be a non-negative int within the ledger column "
                    f"(0..{_MAX_TOKENS}); got {value!r}"
                )

    @classmethod
    def reported(
        cls, input_tokens: object, output_tokens: object, model: object = None
    ) -> "Usage | None":
        """Build a `Usage` from values a PROVIDER supplied, or None when they are not usable counts.

        The two callers — the SDK's `extract_usage` and the gateway's response mapper — both read
        numbers off objects they do not control, and both must answer "we do not know" rather than
        raise or fabricate. Sharing this one constructor is what keeps their idea of a plausible
        count from drifting; `__post_init__` above stays the hard invariant for anything built by
        hand.
        """
        if _is_reported_count(input_tokens) and _is_reported_count(output_tokens):
            return cls(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                model=model if isinstance(model, str) else None,
            )
        return None
