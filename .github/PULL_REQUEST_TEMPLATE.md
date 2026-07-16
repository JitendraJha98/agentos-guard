## What & why

<!-- What does this change do, and why? Link the issue / REQ-ID (e.g. SDK-03). -->

## How it was verified

<!-- The gates you ran locally. Paste output for anything non-trivial. -->

- [ ] `uv run pytest -q` green
- [ ] `uv run pytest -m regression_lock --maxfail=1` green
- [ ] `uv run pytest -m floor_invariant` green
- [ ] `uv run pytest -m latency` green (if the hot path changed)
- [ ] Docs/requirements updated if behavior changed

## Guarantees checklist

- [ ] Does **not** weaken the policy floor (risk/trust may only restrict, never relax)
- [ ] Identity / redaction / audit still fail **closed**
- [ ] Telemetry can never raise into the verdict
- [ ] New/fixed vulnerabilities are locked by a `regression_lock` test

## Notes for the reviewer

<!-- Anything that needs attention: trade-offs, follow-ups, out-of-scope items. -->
