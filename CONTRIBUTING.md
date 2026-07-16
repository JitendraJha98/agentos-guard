# Contributing to agentos-guard

Thanks for helping build the governance & security control plane for AI agents. This
guide covers how to get set up, the bar a change must clear, and how work is organized.

> Building a **security** product: correctness and evidence matter more than speed. A
> change that weakens a governance guarantee — even subtly — will not merge. See
> [`SECURITY.md`](SECURITY.md) for reporting vulnerabilities (do **not** file those as
> public issues).

## Ground rules (from `CLAUDE.md`)

- **Think before coding.** State assumptions; if multiple interpretations exist,
  surface them. If a simpler approach exists, propose it.
- **Simplicity first.** The minimum code that solves the problem — no speculative
  features or single-use abstractions.
- **Surgical changes.** Touch only what the change requires; match existing style;
  don't reformat working adjacent code.
- **Goal-driven.** Turn a task into a verifiable goal (e.g. "fix the bug" → "a failing
  test that reproduces it, then make it pass").

## Project layout

A [uv](https://docs.astral.sh/uv/) workspace of five packages under `packages/`:

| Package | Role |
|---------|------|
| `agentos-contract` | The stable, serializable boundary (`AgentAction` + `Decision`). Zero internal deps — built first. |
| `agentos-pipeline` | The 5-stage decision pipeline (identity → policy → risk → graduated → audit) + telemetry seam. |
| `agentos-constitution` | Constitution → YAML → OPA/Rego compiler. |
| `agentos-controlplane` | Resource API, store, audit chain, identity engine, compliance export. |
| `agentos-sdk` | LangChain/LangGraph PEP middleware, control-plane client, red-team harness. |

Design docs live in `docs/architecture/` (authoritative). Execution planning lives in
`.planning/` (roadmap, requirements, phase state).

## Development setup

Prerequisites: **Python 3.12+**, **uv**, and the pinned **OPA CLI** (`1.9.0`) on `PATH`
(the test constitutions compile to WASM at session start).

```bash
# install uv: https://docs.astral.sh/uv/getting-started/installation/
uv sync --all-packages            # workspace + dev group (pytest)
uv sync --all-packages --group redteam   # adds garak + pyrit (heavy; only for the red-team gate)
```

Install OPA `1.9.0` from https://openpolicyagent.org/downloads and make sure `opa
version` works.

## Running the checks

Every change must keep CI green. The same gates run locally:

```bash
uv run pytest -q                                   # full deterministic suite
uv run pytest -m regression_lock --maxfail=1       # safety-regression locks (must never go red)
uv run pytest -m floor_invariant                   # risk/trust never relax the policy floor
uv run pytest -m latency                           # hot-path latency budget (PIPE-04)
uv run pytest tests/unit -k detector --count=100 -q # detector determinism (non-flaky verdict)
uv run pytest tests/redteam/test_garak_pyrit_gate.py -q  # garak/PyRIT ASR gate (needs redteam extra)
```

Custom pytest markers: `regression_lock`, `floor_invariant`, `latency`.

## The bar for a change

1. **Tests first.** New behavior ships with tests; a bugfix ships with a failing test
   that your change makes pass. Fixed vulnerabilities get a `regression_lock` test so
   they cannot silently return.
2. **Never weaken a guarantee.** The policy floor is a floor (risk/trust may only
   *restrict*, never relax it); identity/redaction/audit fail **closed**; telemetry may
   never raise into the verdict. Changes here need explicit tests proving the guarantee
   still holds.
3. **Green gates at every commit** — the suite, the regression locks, the floor
   invariant, and the latency budget.
4. **Match the docs.** If you change behavior described in `docs/architecture/` or a
   requirement in `.planning/REQUIREMENTS.md`, update it in the same PR.

## Workflow

1. Branch off **`development`** (not `main` — `main` is the protected release branch).
2. Keep commits focused; write a message that explains *why*, and tag the relevant
   REQ-ID (e.g. `feat(sdk): … (SDK-03)`).
3. Open a PR into `development`. Fill in the PR template. CI (`test` + `redteam`) must
   pass.
4. Releases are cut from `main` via tags; see `.github/workflows/release.yml`.

## Reporting bugs & requesting features

Use the issue templates. For anything with a **security impact**, follow
[`SECURITY.md`](SECURITY.md) instead of opening a public issue.

## License

By contributing you agree your contributions are licensed under the project's
[MIT License](LICENSE).
