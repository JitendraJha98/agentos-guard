<div align="center">

# 🛡️ agentos-guard

### The governance & security control plane for AI agents

*Intercept every agent action. Reason about it. Respond on a spectrum. Prove it happened.*

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/)
[![CI](https://github.com/JitendraJha98/agentos-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/JitendraJha98/agentos-guard/actions/workflows/ci.yml)
[![Status: alpha](https://img.shields.io/badge/status-alpha%20·%20phase%206%2F14-orange.svg)](.planning/ROADMAP.md)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#-contributing)

[**Manifesto**](docs/architecture/00-manifesto.md) · [**Architecture**](docs/architecture/) · [**Roadmap**](.planning/ROADMAP.md) · [**vs Microsoft AGT**](docs/architecture/30-comparison-agt.md)

</div>

---

agentos-guard sits between your AI agents and everything they touch — **tools, memory, MCP servers,
models, APIs, and each other** — and intercepts **every action before it executes**. Each action is
checked against a living, human-readable **constitution** and deterministic policy, scored for risk,
bound to a cryptographic identity + trust score, and returned a **graduated decision**. Every
decision becomes tamper-evident audit evidence, and a pytest-native red-team layer makes a safety
regression **break your CI build** like a failing unit test.

Think *Kubernetes + OPA + Istio + a flight recorder* — but for autonomous agents, in one
self-hostable control plane.

## ✨ The paradigm

Most agent-governance tools — including Microsoft's Agent Governance Toolkit — run one reflex:

```
Distrust  →  Block  →  Log          (deterministic rules · no semantic layer · per-action only)
```

That's a firewall bolted in front of a reasoning system. agentos-guard runs a different reflex:

```
Trust  →  Verify  →  Graduate  →  Prove
```

> Establish **who** is acting and how much they've earned trust. **Verify** against a constitution
> that reasons about *intent*, not just matching strings. **Graduate** the response across a
> spectrum instead of a coin-flip. And make the evidence **provable**, not merely append-only.

Full thesis → [`docs/architecture/00-manifesto.md`](docs/architecture/00-manifesto.md).

## 🏛️ How it works

```mermaid
flowchart LR
    A[AI Agent] -->|attempts action| PEP[Policy Enforcement Point<br/>SDK · gateway · sidecar]
    PEP -->|normalized AgentAction| P
    subgraph P [Decision Pipeline]
        direction LR
        ID[1· Identity<br/>& Trust] --> POL[2· Policy<br/>Constitution→OPA/Rego]
        POL --> RISK[3· Risk<br/>injection · intent]
        RISK --> GR[4· Graduated<br/>Response]
    end
    P -->|Decision + reasons| PEP
    P -.->|tamper-evident| AUD[(Hash-chained<br/>audit log)]
    PEP -->|allow · warn · sandbox · consensus · approval · exception · review · deny<br/>+ side-effects| T[Tools · MCP · Models · Memory]
```

1. **Intercept** — a Policy Enforcement Point captures the action before it runs.
2. **Normalize** — it becomes one `AgentAction` event, regardless of framework.
3. **Decide** — the synchronous pipeline runs `identity/trust → policy → risk → graduated response`.
4. **Enforce** — allow, warn, sandbox, require consensus, escalate to a human, grant a time-boxed exception, open an async governance review, or deny — with composable side-effects (notify · monitor · risk-flag · open-incident).
5. **Record** — a signed, hash-chained audit record + OpenTelemetry spans.

## 🚀 Why agentos-guard — the seven pillars

Each pillar names a weakness in the deterministic-only model and the answer. **None requires
blockchain or tokens** ([ADR-0007](docs/architecture/adr/0007-no-crypto-economics-in-core.md)).

| # | Instead of… | agentos-guard gives you | |
|---|-------------|--------------------------|---|
| 1 | deterministic rules with no semantic layer ("actions, not reasoning") | a **living semantic constitution** agents can query | [04](docs/architecture/04-constitution-and-policy.md) |
| 2 | a three-outcome ceiling (allow / deny / require-approval) | **graduated response** — allow · warn · sandbox · consensus · approval · time-boxed exception · async review · deny + composable side-effects | [04](docs/architecture/04-constitution-and-policy.md) |
| 3 | per-action, stateless evaluation | **intent-based policy** — correlates across actions to catch `rename_then_drop` & novel sequences | [05](docs/architecture/05-security-and-runtime.md) |
| 4 | per-agent isolation | **cross-agent permission calculus** — catches the confused-deputy in delegation | [06](docs/architecture/06-identity-trust-discovery.md) |
| 5 | `GovernanceDenied: rule X` | **explainable denials with remediation paths** | [02](docs/architecture/02-domain-model.md) |
| 6 | a one-shot red-team CLI scan | a **CI-gating** red-team that breaks the build + self-play | [08](docs/architecture/08-testing-and-redteam.md) |
| 7 | raw, unredacted audit of attempts | **provable** evidence: fail-closed redaction + provenance → Merkle → zero-knowledge proofs | [07](docs/architecture/07-audit-and-compliance.md) |

## 🆚 vs. Microsoft AGT (honest — verified 2026-06-10, AGT v4.1.0)

| Dimension | AGT / RAMPART | agentos-guard |
|-----------|---------------|---------------|
| Policy | Deterministic only — no semantic layer ("actions, not reasoning") | Semantic constitution + intent reasoning over a deterministic OPA floor |
| Cross-action intent | None — per-action, stateless | Sequence/lineage correlation catches `rename_then_drop` |
| Enforcement | allow / deny / require-approval | Eight graduated outcomes + composable side-effects |
| Memory governance | Admitted gap (their `LIMITATIONS.md`) | Memory access intercepted & governed |
| Denials | Rule id | Cited principle + evidence + remediation |
| Red-team | CLI scan | Continuous, **gates CI**, self-play |
| Audit | Merkle-chained, but raw unredacted parameters | Fail-closed redaction + provenance → Merkle → ZK proofs |

We're inspired by AGT and positioned as **the semantic-judgment and memory-governance layer that
deterministic enforcers — by their own docs — don't provide**. And we say where we are: AGT leads
today on framework breadth (19+ integrations), language SDKs (5), SPIFFE/mTLS identity, sandboxing,
and its MCP gateway — those land across our roadmap. AGT ships monthly, so this comparison is
re-verified each phase. Full scorecard →
[`30-comparison-agt.md`](docs/architecture/30-comparison-agt.md).

## 📦 Project status

> **Alpha — building in public, in vertical slices.** Not yet published to PyPI.

**✅ Shipped (Phase 1 — the walking skeleton):** one LangGraph agent, one governed tool, one
constitution principle, proven **end-to-end** — interception → `AgentAction` → identity (EdDSA) →
OPA/Rego policy → prompt-injection risk → graduated response → hash-chained fail-closed audit — with
a red-team test that **breaks CI if the policy is removed**.

**✅ Shipped (Phase 2 — full interception coverage):** all five action types
(**tool · model · memory · MCP · delegation**) intercepted and run through the same pipeline — model
calls governed via the LangChain `awrap_model_call` hook, memory/MCP/delegation via SDK wrappers
sharing one enforcement core, delegation capturing `parent_action_id` lineage. An interception-coverage
check proves **no silent gaps**, and a bypass attempt (un-instrumented / no-identity action) is
fail-closed denied, not silently allowed.

**✅ Shipped (Phase 3 — constitution, graduated response, approvals & sequence intent):** a
human-readable YAML constitution **compiles to OPA/Rego** (WASM, in-process), decisions span the
full graduated spectrum with policy-driven thresholds (trust modulates but **never relaxes the
policy floor**), a working human-approval workflow with time-boxed ratified exceptions, an
advisory semantic interpreter (Anthropic/NVIDIA adapters, restrict-only clamp), and **cross-action
sequence-intent correlation** (SEC-13) — proven by the 5-minute
[`rename_then_drop` wedge demo](examples/wedge_demo.py).

**✅ Shipped (Phase 4 — tamper-evident audit & operator containment):** every audit record is
**signed (Ed25519)** over a pinned canonical body, a CI-runnable chain verifier
(`python -m agentos_controlplane.audit_verify`) recomputes hashes/links/signatures and detects
truncation, chain heads anchor externally via **RFC-3161 timestamps**, a fail-closed
**secret-scan last gate** keeps leaked credentials out of audit bodies, and operators get **agent
+ fleet kill switches** that halt a rogue agent at stage 0 of the pipeline.

**✅ Shipped (Phase 5 — control plane, SDK & minimal dashboard):** a shared-token **control-plane
API** (TrustProfile/ABOM resources with optimistic versioning, constitution **compile-on-write**,
agent inventory & discovery), gated agent **self-registration**, a Python
**`ControlPlaneClient`** SDK, a **zero-infra quickstart** (`agentos-quickstart` — SQLite +
in-process opa-wasm, no Docker), and a cookie-gated **operator dashboard** (inventory · approvals
· kill switch).

**🛠️ Status:** Phases 1–13 are complete and Phase 14 delivered 6 of its 9 requirements.
Three remain open and are marked as such — zero-knowledge compliance proofs (AUD-07),
SPIFFE/mTLS workload identity (IDN-04), and the Kubernetes operator (INT-09); each carries its
reason in [REQUIREMENTS.md](.planning/REQUIREMENTS.md). See the 14-phase
[roadmap](.planning/ROADMAP.md).

## 📦 Install

```bash
pip install agentos-guard      # the umbrella: SDK, pipeline, control plane, gateway
```

The six packages also publish separately, so an integrator can depend on just the stable
seam instead of the whole control plane:

| Distribution | What it gives you |
|---|---|
| **`agentos-guard`** | Umbrella — depends on all six below. Start here. |
| `agentos-guard-sdk` | The data-plane PEP: LangChain middleware, `governed_call`, the quickstart. |
| `agentos-guard-contract` | `AgentAction` / `Decision` / `RiskFinding` — the integration seam, **zero internal dependencies**. Pin this if you are only speaking the protocol. |
| `agentos-guard-pipeline` | The decision pipeline: risk scoring + the WASM policy floor. |
| `agentos-guard-constitution` | Constitution schema and the deterministic Constitution → Rego compiler. |
| `agentos-guard-controlplane` | Registry, identity, hash-chained audit, API and dashboard. |
| `agentos-guard-gateway` | The framework-agnostic network PEP (reverse proxy). |

> **Distribution names are prefixed; import names are not.** You install
> `agentos-guard-sdk` but you still write `import agentos_sdk`. The `agentos-sdk` name on
> PyPI belongs to an unrelated project, so the published family is namespaced under
> `agentos-guard-*` while the modules keep their original names.

All seven share one version and are released from a single tag, so internal dependencies are
pinned exactly (`agentos-guard-contract==0.1.0`) — combinations that were never built together
are never advertised as supported.

## ⚡ Explore from source

Real code lives under [`packages/`](packages/) as a [uv](https://docs.astral.sh/uv/) workspace.

```bash
git clone https://github.com/JitendraJha98/agentos-guard.git
cd agentos-guard

uv sync            # install the workspace + dev tooling from the lockfile
uv run pytest      # run the suite, including the red-team CI gate

uv run agentos-quickstart   # zero-infra governed loop: allow + deny + signed audit, on SQLite
uv run python examples/wedge_demo.py   # the rename_then_drop sequence-intent wedge (SEC-13)
```

> The policy layer compiles Rego to WASM, so a recent [`opa`](https://www.openpolicyagent.org/docs/cli)
> binary on your `PATH` is needed for the policy tests (CI does this automatically).

## 🗂️ Repository layout

Two layers, deliberately separate — **`docs/` defines, `.planning/` executes and references it**:

| Path | What it is |
|------|------------|
| [`docs/`](docs/) | **Design** (authoritative — *what & why*). Start at the [manifesto](docs/architecture/00-manifesto.md). |
| [`.planning/`](.planning/) | **Execution** (GSD — *how & when*): requirements, roadmap, phase history, research. |
| [`packages/`](packages/) | The code: `contract` (stable boundary) · `pipeline` (the PDP) · `controlplane` · `constitution` · `sdk` (in-process PEP) · `gateway` (network PEP — governs agents with no SDK in their process). |
| [`CLAUDE.md`](CLAUDE.md) | Contributor & agent working guidance. |

Each of `docs/` and `.planning/` has its own README explaining the split, so the two never blur.

## 🧰 Built with

Python 3.12+ · LangChain / LangGraph (interception) · Open Policy Agent / Rego (policy) ·
Pydantic v2 · SQLAlchemy 2.0 + asyncpg + Alembic on PostgreSQL · stdlib hash-chain audit ·
OpenTelemetry · garak / PyRIT under pytest (red-team). Rust is reserved for hot-path enforcement
later, where profiling justifies it. Decisions are recorded as [ADRs](docs/architecture/adr/).

## 🤝 Contributing

Early-stage and contributor-friendly. Good first steps: read the
[manifesto](docs/architecture/00-manifesto.md), skim the [roadmap](.planning/ROADMAP.md), and open an
issue to discuss before a PR. Feature work happens on the `development` branch (see
[`CLAUDE.md`](CLAUDE.md)).

## 📄 License

[MIT](LICENSE) © 2026 Jitendra Jha, Siddhant Nikumbh — open-source, self-hosted first.

<div align="center">
<sub>Governance as a collaborative, evolving system — not a static firewall.</sub>
</div>
