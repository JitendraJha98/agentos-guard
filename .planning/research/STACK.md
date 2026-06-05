# Stack Research

> 📸 **Research snapshot — 2026-06-01. Not authoritative.** Point-in-time stack analysis that fed
> the design and plan. Authoritative design is [`docs/architecture/`](../../docs/architecture/)
> (esp. the ADRs); live execution state is [`.planning/`](../). Read this for *why* these libraries
> were chosen, not for current truth.

**Domain:** AI-agent runtime governance & security control plane (Python-first)
**Researched:** 2026-06-01
**Confidence:** HIGH for Phase 0 core (LangChain/LangGraph interception, OPA/Rego, FastAPI/Pydantic/SQLAlchemy/Alembic, OTel, anthropic SDK, pytest red-team). MEDIUM for the in-process Rego path and OTel GenAI conventions (experimental). LOW / speculative for Phase 2 (ZK, SPIFFE, BFT, Rust interop).

All recommendations are tagged **[P0] / [P1] / [P2]** for the documented build phases, and chosen to respect the locked ADRs (Python-first, SDK-interception-first, OPA/Rego substrate, hash-chain audit, graduated response). Nothing here proposes replacing those decisions.

---

## TL;DR — the prescriptive stack

| Layer | Pick (Phase 0) | Why in one line |
|-------|----------------|-----------------|
| Interception PEP | **LangChain v1 `AgentMiddleware`** (`wrap_tool_call` / `wrap_model_call` / `before_model` / `after_model`) | First-class, short-circuitable hooks that map 1:1 onto `enforce()`; no monkey-patching. |
| Policy hot path | **OPA server** (sidecar) via HTTP, behind a thin `PolicyEngine` interface | CNCF-graduated, full Rego, zero in-process build pain; swap to in-process later. |
| In-process Rego (option) | **opa-wasm 0.3.2** (compile → WASM) | When you want to kill the sidecar; pip-installable, no Go runtime. |
| Semantic interpreter | **anthropic 0.105.x** + **structured outputs (JSON-schema beta)**, schemas via **Pydantic v2** | Guaranteed schema-valid `{outcome, cited_principle, rationale}`; no parse failures on the hot path's slow lane. |
| Control-plane API | **FastAPI 0.136.x** + **Pydantic v2.13.x** | De-facto standard for declarative, validated, async Python APIs. |
| Persistence | **SQLAlchemy 2.0.x** (async) + **asyncpg 0.31.x** + **Alembic 1.18.x** | Async ORM/Core + migrations; the boring, correct choice for Postgres. |
| Audit hash chain | **hashlib (stdlib SHA-256)** + canonical JSON + Postgres append-only table | ADR-0004 is a hash chain, not a dependency — keep it stdlib. |
| Prompt-injection / guardrails | **LlamaFirewall 1.0.x** (orchestrator) wrapping **Prompt Guard 2** + **LLM Guard 0.3.x** scanners | Detector-as-pluggable-scorer fits the security engine's design exactly. |
| PII | **Presidio (analyzer/anonymizer) 2.2.x** | Standard OSS PII detection + redaction (redaction is required at audit write time). |
| Telemetry | **opentelemetry-sdk 1.42.x** + **GenAI semantic conventions** (opt-in) | Emit, don't replace; conventions exist but are experimental — pin and gate. |
| Red-team in CI | **pytest** + **garak 0.15.x** + **PyRIT 0.13.x** as attack libraries behind a `pytest` fixture | "Safety as a failing test" with statistical thresholds. |
| Dashboard | **FastAPI + HTMX + server-rendered Jinja2** (or a thin Next.js read-only app) | P0 dashboard is read-only + approvals + kill switch — do not build an SPA. |

---

## Recommended Stack

### Core Technologies

| Technology | Version | Phase | Purpose | Why Recommended |
|------------|---------|-------|---------|-----------------|
| **Python** | 3.12 / 3.13 | P0 | Implementation language | Locked by ADR-0001; ecosystem fit (LangChain, OPA SDKs, ML detectors, pytest). Target 3.12 as the floor (broadest wheel support); 3.13 is fine. |
| **LangChain** | 1.3.x | P0 | Framework being governed; provides the `AgentMiddleware` interception surface | LangChain v1 (1.0+) ships a stable middleware system. `wrap_tool_call(request, handler)` and `wrap_model_call(...)` let you call `handler` **zero times to short-circuit** — exactly the `allow/deny/sandbox` `enforce()` contract from doc 03. No fork/monkey-patch needed. |
| **LangGraph** | 1.2.x | P0 | Runtime LangChain agents execute on; node/graph boundary | LangChain v1 agents run on the LangGraph runtime; middleware composes over graph nodes. `HumanInTheLoopMiddleware` + a `checkpointer` is the native primitive for `require_approval` (park → resume). |
| **OPA (Open Policy Agent)** | 1.x server (CNCF-graduated) | P0 | Deterministic Rego policy evaluation on the hot path | ADR-0003. Run OPA as a co-located server; the Decision Pipeline POSTs `{input}` to `/v1/data/...` and gets a decision document. Full Rego support, no in-process build pain, easy to cache. The "Kubernetes-for-agents" positioning wants the canonical CNCF engine. |
| **opa-wasm** | 0.3.2 | P0/P1 | In-process Rego (policy compiled to WASM) | The escape hatch when a network hop to OPA is unacceptable. `opa build -t wasm` produces a bundle; `opa-wasm` (wasmer-backed) evaluates it in-process. Keep behind the same `PolicyEngine` interface so it's a deployment toggle, not a rewrite. |
| **anthropic** (Claude SDK) | 0.105.x | P0 | LLM semantic interpreter for ambiguous / rule-absent policy cases | ADR-0003's reasoning layer. Use **structured outputs** (JSON-schema, currently public beta on Sonnet 4.5 / Opus 4.x) so the interpreter *always* returns a schema-valid `{outcome, cited_principle_id, rationale, confidence}` — no JSON-parse failures in the pipeline. Runs only on the ambiguous minority (latency/cost bounded by design). |
| **FastAPI** | 0.136.x | P0 | Declarative Control-Plane API server | Async-native, OpenAPI out of the box, Pydantic-validated request/response — the standard for a Kubernetes-style declarative resource API (`Agent`, `Constitution`, `Policy`, `TrustProfile`, `ApprovalRequest`, `ABOM`). |
| **Pydantic** | 2.13.x | P0 | Resource modeling, `AgentAction` schema, validation, settings | v2's Rust core makes per-action (de)serialization cheap — relevant on the hot path. Doubles as the JSON-schema source for both the API and the Claude structured-output interpreter. |
| **SQLAlchemy** | 2.0.x | P0 | Postgres ORM + Core (async) | The 2.0 async API + Core gives you both declarative resources and the hand-tuned append-only audit insert. Battle-tested; the default. |
| **asyncpg** | 0.31.x | P0 | Async Postgres driver | Fastest async driver; pairs with SQLAlchemy async engine. (Use `psycopg` 3.3.x instead if you prefer one driver for sync Alembic + async app.) |
| **Alembic** | 1.18.x | P0 | Schema migrations | Canonical SQLAlchemy migration tool; autogenerate from models. The audit table needs careful, reviewed migrations (append-only constraints, triggers). |
| **PostgreSQL** | 16 / 17 | P0 | Resource store + append-only hash-chained audit table | Locked by PROJECT constraints. 16/17 both fine; nothing here needs 17-only features. |
| **opentelemetry-sdk / -api** | 1.42.x | P0 | Spans + metrics for every `AgentAction`/`Decision` | "Emit, integrate, don't replace." Pair with GenAI semantic conventions (below). |
| **pytest** | 8.x | P0 | Red-team / safety test harness | ADR-aligned: safety regressions break CI like unit tests. Fixtures host attack libraries; assert on statistical thresholds. |

### Supporting Libraries

| Library | Version | Phase | Purpose | When to Use |
|---------|---------|-------|---------|-------------|
| **LlamaFirewall** | 1.0.x | P0 | Guardrail **orchestrator** across detectors (prompt injection, alignment, code) | Use as the security-engine front door: it scans inputs/retrieved-content/inter-agent messages and orchestrates Prompt Guard 2 + custom scanners. Each scanner = a pluggable risk scorer (doc 05). |
| **Llama Prompt Guard 2** (86M / 22M) | HF model | P0 | Prompt-injection + jailbreak classifier | Small (86M) classifier runnable CPU-only as the cheap inline detector. Returns a score → normalized `risk_score` contribution. The 22M variant for latency-sensitive paths. |
| **LLM Guard** | 0.3.16 | P0 | Library of input/output scanners (PII, secrets, toxicity, regex, format) | Offline, no vendor callback. Provides the "baseline runtime guardrails" row in doc 05 (PII/unsafe-content/format) and seeds P1 secret-leakage detection. |
| **Presidio** (`presidio-analyzer` / `presidio-anonymizer`) | 2.2.x | P0 | PII detection + **redaction-at-write-time** | Required by ADR-0004: sensitive payloads must be redacted before the audit record is hashed. Presidio's recognizer registry + anonymizer is the standard OSS path. Also a guardrail detector. |
| **hashlib** (stdlib) | — | P0 | SHA-256 for the audit hash chain | ADR-0004 is a *pattern*, not a library. `record.hash = sha256(canonical_json(prev_hash + payload))`. Keep it dependency-free and auditable. Use a **canonical JSON** serializer (e.g. `json.dumps(..., sort_keys=True, separators=(",",":"))` or RFC 8785 JCS) so hashes are reproducible. |
| **cryptography** | 48.0.x | P0 | Signing identity tokens / signed decision records | For the "signed identity token" (doc 06) and optional record signatures. Ed25519 via `cryptography` (or `PyNaCl` 1.6.x). Prefer JWT (`PyJWT`/`joserfc`) if you want standard token semantics. |
| **opentelemetry-instrumentation-langchain** *(Traceloop)* or **openinference-instrumentation-langchain** *(Arize)* | 0.61.x / 0.1.x | P0/P1 | Auto-instrument LangChain spans | Two competing community instrumentations. **You likely don't need either** in P0 because *your own middleware already sits on every action* — emit OTel spans there directly with GenAI conventions. Adopt one of these only to capture intra-chain detail you don't intercept. |
| **garak** | 0.15.x | P0 | LLM vulnerability scanner / attack probe library | Mature (NVIDIA-maintained), large probe catalog (injection, jailbreak, leakage). Wrap as a pytest fixture that runs probes against the governed agent and returns attack-success-rate. |
| **PyRIT** | 0.13.x | P0/P1 | Adversarial orchestration framework (multi-turn attacks) | Microsoft's red-team framework — better for *multi-step* campaigns (doc 08 "adversarial simulations", P1) than single-shot probes. Use alongside garak; garak for breadth, PyRIT for orchestrated depth. |
| **HTMX + Jinja2** (server-rendered) | latest | P0 | Minimal dashboard (read-only + approvals + kill switch) | Keep the P0 dashboard lean: server-rendered pages + HTMX for the approve/deny/kill-switch actions. No build pipeline, no SPA state management. Lives inside the FastAPI app. |
| **pgmq** *(or just a Postgres table)* | 1.1.x | P1 | Approval / async work queue | `ApprovalRequest` parking and reconciliation can start as a plain Postgres table + polling; `pgmq` (Postgres-native queue) is a clean upgrade before reaching for Redis/Celery. |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| **uv** | Dependency + venv management | Fastest resolver/installer; lockfile for reproducible CI. Strongly preferred over pip/poetry for a new 2026 project. |
| **Ruff** | Lint + format | Single fast tool replaces flake8/black/isort. |
| **mypy** or **pyright** | Static typing | The pipeline is contract-heavy (`AgentAction` → `Decision`); types pay off. Pydantic v2 + mypy plugin. |
| **OPA CLI** | `opa fmt`, `opa test`, `opa build -t wasm` | Test Rego policies in CI; build WASM bundles for the in-process path. The Constitution→YAML→Rego compiler's output should be `opa test`-covered. |
| **pytest-randomly / pytest-repeat** | Flakiness-aware statistical assertions | Red-team tests assert on *rates* across many runs (doc 08); repeat/seed control makes thresholds meaningful. |
| **testcontainers[postgres]** | Ephemeral Postgres in tests | Real Postgres (not SQLite) for audit-chain + migration tests; SQLite will hide append-only/trigger behavior. |

---

## Installation

```bash
# Core control plane
uv add fastapi uvicorn "pydantic>=2.13" "sqlalchemy>=2.0" asyncpg alembic

# Interception (the governed framework + middleware surface)
uv add "langchain>=1.3" "langgraph>=1.2"

# Policy substrate (hot path = OPA server; in-process option = opa-wasm)
uv add opa-wasm            # + run OPA server as a sidecar (binary/container)

# Semantic interpreter
uv add "anthropic>=0.105"

# Security engine / guardrails
uv add llamafirewall llm-guard presidio-analyzer presidio-anonymizer

# Identity / audit crypto
uv add cryptography        # or pynacl; + PyJWT/joserfc if using JWTs

# Observability
uv add opentelemetry-sdk opentelemetry-api opentelemetry-exporter-otlp \
       opentelemetry-semantic-conventions

# Red-team (dev / CI)
uv add --dev pytest garak pyrit testcontainers pytest-repeat ruff mypy
```

> **Prompt Guard 2** is a Hugging Face model, not a PyPI package — pull it via `transformers`/`huggingface_hub` (or let LlamaFirewall manage it). Plan for a model-download/cache step in CI.

---

## Alternatives Considered

| Recommended | Alternative | When to Use the Alternative |
|-------------|-------------|-----------------------------|
| **OPA server (HTTP)** for the hot path | **opa-wasm (in-process)** | When the network hop to a sidecar is unacceptable for p95 latency, or you want a single deployable unit. Keep both behind one `PolicyEngine` interface so it's a config toggle. |
| **OPA server / opa-wasm** | **regorus** (Microsoft, Rust Rego interpreter; `pyo3`/maturin bindings) | Attractive: fast, embeddable, fits the future Rust hot path (ADR-0001). **But not published to PyPI** (must build wheels with `cargo xtask build-python`) — real adoption friction. Revisit for the **Phase 2 Rust hot-path rewrite**, not Phase 0. |
| **OPA server / opa-wasm** | **regopy** (Microsoft `rego-cpp`, pip-installable as `regopy`) | A pip-installable embedded Rego runtime (C++ core). Viable if you want in-process Rego *and* `pip install` simplicity, but it is a separate Rego implementation from OPA — validate language-feature parity for your generated Rego before betting on it. |
| **OPA/Rego** (locked) | **Cedar / AWS Cedar** | Explicitly rejected in ADR-0003 (OPA chosen for CNCF maturity + K8s positioning). Do not reopen. |
| **SQLAlchemy 2.0 (async) + asyncpg** | **SQLModel** (0.0.38) | SQLModel (Pydantic + SQLAlchemy) is tempting for API+DB model unification, but it is still pre-1.0, lags SQLAlchemy releases, and its async story is thinner. Use plain SQLAlchemy 2.0 for the audit/hot path; consider SQLModel only for simple CRUD resources if the team strongly prefers it. |
| **asyncpg** | **psycopg 3.3.x** | psycopg 3 supports both sync and async with one driver — simpler if Alembic (sync) and the app (async) sharing a driver matters more than raw throughput. asyncpg is faster on the hot path. |
| **anthropic + structured outputs** | **instructor 1.15.x** | `instructor` adds retry/validation ergonomics over many providers and is provider-agnostic. With Anthropic's *native* schema-guaranteed structured outputs now available, the extra layer is largely unnecessary for P0; keep `instructor` in mind if you later want multi-provider interpreter fallback. |
| **Native OTel spans in your middleware** | **Traceloop / OpenLLMetry** or **OpenInference** auto-instrumentation | Your middleware already intercepts every action, so emit spans there. Add an auto-instrumentation library only to capture *intra-chain* detail your PEP doesn't see. Picking one couples you to that vendor's attribute conventions — prefer raw OTel GenAI semconv. |
| **garak + PyRIT** | **promptfoo**, **Giskard**, **DeepEval** | promptfoo (JS) and Giskard/DeepEval (Python) are eval-leaning; garak (breadth of attack probes) + PyRIT (multi-turn orchestration) are the closest fit to "attack library + statistical thresholds in CI." Consider DeepEval if you also want general-quality regression assertions. |
| **HTMX + Jinja2 dashboard** | **Next.js / React SPA** | Defer a full SPA to P1 when the live agent graph, SLO views, and attack visualization land. P0's read-only + approvals + kill switch does not justify an SPA toolchain. |

---

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| **Monkey-patching LangChain internals / subclassing executors** for interception | Brittle across LangChain releases; LangChain v1 ships a *supported* middleware API designed for exactly this. | LangChain `AgentMiddleware` (`wrap_tool_call` / `wrap_model_call` / `before_model` / `after_model`). |
| **LangChain 0.x callbacks as the *enforcement* mechanism** | Legacy callbacks are observe-only and can't reliably *block* or rewrite a tool call; they're for tracing. | v1 `wrap_*` hooks (can short-circuit by not calling `handler`); use callbacks only for extra telemetry. |
| **regorus from PyPI** (in Phase 0) | Not published to PyPI yet — requires building wheels with maturin; adds toolchain/CI burden before you have a product. | OPA server (P0); revisit regorus for the P2 Rust hot path. |
| **Pydantic v1** | EOL; v2's Rust core is materially faster on the per-action hot path and is the ecosystem default. | Pydantic v2.13.x. |
| **A separate message broker (Kafka/RabbitMQ/Redis) for approvals in P0** | Over-engineering; the approval queue is low-volume and you already run Postgres. | Postgres table (P0) → `pgmq` (P1) if needed. |
| **SQLite for audit-chain / migration tests** | Hides Postgres-specific append-only constraints, triggers, and concurrency the audit log depends on. | `testcontainers[postgres]` against real Postgres. |
| **Treating OTel GenAI semconv attributes as stable** | They are still **experimental** (as of early 2026); attribute names can change. | Pin `opentelemetry-semantic-conventions`, use `OTEL_SEMCONV_STABILITY_OPT_IN` for dual-emission, and centralize attribute names in one module so a rename is one edit. |
| **Calling the LLM semantic interpreter on every action** | Blows the hot-path latency/cost budget; defeats the "low single-digit-ms" target (doc 03). | OPA decides the clear majority; interpreter runs only on `ambiguous / no-rule` (design intent in doc 04). |
| **Rolling your own PII regexes for redaction** | Incomplete, hard to maintain, fails compliance scrutiny. | Presidio (analyzer + anonymizer). |

---

## Stack Patterns by Variant

**If hot-path policy latency is the binding constraint:**
- Move from OPA-server (HTTP) to **opa-wasm in-process**, behind the same `PolicyEngine` interface.
- Aggressively cache compiled policy + identity (doc 03 assumes a hot-path cache layer).
- Because: the network hop dominates a deterministic Rego eval; removing it gets you closest to single-digit-ms.

**If the team wants one DB driver everywhere (less moving parts):**
- Use **psycopg 3** for both Alembic (sync) and the async app instead of asyncpg.
- Because: simpler dependency surface; the throughput delta rarely matters before P1 scale work.

**If you need multi-provider semantic interpreter (vendor independence):**
- Keep Anthropic native structured outputs as primary, add **instructor** as the abstraction for a fallback model.
- Because: instructor normalizes structured-output + retry across providers; do this only if a procurement/availability requirement forces it.

**If reaching the P2 Rust hot path:**
- Profile first (ADR-0001). The first candidates are policy eval + audit hashing + the normalize step.
- **PyO3 + maturin** is the standard interop; **regorus** becomes a natural in-process Rego engine for the Rust side.
- Because: these are the per-action, allocation-heavy steps where Rust pays off without changing the language-agnostic pipeline contract.

---

## Phase 2 stack notes (SPECULATIVE — do not commit yet)

> Flagged LOW confidence: these move fast, Python interop is immature, and the design marks them moonshot. Listed so the roadmap can sequence *evaluation*, not adoption.

| Concern | Candidate | Maturity / Python interop reality | Confidence |
|---------|-----------|-----------------------------------|------------|
| **ZK compliance proofs** | **RISC Zero** (zkVM) / **SP1** (Succinct, RISC-V zkVM) | Both are Rust-first zkVMs. No first-class Python SDK — interop is via a Rust prover binary/service that Python calls (subprocess/gRPC), or PyO3 wrappers you build. Expect a Rust component. The *prover* is the heavy part; Python orchestrates. | LOW |
| **Workload identity** | **SPIFFE / SPIRE** (SVID, mTLS) | SPIRE is the mature CNCF reference implementation; Python integrates by consuming SVIDs from the SPIFFE Workload API (gRPC). `py-spiffe` exists but is less mature than Go/Java. Pairs with the P1 X.509 agent certs. | MEDIUM |
| **BFT consensus** | Tendermint/CometBFT, HotStuff-family libs | No strong Python-native BFT lib; the 2-of-3 *agent* consensus (P1) is application-level voting, not protocol BFT. True BFT (P2) likely means embedding/calling a Go/Rust consensus engine. Scope carefully — the P1 "consensus outcome" is much simpler than a BFT protocol. | LOW |
| **Rust hot-path interop** | **PyO3 + maturin** | The standard, mature path (this is how regorus/pydantic-core themselves ship). Introduce only where profiling justifies (ADR-0001). | HIGH (the *mechanism*; not the need) |
| **Merkle DAG audit (P1)** | stdlib `hashlib` + a Merkle tree impl (e.g. `pymerkle`) or hand-rolled | The P1 upgrade from hash chain → Merkle DAG is mostly your own data structure over the same SHA-256 primitive; few load-bearing deps. Keep it in-house and auditable, like the P0 chain. | MEDIUM |

---

## Version Compatibility

| Package A | Compatible With | Notes |
|-----------|-----------------|-------|
| langchain 1.3.x | langgraph 1.2.x, langchain-core 1.4.x | v1 line; middleware API is in `langchain.agents.middleware`. Note early-1.0 alphas had import churn (`ModelResponse` etc.) — pin to a current 1.3.x patch, not 1.0.0aN. |
| FastAPI 0.136.x | Pydantic 2.13.x | FastAPI fully on Pydantic v2; do not mix v1. |
| SQLAlchemy 2.0.x | asyncpg 0.31.x / psycopg 3.3.x | Use the async engine (`create_async_engine`). Alembic 1.18.x runs migrations sync — give it a sync driver/URL even if the app is async. |
| opa-wasm 0.3.2 | OPA CLI (for `opa build -t wasm`) | The WASM bundle must be built by a matching OPA version; pin the OPA CLI in CI. wasmer/wasmtime runtime is a transitive dep. |
| anthropic 0.105.x | structured-outputs beta | Structured outputs are a beta header/param on Sonnet 4.5 / Opus 4.x — confirm the beta flag in the SDK version you pin; gate behind a feature check. |
| opentelemetry-sdk 1.42.x | opentelemetry-semantic-conventions (GenAI) | GenAI conventions experimental; use `OTEL_SEMCONV_STABILITY_OPT_IN` for migration safety. |
| garak 0.15.x / pyrit 0.13.x | pytest 8.x | Both are heavier deps (pull ML/transformers); isolate in a `dev`/`redteam` extra so the runtime control plane stays lean. |
| Presidio 2.2.x | spaCy models | Presidio pulls spaCy + a language model — plan the model download in CI/image build. |

---

## Sources

- LangChain middleware docs — `wrap_tool_call`/`wrap_model_call`/`before_model`/`after_model`, short-circuit semantics, LangGraph runtime, HumanInTheLoopMiddleware: https://docs.langchain.com/oss/python/langchain/middleware/custom and https://reference.langchain.com/python/langchain/middleware — **HIGH** (official docs + verified hook signature)
- PyPI version checks (langchain 1.3.2, langgraph 1.2.2, langchain-core 1.4.0, fastapi 0.136.3, pydantic 2.13.4, sqlalchemy 2.0.50, alembic 1.18.4, asyncpg 0.31.0, psycopg 3.3.4, opentelemetry-sdk 1.42.1, anthropic 0.105.2, instructor 1.15.1, llm-guard 0.3.16, llamafirewall 1.0.3, presidio 2.2.362, garak 0.15.0, pyrit 0.13.0, opa-wasm 0.3.2, cryptography 48.0.0, pynacl 1.6.2, sqlmodel 0.0.38, pgmq 1.1.1) via PyPI JSON API, 2026-06-01 — **HIGH**
- OPA / Rego Python integration paths (OPA server, opa-wasm, regorus, regopy): https://github.com/open-policy-agent/awesome-opa , https://pypi.org/project/opa-wasm/ , https://github.com/microsoft/regorus (Python bindings README — *"not yet available in PyPI, can be manually built"*), https://pypi.org/project/regopy/ — **HIGH** for OPA/opa-wasm; **MEDIUM** for regorus/regopy maturity
- Anthropic structured outputs (JSON-schema guarantee, Pydantic, beta on Sonnet 4.5 / Opus 4.x): https://platform.claude.com/docs/en/build-with-claude/structured-outputs — **HIGH**
- OTel GenAI semantic conventions (agent spans, experimental status, `OTEL_SEMCONV_STABILITY_OPT_IN`): https://opentelemetry.io/docs/specs/semconv/gen-ai/ and gen-ai-agent-spans — **HIGH** (official, but conventions themselves are experimental → MEDIUM for stability)
- Prompt-injection / guardrails landscape (LlamaFirewall, Prompt Guard 2, LLM Guard, InjecGuard): https://meta-llama.github.io/PurpleLlama/LlamaFirewall/ , https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M , https://appsecsanta.com/llm-guard , https://arxiv.org/pdf/2505.03574 — **HIGH** for existence/role; **MEDIUM** for detector efficacy claims (vendor/benchmark sourced)
- Red-team frameworks (garak release 2026-05-01; PyRIT release 2026-04-17): PyPI JSON API — **HIGH** (actively maintained)
- Regorus latest release `regorus-v0.10.1` (2026-05-22), microsoft/regorus GitHub releases API — **HIGH**

---
*Stack research for: AI-agent runtime governance & security control plane (agentos-guard)*
*Researched: 2026-06-01*
