# Phase 4 — Tamper-Evident Audit, Operator Containment & NVIDIA Interpreter — Decomposition & Design

> **Overview doc.** Locks the slice breakdown, the cross-cutting design decisions, and the
> requirement-coverage matrix. Each slice gets its own detailed TDD plan written just-in-time and
> executed with `superpowers:subagent-driven-development` + adversarial review (the Phase-3 loop).
> **Branch:** `phase-4-audit-containment`, stacked on the Phase-3 HEAD (Phase 4 extends Phase-3's
> `audit.py` + interpreter seam; Phase 3 is pending PR). Rebase onto `development` once Phase 3 merges.
>
> The NVIDIA facts below are from an adversarial research workflow (2026-06-12, primary-source +
> skeptic re-check, `confidence: high`). Uncertainties are stated honestly; re-verify model-id
> strings + structured-output behavior against the live catalog before shipping the adapter.

**Goal:** Make audit evidence genuinely tamper-*proof* and independently verifiable, give operators
an immediate kill switch for one agent or the whole fleet, and add a **free** NVIDIA-hosted LLM
provider for the semantic interpreter (mirroring the Anthropic adapter).

**Requirements:** AUD-02, AUD-03, AUD-04, AUD-05, AUD-08, RUN-01, RUN-02 (roadmap) **+** an
NVIDIA interpreter adapter (user-requested addition; extends Phase-3 POL-04 seam).

> **Already satisfied by Phase 3 (verify, don't rebuild):** AUD-02 (audit body links
> action→decision→fired-principles→outcome via `reasons[].principle_ref`) and AUD-03
> (`constitution_version`/`policy_version` in every body) landed in Slice 3/hardening; fail-closed
> field redaction (AUD-04 layer 1) exists. Phase 4 adds the per-record signatures, the verifier,
> external anchoring, the AUD-04 *last-gate*, and the kill switches.

---

## Cross-cutting design (verified)

### A — NVIDIA interpreter adapter (`NvidiaInterpreter`)
Mirrors `AnthropicInterpreter` behind the existing `SemanticInterpreter` Protocol; the deterministic
stub stays the default. Differences (all verified):
- **Transport:** the **`openai` SDK** (`AsyncOpenAI`, lazy-imported, root dep) pointed at
  `base_url="https://integrate.api.nvidia.com/v1"`, `api_key=os.environ["NVIDIA_API_KEY"]` (the
  `nvapi-` key; env-var name is *our* convention — the wire only sees `Authorization: Bearer`).
  Client injectable for offline CI. **Not** the anthropic SDK.
- **Default model:** `meta/llama-3.1-8b-instruct` — the skeptic flagged `meta/llama-3.3-70b-instruct`
  has a documented "guided decoding might not work with the TensorRT-LLM backend" caveat and the
  hosted backend isn't user-selectable. Model is configurable; tool-calling + structured output
  confirmed on 3.1-8b.
- **Structured output:** `structured_mode` config, default **`nvext_guided_json`**
  (`extra_body={"nvext":{"guided_json": SCHEMA}}` — NVIDIA's documented LLM path), with
  `json_schema` (`response_format`) and `json_object` alternatives. Schema is **FLAT**: `outcome`
  string-enum (7 AUTHORABLE_EFFECTS), `rationale` string, **`principle_ref` string with a `"none"`
  sentinel** (NOT a nullable union — weak under hosted constrained decoding), `required=[all]`,
  `additionalProperties=false`.
- **Mandatory robustness wrapper (the research's hard requirement):** extract content →
  `json.loads` → validate against a Pydantic `_VerdictModel` → **bounded retry** (default 2) with a
  corrective nudge → on exhaustion raise. Adherence on free open-weight models is best-effort, not a
  contract. The runner already degrades an interpreter exception to an `interpreter_error` reason
  with the floor intact (Slice 5), so a parse failure is fail-safe; and the **restrict-only clamp
  (POL-05) backstops any verdict** the model returns. 1–2 few-shot examples in the system prompt.
- **Live + injection tests** (key-gated on `NVIDIA_API_KEY`, mirroring the Anthropic ones) →
  becomes the **free** provider for the D2 human-verify checkpoint.
- **Honest free-tier note:** ~40 RPM (community-reported, no primary doc); bound retries against it.

### B — AUD-08 per-record EdDSA signatures
- **Sign the canonical BODY bytes, NOT the record_hash digest.** Ed25519 is PureEdDSA (RFC 8032):
  signing a SHA-256 prehash forfeits its collision resistance (a hash collision would forge a
  record whose signature still verifies) and RFC 8032 §8.7 says prehash "SHOULD NOT be used." The
  body already contains `seq`+`prev_hash`, so signing it binds authorship to the full chain-linked
  content. Cost is identical (Ed25519 hashes internally).
- **Domain separation:** sign `b"agentos-guard/audit-record/v1\x00" + canonical_json(body)`. The
  same control-plane Ed25519 key signs agent JWTs — a fixed context prefix makes an audit signature
  unusable as a JWT and vice-versa (RFC 8032 §8.4; CT/Rekor leaf/node prefix practice).
- **Key custody:** add `IdentityEngine.sign_record(body_bytes)->bytes` + `public_key_id` (a short
  SHA-256 fingerprint of the pub PEM) — never leak the private key out of the engine. New nullable
  `AuditRecord.signature` + `signing_key_id` columns (OUT of `body` so the sig doesn't cover itself),
  written inside `_insert` under the writer lock.
- **Canonicalization pin (must fix — flagged by research):** `canonical_json` is labelled
  "RFC-8785-ish" but diverges (float repr, non-ASCII key sort, lone surrogates). For a signed
  artifact an external verifier recomputes, pin it explicitly as **"agentos-guard canonical JSON v1
  = `json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=False)` over ASCII-key,
  JSON-native-scalar bodies"**, drop the RFC-8785 claim, and have the verifier import the *exact*
  function. Invariant: the SAME `canonical_json` output is both hashed and signed.

### C — AUD-05 verifier + external anchoring
- **CI verifier (the offline centerpiece):** a standalone `python -m agentos_controlplane.audit_verify
  --db … --pubkey …` (+ a pytest) that re-derives every property from rows + pubkey ONLY (never
  trusting a stored derived field), streaming `ORDER BY seq ASC`, exit-non-zero-at-first-violation:
  (1) genesis seq==0/prev NULL; (2) strict seq continuity (gap=delete, dup/reorder caught); (3)
  prev_hash == prior row's *recomputed* hash; (4) `record_hash` recompute + `body.seq`/`body.prev_hash`
  agree with columns; (5) per-record Ed25519 verify over the domain-prefixed body; (6) checkpoint
  anchors; (7) tail head == persisted head (truncation). Tamper-class test matrix proves each step
  fails at the right seq. Dependency-light (sqlite3 + cryptography) → runs in CI, no Docker.
- **External anchoring = RFC-3161 trusted timestamping of periodic chain-head checkpoints.** The
  minimal *honest* option for a single-process/SQLite/no-Docker MVP: one outbound HTTPS POST to a
  free/public TSA, no new service, no Merkle tree, **token-free / no blockchain (ADR-0007-clean — a
  TSA is a notary, not a chain).** New `chain_checkpoint(seq, record_hash, tsa_token, tsa_url,
  created_at)` table + a `CheckpointAnchor` Protocol (RFC-3161 anchor for real use, deterministic
  stub for unit tests; the real TSA round-trip is a network-gated integration test like the live
  interpreter). **Threat model, stated plainly in the docs:** defends against an insider with DB
  write access rewriting *already-checkpointed* history (the rewritten head won't match the
  TSA-signed token, which they can't forge); does NOT prove completeness/forward-forgery (→ Phase-11
  Merkle/witness, AUD-06), split-view (→ witness quorum), or survive live key compromise.
  *Dependency to pin at plan time:* a Python RFC-3161 client (e.g. `rfc3161-client`); evaluate vs.
  effort in the fork below.

### D — AUD-04 secret-detector last gate
A fail-closed, content-based, name-agnostic detector run as the **last gate** over the fully-assembled
canonical body bytes (sees `redacted_payload` AND `reasons`/`inferred_intent`/`remediation`), AFTER
canonicalization and BEFORE hash/sign/INSERT, in both `append` and `append_event`. Deterministic
(stdlib `re` compiled once + Shannon-entropy on long token-like substrings; no LLM/network;
ReDoS-safe) — the gitleaks/detect-secrets rule family (AWS `AKIA`, GitHub `ghp_`, Slack `xox`, PEM
private-key headers, JWT `eyJ…`, bearer tokens) + an entropy gate. **Must allowlist the redactor's
own `{len, sha256:64-hex}` digest shape** so the backstop doesn't false-positive on the digest layer
1 emits. Fires → `SecretLeakError`, write NOTHING (same contract as `RedactionError`). Honest scope:
best-effort recall, a backstop beneath the fail-closed allowlist classifier — not a guarantee
(Presidio-grade ML is the later upgrade already noted in `audit.py`).

### E — RUN-01/02 operator kill switch
A `KillSwitch` store (per-`agent_id` flags + a fleet flag), consulted on **every** action as a
pre-policy short-circuit (stage 0, before policy/risk) → terminal **deny** with an audited reason
(`agent_killed` / `fleet_killed`), no operation run. Operator sets/clears via the resolve API
(API surface alongside Phase-3's approvals router) and every toggle is an `AuditRecord`
(new event kinds). **Honest scope (state in docs):** in the SDK-interception model "halt
immediately" = every *subsequent* action denied the instant the switch flips (checked per action,
cheaply cached, invalidated on toggle); a request already mid-flight in the agent isn't force-killed
— true in-flight termination is the gateway/sandbox layer (Phase 9/10). Fleet kill = one flag the
per-agent check also honors.

---

## Slice decomposition

| Slice | Scope | Requirements | Depends on | Verification gate |
|-------|-------|--------------|------------|-------------------|
| **4a** | Per-record EdDSA signatures + canonicalization pin | AUD-08 | — | sign/verify; domain-sep (audit-sig ≠ JWT); tamper→bad sig; canonical_json byte-pin test |
| **4b** | CI chain verifier | AUD-05 (verify) | 4a | tamper-class matrix (7 steps fail at right seq); runs offline in CI |
| **4c** | External anchoring (RFC-3161) | AUD-05 (anchor) | 4a, 4b | checkpoint table; stub-anchor unit tests; network-gated real-TSA test; verifier validates tokens |
| **4d** | Secret-detector last gate | AUD-04 | 4a | secret in any field → SecretLeakError, no row; digest-shape allowlisted; append_event gated |
| **4e** | Operator kill switch (agent + fleet) | RUN-01, RUN-02 | — | killed agent denied immediately; fleet halts all; clear restores; toggles audited |
| **4f** | NVIDIA interpreter adapter | (NVIDIA add) | — (Phase-3 seam) | offline contract tests (injected client); flat-schema + sentinel + revalidate-retry; key-gated live + injection-of-the-judge proof |
| **4g** | AUD-02/03 confirmation + verifier coverage | AUD-02, AUD-03 | 4b | a test asserts every body carries the linkage + versions and the verifier checks them (closes the roadmap criteria explicitly) |

Dependency spine: 4a → 4b → 4c (and 4b → 4g); 4d depends on 4a; **4e and 4f are independent** and
can slot anywhere.

---

## Forks for your call (recommendations in **bold**)

1. **AUD-05 anchoring depth (4c).** **Implement RFC-3161 TSA anchoring now** (it's what makes
   "externally anchored" *meaningful* — self-signing by the same process adds little against an
   insider). Cost: one new dep (`rfc3161-client` or similar) + a network-gated test. *Alternative:*
   ship 4b (verifier) + the checkpoint table + the `CheckpointAnchor` seam now and defer the real
   TSA wiring to a follow-up — the verifier is the high-value, fully-offline piece either way.
2. **NVIDIA default model (4f).** **`meta/llama-3.1-8b-instruct`** (caveat-free, robust for a
   constrained judge), configurable; not 3.3-70b (documented guided-decoding caveat on the hosted
   backend).
3. **Slice ordering.** **Recommend: 4f (NVIDIA) first** — it's self-contained, high-interest, and
   unblocks the *free* live-interpreter checkpoint; then the audit spine 4a→4b→4c→4g, then 4d, then
   4e. Say if you'd rather lead with the audit work.
4. **Kill-switch honesty.** Confirm the Phase-4 scope = deny-all-subsequent-actions-instantly (not
   force-killing in-flight external calls, which is Phase 9/10). **Recommend yes** — it's the honest
   capability at the SDK-interception layer.

## Phase-close acceptance (maps to roadmap criteria 1–4)
1. Every `AuditRecord` links action→decision→principles→outcome + exact versions — confirmed + verifier-checked (4g, 4b).
2. Fail-closed redaction + last-gate secret detector — no record on failure (4d).
3. CI verifier detects any retroactive edit; checkpoints externally anchored; per-record EdDSA so a single record verifies alone (4a, 4b, 4c).
4. Operator kill-switches a single agent or the fleet; targeted actions halt immediately (4e).
