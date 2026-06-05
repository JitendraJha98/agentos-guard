# Architecture Decision Records

Each ADR captures one significant decision: its context, the decision, and consequences.

| ADR | Decision |
|-----|----------|
| [0001](0001-python-first.md) | Python-first stack; Rust reserved for later hot paths |
| [0002](0002-sdk-interception-first.md) | SDK interception as the v1 enforcement point |
| [0003](0003-opa-rego-policy-substrate.md) | Layered Constitution → YAML → OPA/Rego policy substrate |
| [0004](0004-tamper-evident-audit-hash-chain.md) | Hash-chained tamper-evident audit log |
| [0005](0005-graduated-response-model.md) | Graduated response instead of binary allow/deny |
| [0006](0006-naming-agentos-guard.md) | Product name: agentos-guard |
| [0007](0007-no-crypto-economics-in-core.md) | No crypto-economics in core; keep only token-free cryptography (Merkle/ZK) |
