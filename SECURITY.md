# Security Policy

`agentos-guard` is a security control plane for AI agents. A vulnerability here can
weaken the governance of every agent that depends on it, so we treat security reports
as our highest-priority work.

## Supported versions

The project is pre-1.0 and ships from the `main` branch. Until a `1.0.0` release, only
the latest tagged release and `main` receive security fixes.

| Version | Supported |
|---------|-----------|
| latest release / `main` | ✅ |
| older pre-1.0 tags | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through GitHub's coordinated-disclosure channel:

1. Go to the repository's **Security** tab → **Report a vulnerability** (GitHub Private
   Vulnerability Reporting), or
2. Email the maintainers at **security@agentos-guard.dev** with the details below.

Please include:

- the affected package(s) (`agentos-contract`, `agentos-pipeline`,
  `agentos-constitution`, `agentos-controlplane`, `agentos-sdk`) and version/commit,
- a description of the issue and its security impact (e.g. governance bypass, audit
  tampering, redaction failure, identity forgery, cardinality/DoS),
- a minimal reproduction (a failing test against the `evaluate()` seam is ideal), and
- any known mitigations.

## What to expect

| Stage | Target |
|-------|--------|
| Acknowledgement of your report | within **3 business days** |
| Initial assessment + severity | within **7 business days** |
| Fix or mitigation plan | within **30 days** for high/critical |
| Public disclosure | coordinated with you, after a fix ships |

We will keep you updated, credit you in the release notes and advisory (unless you
prefer to remain anonymous), and publish a GitHub Security Advisory when the fix is
released.

## Scope

In scope — anything that undermines a core governance guarantee:

- **Governance bypass** — an action that should be denied/restricted is allowed
  (policy floor, detector, or interception-coverage evasion; a silent un-instrumented
  path).
- **Identity** — forging or replaying an identity token, or bypassing the fail-closed
  verify gate.
- **Audit integrity** — tampering that is not detected by the hash chain / per-record
  signature / checkpoint verifier, or a redaction failure that writes sensitive data.
- **Fail-open regressions** — a control-plane error that silently allows instead of
  failing closed.
- **Telemetry/DoS** — unbounded metric cardinality or resource exhaustion via
  attacker-controlled input.

Out of scope — the deliberate, documented limitations of a pre-1.0 P0 build (e.g. the
regex prompt-injection detector missing subtler indirect injections; see the red-team
gate's honest ASR calibration). Report these as normal issues, not vulnerabilities.

## Our commitment

We follow coordinated disclosure, will not pursue legal action against good-faith
security research that respects this policy, and treat a failing safety test as a
release blocker — consistent with the project's "safety as a failing test" posture.
