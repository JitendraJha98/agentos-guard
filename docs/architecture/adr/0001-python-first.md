# ADR 0001 — Python-first stack, Rust later

- **Status:** Accepted
- **Date:** 2026-06-01

## Context

The raw spec proposed a Rust core runtime with Python/TypeScript/Go SDKs, but also a
*pytest-native* safety layer. Rust-from-day-one maximizes performance but slows shipping and
raises the contributor barrier for an open-source project; the AI-agent ecosystem (LangChain,
LangGraph, MCP, pytest) is overwhelmingly Python.

## Decision

Build Python-first: the control plane, Decision Pipeline, engines, SDK, and red-team layer are
Python. Reserve Rust for **specific hot enforcement paths** in Phase 2, introduced only where
profiling justifies it.

## Consequences

- (+) Fastest path to a working MVP; lowest OSS contribution barrier; native fit with the
  agent + pytest ecosystem.
- (+) The Phase 0 pipeline targets low single-digit-ms overhead with caching; sufficient for
  early adopters.
- (−) Pure-Python interception may bottleneck at very high throughput — accepted until Phase 2.
- The pipeline contract ([`../03-interception-and-pipeline.md`](../03-interception-and-pipeline.md))
  is language-agnostic, so a Rust hot-path swap won't change interfaces.
