"""agentos-pipeline — the 4-stage decision pipeline.

Phase 1 ships the risk stage (SEC-01): the deterministic, inline
PromptInjectionScorer + normalize() + assess_risk aggregator. stdlib-only on the
hot path (re/unicodedata/base64) + Pydantic; NO LLM/model/network (P0-killer).
"""
