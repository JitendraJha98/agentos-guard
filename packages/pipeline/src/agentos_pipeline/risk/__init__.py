"""Risk stage (SEC-01) — deterministic, inline scorers.

Exports the Phase-1 detector surface: the de-obfuscation pass, the
PromptInjectionScorer, and the assess_risk aggregator. Nothing here imports a
model, network, or LLM — that is a tested invariant (the import-guard test).
"""

from agentos_pipeline.risk.aggregator import assess_risk
from agentos_pipeline.risk.intent_scorer import IntentScorer
from agentos_pipeline.risk.normalize import normalize
from agentos_pipeline.risk.pii import PiiScorer
from agentos_pipeline.risk.prompt_injection import PromptInjectionScorer

__all__ = ["assess_risk", "IntentScorer", "normalize", "PiiScorer", "PromptInjectionScorer"]
