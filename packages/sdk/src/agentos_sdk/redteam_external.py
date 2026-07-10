"""TEST-02/06 — bind the garak + PyRIT attack corpora to the GOVERNED agent.

Slice 6d shipped a curated, deterministic corpus (`agentos_sdk.redteam`). Slice 6e wires
the real libraries: `GovernedTarget` routes an attack *prompt* through the governed
pipeline (a scripted fake model -> the real 5-stage PDP over the test constitution) and
reports whether governance BLOCKED it. A garak custom **generator** + **detector** and a
PyRIT single-turn **target** + **scorer** bind that `GovernedTarget` to each library's
extension point; their probes/prompts drive the attacks, and a block-rate score computes
ASR = fraction NOT blocked. No live LLM / no network -> reproducible.

External-API discipline — verified against the INSTALLED packages (pinned in the `redteam`
extra), NOT guessed. Bound signatures:

garak 0.15.1
  * ``garak.generators.base.Generator`` — subclass; override
    ``_call_model(self, prompt: garak.attempt.Conversation, generations_this_call: int = 1)
    -> list[garak.attempt.Message | None]`` (must return a 1-item list when called with
    ``generations_this_call == 1``). ``__init__(self, name="", config_root=garak._config)``.
    Read the attack text from ``prompt.last_message().text``.
  * ``garak.detectors.base.Detector`` — subclass; override
    ``detect(self, attempt: garak.attempt.Attempt) -> Iterable[float | None]`` returning a
    score per output in [0.0, 1.0] where **1.0 == hit (vulnerability found / attack
    succeeded)** and 0.0 == no hit (blocked). ``__init__(self, config_root=garak._config)``
    (a class docstring is required). Read outputs via ``attempt.outputs_for(self.lang_spec)``.
  * ``garak.attempt`` — ``Message(text=...)``, ``Turn(role, content)``,
    ``Conversation(turns=[...])``, ``Attempt(prompt=Message|Conversation)`` then
    ``attempt.outputs = [Message(...)]`` (the prompt must be set before outputs).

PyRIT 0.13.0
  * Memory: ``pyrit.memory.CentralMemory.set_memory_instance(SQLiteMemory(db_path=":memory:"))``
    — in-process SQLite, no network/Docker (mirrors the repo's D-14 no-Docker posture). The
    target and scorer base classes both resolve ``CentralMemory.get_memory_instance()``.
  * ``pyrit.prompt_target.PromptTarget`` — subclass; implement
    ``async send_prompt_async(self, *, message: pyrit.models.Message) -> list[Message]``.
    Read the prompt via ``message.get_value()``; build the reply with
    ``pyrit.models.construct_response_from_request(request=message.get_piece(),
    response_text_pieces=[text])``.
  * ``pyrit.score.TrueFalseScorer`` (a ``pyrit.score.Scorer``) — subclass; implement
    ``async _score_piece_async(self, message_piece, *, objective=None) -> list[Score]`` and
    ``_build_identifier()``; construct with ``validator=ScorerPromptValidator(...)``. Read the
    response text via ``message_piece.converted_value``; ``Score`` needs
    ``score_value("true"/"false"), score_type="true_false", score_value_description,
    score_rationale, message_piece_id, scorer_class_identifier``.
  * ``pyrit.models.SeedPrompt.from_yaml_file(path).render_template_value(prompt=...)`` loads
    the bundled jailbreak templates offline (the real PyRIT single-turn corpus).

IMPORT DISCIPLINE: garak / pyrit are the OPTIONAL `redteam` extra. This module keeps them
OUT of import time — every garak/pyrit symbol is imported lazily inside the builder
functions — so ``import agentos_sdk.redteam_external`` (and hence the whole SDK) works with
the extra ABSENT. Only ``GovernedTarget`` is available then; the wrappers raise on build.
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

from agentos_contract import ActionType, AgentAction, Outcome
from agentos_sdk.redteam import BLOCKING_OUTCOMES

# Unambiguous sentinels the generator/target emit so the detector/scorer can classify the
# governed outcome without re-running the pipeline. Neither string trips the SEC-01 detector.
BLOCK_SENTINEL = "<GOVERNANCE_BLOCKED>"
ALLOWED_RESPONSE = "<GOVERNANCE_ALLOWED>"


class GovernedTarget:
    """Route an attack prompt through the governed pipeline; report whether it was BLOCKED.

    ``evaluate`` is the caller-supplied ``async evaluate(action) -> Decision`` seam (e.g.
    ``Pipeline.evaluate``). Each prompt is submitted as a ``model_invocation`` — the egress
    policy floor does NOT apply to it, so the SEC-01 prompt-injection detector is the only
    thing that can block, which isolates the detector's contribution (the same detector-path
    isolation the 6d jailbreak suite uses). Blocked == outcome in ``BLOCKING_OUTCOMES``.
    """

    def __init__(
        self,
        evaluate: Callable[[AgentAction], Awaitable[object]],
        *,
        agent_id: str,
        token: str,
    ) -> None:
        self._evaluate = evaluate
        self._agent_id = agent_id
        self._token = token

    async def probe_async(self, prompt: str) -> bool:
        """Await the governed decision for `prompt`; return True if BLOCKED."""
        action = AgentAction(
            agent_id=self._agent_id,
            type=ActionType.model_invocation,
            target="chat",
            payload={"messages": [prompt]},
            identity_token=self._token,
        )
        decision = await self._evaluate(action)
        return decision.outcome in BLOCKING_OUTCOMES

    def probe(self, prompt: str) -> bool:
        """Synchronous wrapper for callers outside an event loop (e.g. garak's sync
        ``_call_model``). Must NOT be called from within a running loop — the PyRIT path,
        which runs inside ``asyncio.run``, uses ``probe_async`` instead."""
        return asyncio.run(self.probe_async(prompt))
