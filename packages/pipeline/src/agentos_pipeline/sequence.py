"""SequenceCorrelator — windowed sequence-intent correlation over lineage (SEC-13).

Catches multi-step evasions (e.g. ``rename_then_drop``) that no single action
reveals: each action's deterministic intent class (SEC-12 tagger) is observed
into a bounded per-conversation window, and the window is matched against the
forbidden sequences DECLARED in the Constitution (``kind: sequence`` principles,
compiled into ``bundle.sequences``). A match feeds ``input.sequence.matched_refs``
in the policy input, where the compiled membership rule fires the principle as a
REAL deterministic floor — citation and remediation flow through the ordinary
matched-principle machinery. Pure CPU, no I/O, deterministic.

Matching semantics: a declared sequence matches iff its intent classes are an
ORDERED SUBSEQUENCE of the conversation's observed classes ENDING at the current
action (the action being gated must be the sequence's final step). Untagged
actions are skipped — they neither extend nor break a sequence (a benign
``http_get`` between the rename and the drop does not launder the evasion).

State honesty (D-14): the windows live in-process with no TTL — correct for the
single-process Phase-3 deployment; distributed/persistent correlation state is
Phase-7 reconciler territory. Bounded by ``max_conversations`` (FIFO eviction)
and ``window`` (deque maxlen), so a hostile flood of conversation ids cannot
grow memory unboundedly.
"""

from __future__ import annotations

from collections import OrderedDict, deque


def _ordered_subsequence(needle: list[str], haystack: list[str]) -> bool:
    """True iff `needle` appears in `haystack` in order (not necessarily contiguous)."""
    it = iter(haystack)
    return all(cls in it for cls in needle)


class SequenceCorrelator:
    """Bounded, deterministic per-conversation intent-sequence matcher (SEC-13)."""

    def __init__(self, *, window: int = 8, max_conversations: int = 1024) -> None:
        self._window = window
        self._max_conversations = max_conversations
        self._windows: OrderedDict[str, deque[str]] = OrderedDict()

    def observe(
        self, key: str, intent_class: str | None, sequences: list[dict]
    ) -> tuple[str, ...]:
        """Match the current action against declared sequences, then record it.

        `key` scopes the window (conversation_id, falling back to agent_id).
        Returns the sorted principle refs whose declared sequence ends at this
        action's class. Untagged actions (`None`/"") never match or record.
        """
        if not intent_class:
            return ()
        window = self._windows.get(key)
        if window is None:
            window = deque(maxlen=self._window)
            self._windows[key] = window
            while len(self._windows) > self._max_conversations:
                self._windows.popitem(last=False)  # FIFO: evict the oldest conversation
        prior = list(window)
        matched = sorted(
            str(seq["principle_ref"])
            for seq in sequences
            if (classes := list(seq.get("intent_classes", [])))
            and classes[-1] == intent_class
            and _ordered_subsequence(classes[:-1], prior)
        )
        window.append(intent_class)
        return tuple(matched)
