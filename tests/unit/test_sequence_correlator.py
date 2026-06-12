"""SequenceCorrelator unit behavior (SEC-13) — ordered-subsequence, bounds, isolation."""

from agentos_pipeline.sequence import SequenceCorrelator

SEQS = [
    {"principle_ref": "3.5", "intent_classes": ["RESOURCE_RENAME", "DATA_DESTRUCTION"], "effect": "deny"}
]


def test_rename_then_drop_matches():
    c = SequenceCorrelator()
    assert c.observe("conv", "RESOURCE_RENAME", SEQS) == ()
    assert c.observe("conv", "DATA_DESTRUCTION", SEQS) == ("3.5",)


def test_drop_alone_does_not_match():
    c = SequenceCorrelator()
    assert c.observe("conv", "DATA_DESTRUCTION", SEQS) == ()


def test_untagged_actions_are_skipped_not_sequence_breaking():
    c = SequenceCorrelator()
    c.observe("conv", "RESOURCE_RENAME", SEQS)
    assert c.observe("conv", None, SEQS) == ()       # benign http_get between the steps
    assert c.observe("conv", "DATA_DESTRUCTION", SEQS) == ("3.5",)


def test_wrong_order_does_not_match():
    c = SequenceCorrelator()
    c.observe("conv", "DATA_DESTRUCTION", SEQS)
    assert c.observe("conv", "RESOURCE_RENAME", SEQS) == ()


def test_conversations_are_isolated():
    c = SequenceCorrelator()
    c.observe("conv-a", "RESOURCE_RENAME", SEQS)
    assert c.observe("conv-b", "DATA_DESTRUCTION", SEQS) == ()
    assert c.observe("conv-a", "DATA_DESTRUCTION", SEQS) == ("3.5",)


def test_window_eviction_forgets_old_steps():
    c = SequenceCorrelator(window=3)
    c.observe("conv", "RESOURCE_RENAME", SEQS)
    for _ in range(3):                                # push the rename out of the window
        c.observe("conv", "X", SEQS)
    assert c.observe("conv", "DATA_DESTRUCTION", SEQS) == ()


def test_max_conversations_fifo_bound():
    c = SequenceCorrelator(max_conversations=2)
    c.observe("c1", "RESOURCE_RENAME", SEQS)
    c.observe("c2", "RESOURCE_RENAME", SEQS)
    c.observe("c3", "RESOURCE_RENAME", SEQS)          # evicts c1
    assert c.observe("c1", "DATA_DESTRUCTION", SEQS) == ()   # window gone -> fresh (re-inserts c1, evicting c2)
    assert c.observe("c3", "DATA_DESTRUCTION", SEQS) == ("3.5",)   # c3 survived with its rename


def test_multi_match_is_sorted_and_deterministic():
    seqs = SEQS + [
        {"principle_ref": "9.9", "intent_classes": ["DATA_DESTRUCTION"], "effect": "deny"},
        {"principle_ref": "1.2", "intent_classes": ["DATA_DESTRUCTION"], "effect": "warn"},
    ]
    c = SequenceCorrelator()
    c.observe("conv", "RESOURCE_RENAME", seqs)
    assert c.observe("conv", "DATA_DESTRUCTION", seqs) == ("1.2", "3.5", "9.9")
