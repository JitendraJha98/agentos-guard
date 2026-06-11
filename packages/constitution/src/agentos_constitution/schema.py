"""POL-01 — the structured Constitution schema.

Operators author numbered principles (id/title/statement verbatim) with a bounded
`when` algebra over the versioned policy-input registry (D4). temporary_exception
is never authorable as an effect (POL-13). All models are extra="forbid".
"""

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from agentos_contract import ActionType, SideEffect
from agentos_contract.policy_io import AUTHORABLE_EFFECTS, POLICY_INPUT_FIELDS

Op = Literal["eq", "ne", "in", "not_in", "prefix", "glob", "gte", "lte"]

_MAX_DEPTH = 3
_LIST_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_SEQUENCE_CLASS_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


class Leaf(BaseModel):
    """A single comparison: {field, op, value | list_ref}."""

    model_config = {"extra": "forbid"}

    field: str
    op: Op
    value: str | int | float | bool | list[str] | None = None
    list_ref: str | None = None

    @model_validator(mode="after")
    def _validate_leaf(self) -> "Leaf":
        if self.field not in POLICY_INPUT_FIELDS:
            raise ValueError(f"unknown policy-input field: {self.field!r}")
        if (self.value is None) == (self.list_ref is None):
            raise ValueError("exactly one of value/list_ref is required")
        if self.list_ref is not None and self.op not in ("in", "not_in"):
            raise ValueError(f"op {self.op!r} does not accept list_ref (only in/not_in)")
        ftype, _ = POLICY_INPUT_FIELDS[self.field]
        if self.op in ("prefix", "glob"):
            if ftype is not str or not isinstance(self.value, str):
                raise ValueError(
                    f"op {self.op!r} requires a string field and string value, "
                    f"got field {self.field!r}"
                )
        elif self.op in ("gte", "lte"):
            if ftype not in (int, float) or isinstance(self.value, bool) or not isinstance(
                self.value, (int, float)
            ):
                raise ValueError(
                    f"op {self.op!r} requires a numeric field and numeric value, "
                    f"got field {self.field!r}"
                )
        elif self.op in ("eq", "ne"):
            scalar_ok = (
                self.value is not None
                and not isinstance(self.value, list)
                and isinstance(self.value, ftype)
                and not (isinstance(self.value, bool) and ftype is not bool)
            )
            if not scalar_ok:
                raise ValueError(
                    f"op {self.op!r} requires a scalar value matching the type of "
                    f"field {self.field!r}"
                )
        else:  # in / not_in
            if ftype is not str:
                raise ValueError(f"op {self.op!r} applies to string fields only")
            if self.value is not None and not isinstance(self.value, list):
                raise ValueError(f"op {self.op!r} requires a list[str] value or list_ref")
        return self


class AllNode(BaseModel):
    model_config = {"extra": "forbid"}
    all: list["Node"] = Field(min_length=1)


class AnyNode(BaseModel):
    model_config = {"extra": "forbid"}
    any: list["Node"] = Field(min_length=1)


class NotNode(BaseModel):
    model_config = {"extra": "forbid"}
    not_: "Node" = Field(alias="not")


Node = Leaf | AllNode | AnyNode | NotNode

AllNode.model_rebuild()
AnyNode.model_rebuild()
NotNode.model_rebuild()


def _depth(node: "Node") -> int:
    """Combinator nesting depth; a bare leaf is 0."""
    if isinstance(node, Leaf):
        return 0
    if isinstance(node, AllNode):
        return 1 + max(_depth(n) for n in node.all)
    if isinstance(node, AnyNode):
        return 1 + max(_depth(n) for n in node.any)
    return 1 + _depth(node.not_)


def _leaves(node: "Node"):
    if isinstance(node, Leaf):
        yield node
    elif isinstance(node, AllNode):
        for n in node.all:
            yield from _leaves(n)
    elif isinstance(node, AnyNode):
        for n in node.any:
            yield from _leaves(n)
    else:
        yield from _leaves(node.not_)


class Principle(BaseModel):
    model_config = {"extra": "forbid"}

    id: str = Field(pattern=r"^\d+(\.\d+)*$")
    title: str = Field(max_length=120)
    statement: str = Field(max_length=2000)  # VERBATIM — never normalized
    kind: Literal["action", "sequence"] = "action"
    applies_to: list[ActionType] | Literal["all"] = "all"
    effect: str
    when: Node | None = None            # action kind only
    sequence: list[str] | None = None   # sequence kind only
    side_effects: list[SideEffect] = Field(default_factory=list)

    @field_validator("effect")
    @classmethod
    def _authorable_effect(cls, v: str) -> str:
        if v not in AUTHORABLE_EFFECTS:
            if v == "temporary_exception":
                raise ValueError(
                    "effect temporary_exception is human-ratified only — "
                    "never authorable (POL-13)"
                )
            raise ValueError(f"unknown effect {v!r}; authorable effects: "
                             f"{sorted(AUTHORABLE_EFFECTS)}")
        return v

    @field_validator("sequence")
    @classmethod
    def _sequence_classes(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            if len(v) < 2:
                raise ValueError("sequence requires at least 2 intent classes")
            for cls_name in v:
                if not _SEQUENCE_CLASS_RE.match(cls_name):
                    raise ValueError(
                        f"sequence intent classes must be UPPER_SNAKE, got {cls_name!r}"
                    )
        return v

    @model_validator(mode="after")
    def _kind_consistency(self) -> "Principle":
        if self.kind == "sequence":
            if self.sequence is None:
                raise ValueError("sequence principles require a sequence of intent classes")
            if self.when is not None:
                raise ValueError("sequence principles must not declare a when condition")
        else:
            if self.sequence is not None:
                raise ValueError("action principles must not declare a sequence")
        if self.when is not None and _depth(self.when) > _MAX_DEPTH:
            raise ValueError(f"when condition nesting depth exceeds {_MAX_DEPTH}")
        return self


class GraduatedThresholdsCfg(BaseModel):
    model_config = {"extra": "forbid"}

    sandbox_at: float = 0.4
    deny_at: float = 0.7
    trust_harden_at: float = 0.2

    @model_validator(mode="after")
    def _ordered(self) -> "GraduatedThresholdsCfg":
        # Same ordering invariant as the pipeline's GraduatedThresholds (POL-06).
        if not (0.0 <= self.sandbox_at <= self.deny_at <= 1.0):
            raise ValueError(
                "graduated thresholds require 0.0 <= sandbox_at <= deny_at <= 1.0, "
                f"got sandbox_at={self.sandbox_at}, deny_at={self.deny_at}"
            )
        if not (0.0 <= self.trust_harden_at <= 1.0):
            raise ValueError(
                f"graduated thresholds require 0.0 <= trust_harden_at <= 1.0, "
                f"got {self.trust_harden_at}"
            )
        return self


class GraduatedSection(BaseModel):
    model_config = {"extra": "forbid"}

    default: GraduatedThresholdsCfg = GraduatedThresholdsCfg()
    per_action_type: dict[ActionType, GraduatedThresholdsCfg] = Field(default_factory=dict)


class Constitution(BaseModel):
    model_config = {"extra": "forbid"}

    schema_version: Literal[1]
    name: str
    principles: list[Principle]
    lists: dict[str, list[str]] = Field(default_factory=dict)
    graduated: GraduatedSection | None = None

    @field_validator("lists")
    @classmethod
    def _list_names(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
        for name in v:
            if not _LIST_NAME_RE.match(name):
                raise ValueError(f"list names must match ^[a-z][a-z0-9_]*$, got {name!r}")
        return v

    @model_validator(mode="after")
    def _cross_checks(self) -> "Constitution":
        seen: set[str] = set()
        for p in self.principles:
            if p.id in seen:
                raise ValueError(f"duplicate principle id {p.id!r}")
            seen.add(p.id)
        for p in self.principles:
            if p.when is None:
                continue
            for leaf in _leaves(p.when):
                if leaf.list_ref is not None and leaf.list_ref not in self.lists:
                    raise ValueError(f"unknown list {leaf.list_ref!r} referenced by "
                                     f"principle {p.id}")
        return self


def load_constitution(path: str | Path) -> Constitution:
    """Load + validate a Constitution from a structured-YAML file (POL-01)."""
    with open(path, encoding="utf-8") as fh:
        return Constitution.model_validate(yaml.safe_load(fh))
