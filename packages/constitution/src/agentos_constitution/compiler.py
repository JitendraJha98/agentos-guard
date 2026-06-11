"""POL-02 — deterministic Constitution -> YAML policy -> Rego compiler.

Pure functions: canonical sort (Task 4) -> reviewable YAML middle layer -> Rego
via DNF normalization (Rego OR = separate rules; `not` pushed to leaves by
De Morgan). One entrypoint: agentos/constitution/result ->
{"matched": [...], "no_match": bool}. Every rule carries `principle_ref`
provenance plus a comment block citing id/title/statement. Named lists stay
runtime `data` (set_data({"lists": ...})); sequence principles also emit
bundle metadata for the Slice-7 correlator. Golden tests lock the bytes.
"""

import json
from dataclasses import dataclass

import yaml

from agentos_contract.policy_io import POLICY_INPUT_SCHEMA_VERSION

from agentos_constitution.schema import (
    AllNode,
    AnyNode,
    Constitution,
    GraduatedSection,
    Leaf,
    Node,
    NotNode,
    Principle,
)
from agentos_constitution.version import _id_key, canonical_form, constitution_version


@dataclass(frozen=True)
class CompiledBundle:
    constitution_version: str
    input_schema_version: int
    yaml_policy: str          # the reviewable middle layer
    rego: str                 # deterministic Rego, one entrypoint agentos/constitution/result
    sequences: list[dict]     # [{principle_ref, intent_classes, effect}] for the Slice-7 correlator
    graduated_config: dict    # from the graduated: section (defaults if absent)
    lists: dict[str, list[str]]   # runtime data document (set_data({"lists": ...}))


# ---- condition lowering ----

# The schema's depth<=3 bound limits nesting, NOT breadth: an `all` of N `any`
# nodes expands to the product of their branch counts (e.g. 4 any-of-3 -> 81
# disjuncts), so _principle_rules enforces this ceiling per principle.
_MAX_DISJUNCTS = 64


def _to_dnf(node: Node, negated: bool = False) -> list[list[tuple[Leaf, bool]]]:
    """Normalize to a list of disjuncts; each disjunct is [(leaf, negated)].
    not(all) / not(any) via De Morgan; not(leaf) -> (leaf, True). Expansion is a
    cross product over `all` children — the caller caps it at _MAX_DISJUNCTS."""
    if isinstance(node, Leaf):
        return [[(node, negated)]]
    if isinstance(node, NotNode):
        return _to_dnf(node.not_, not negated)
    children = node.all if isinstance(node, AllNode) else node.any
    child_dnfs = [_to_dnf(child, negated) for child in children]
    conjunctive = isinstance(node, AllNode) != negated   # De Morgan: not(any) is a conjunction
    if conjunctive:
        disjuncts: list[list[tuple[Leaf, bool]]] = [[]]
        for child_dnf in child_dnfs:
            disjuncts = [acc + disjunct for acc in disjuncts for disjunct in child_dnf]
        return disjuncts
    return [disjunct for child_dnf in child_dnfs for disjunct in child_dnf]


_OP_TEMPLATES = {
    "eq":     "input.{f} == {v}",
    "ne":     "input.{f} != {v}",
    "in":     "input.{f} in {v}",          # {v} = set literal or data.lists.<name>
    "not_in": "not input.{f} in {v}",
    "prefix": "startswith(input.{f}, {v})",
    "glob":   'glob.match({v}, ["."], input.{f})',
    "gte":    "input.{f} >= {v}",
    "lte":    "input.{f} <= {v}",
    # negated-leaf inversions of gte/lte (never authored directly):
    "lt":     "input.{f} < {v}",
    "gt":     "input.{f} > {v}",
}

# Exact-inverse op under negation; prefix/glob have none and get a `not ` prefix.
_NEGATED_OP = {"eq": "ne", "ne": "eq", "in": "not_in", "not_in": "in",
               "gte": "lt", "lte": "gt"}


def _render_value(leaf: Leaf) -> str:
    if leaf.list_ref is not None:
        return f"data.lists.{leaf.list_ref}"
    if isinstance(leaf.value, list):
        return "{" + ", ".join(sorted(json.dumps(x) for x in leaf.value)) + "}"
    return json.dumps(leaf.value)


def _lower_leaf(leaf: Leaf, negated: bool) -> str:
    op = leaf.op
    if negated:
        op = _NEGATED_OP.get(op, op)
    line = _OP_TEMPLATES[op].format(f=leaf.field, v=_render_value(leaf))
    if negated and op == leaf.op:   # prefix/glob: no inverse op — negate the expression
        line = f"not {line}"
    return line


def _sanitize_comment(text: str) -> str:
    """Defense-in-depth (schema already rejects these): control characters must
    not break out of a single `# ` comment line, so replace them with spaces."""
    return "".join(" " if ch < " " else ch for ch in text)


def _principle_rules(p: Principle) -> str:
    comment_lines = [f"# Principle {p.id} — {_sanitize_comment(p.title)}"]
    # splitlines() splits on \r and every other line boundary, so each statement
    # line lands inside its own `# ` comment — nothing can escape into Rego.
    comment_lines += [f"# {line}" for line in p.statement.splitlines()]
    comment = "\n".join(comment_lines)

    head = f'matched contains {{"principle_ref": "{p.id}", "effect": "{p.effect}"}} if {{'
    scope: list[str] = []
    if p.applies_to != "all":
        types = ", ".join(json.dumps(t.value) for t in sorted(p.applies_to, key=lambda t: t.value))
        scope = [f"input.type in {{{types}}}"]

    if p.kind == "sequence":
        bodies = [scope + [f'"{p.id}" in input.sequence.matched_refs']]
    else:
        disjuncts = _to_dnf(p.when) if p.when is not None else [[]]
        if len(disjuncts) > _MAX_DISJUNCTS:
            raise ValueError(
                f"principle {p.id}: condition expands to {len(disjuncts)} disjuncts "
                f"(max {_MAX_DISJUNCTS}) — simplify the condition"
            )
        bodies = [scope + [_lower_leaf(leaf, neg) for leaf, neg in disjunct] or ["true"]
                  for disjunct in disjuncts]

    rules = [head + "\n" + "".join(f"\t{line}\n" for line in body) + "}" for body in bodies]
    return comment + "\n" + "\n\n".join(rules)


REGO_HEADER = """# GENERATED by agentos-constitution — DO NOT EDIT.
# constitution_version: {version}
# policy_input_schema_version: {schema_v}
package agentos.constitution

import rego.v1

"""

REGO_FOOTER = """result := {"matched": matched, "no_match": count(matched) == 0}
"""


def _policy_doc(p: dict) -> dict:
    """One reviewable YAML-policy document per principle (canonical dump shape)."""
    doc = {
        "id": p["id"],
        "title": p["title"],
        "statement": p["statement"],   # VERBATIM
        "kind": p["kind"],
        "applies_to": p["applies_to"],
        "effect": p["effect"],
        "side_effects": p["side_effects"],
    }
    if p["kind"] == "sequence":
        doc["sequence"] = p["sequence"]
    else:
        doc["condition"] = p["when"]
    return doc


def compile_constitution(c: Constitution) -> CompiledBundle:
    version = constitution_version(c)
    form = canonical_form(c)

    yaml_policy = yaml.safe_dump(
        {"constitution_version": version,
         "policies": [_policy_doc(p) for p in form["principles"]]},
        sort_keys=True, default_flow_style=False, allow_unicode=True,
    )

    principles = sorted(c.principles, key=lambda p: _id_key(p.id))
    rego = (
        REGO_HEADER.format(version=version, schema_v=POLICY_INPUT_SCHEMA_VERSION)
        + "\n\n".join(_principle_rules(p) for p in principles)
        + "\n\n"
        + REGO_FOOTER
    )

    sequences = [
        {"principle_ref": p.id, "intent_classes": list(p.sequence), "effect": p.effect}
        for p in principles
        if p.kind == "sequence"
    ]
    graduated = c.graduated if c.graduated is not None else GraduatedSection()
    return CompiledBundle(
        constitution_version=version,
        input_schema_version=POLICY_INPUT_SCHEMA_VERSION,
        yaml_policy=yaml_policy,
        rego=rego,
        sequences=sequences,
        graduated_config=graduated.model_dump(mode="json"),
        lists=form["lists"],
    )
