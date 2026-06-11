"""Canonical form + content-hash version (POL-08 key).

Same content in any authoring order -> identical canonical form -> the same
`sha256:` version. The canonical-JSON idiom (sorted keys, compact separators)
is intentionally local — do NOT import from controlplane (audit is a different
trust boundary)."""

import hashlib
import json

from agentos_constitution.schema import Constitution


def _id_key(principle_id: str) -> tuple[int, ...]:
    """Natural sort over numeric id segments: '3.10' > '3.2'."""
    return tuple(int(x) for x in principle_id.split("."))


def canonical_form(c: Constitution) -> dict:
    """Order-invariant dict: principles sorted by id, lists sorted+deduped,
    per_action_type keys sorted."""
    form = c.model_dump(mode="json", by_alias=True)
    form["principles"] = sorted(form["principles"], key=lambda p: _id_key(p["id"]))
    form["lists"] = {name: sorted(set(values)) for name, values in form["lists"].items()}
    if form.get("graduated"):
        per = form["graduated"]["per_action_type"]
        form["graduated"]["per_action_type"] = {k: per[k] for k in sorted(per)}
    return form


def _canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def constitution_version(c: Constitution) -> str:
    """Content-hash version of the canonical form: 'sha256:<hex>'."""
    return "sha256:" + hashlib.sha256(_canonical_json(canonical_form(c))).hexdigest()
