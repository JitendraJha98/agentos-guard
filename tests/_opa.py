"""Locate OPA (vendored exe on the Windows dev box; PATH on CI) + build test WASM.

The Slice-3 fixtures compile the test constitutions at session start via this
helper; tests skip cleanly when no OPA binary is found anywhere.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from agentos_constitution import CompiledBundle, compile_constitution, load_constitution
from agentos_constitution.wasm import OPA_BIN, build_wasm


def find_opa() -> str | None:
    """The vendored opa.exe if present (Windows dev box), else PATH (CI installs
    Linux OPA). OPA_BIN is repo-root-anchored — never CWD-dependent."""
    return str(OPA_BIN) if OPA_BIN.exists() else shutil.which("opa")


@dataclass(frozen=True)
class BuiltPolicy:
    """A compiled test constitution: WASM path + bundle + per-principle metadata."""

    wasm_path: Path
    bundle: CompiledBundle
    principles_meta: dict[str, dict]  # {ref: {title, statement, effect, side_effects, remediation}}


def build_constitution_wasm(constitution_path: Path, out_dir: Path) -> BuiltPolicy:
    """compile_constitution + agentos_constitution.wasm.build_wasm via find_opa()."""
    constitution = load_constitution(constitution_path)
    bundle = compile_constitution(constitution)
    wasm_path = build_wasm(bundle.rego, Path(out_dir), opa_bin=find_opa())
    principles_meta = {
        p.id: {
            "title": p.title,
            "statement": p.statement,
            "effect": p.effect,
            "side_effects": [s.value for s in p.side_effects],
            "remediation": p.remediation,
        }
        for p in constitution.principles
    }
    return BuiltPolicy(wasm_path=wasm_path, bundle=bundle, principles_meta=principles_meta)
