"""agentos-constitution — Constitution schema + deterministic compiler (POL-01/POL-02)."""

from agentos_constitution.compiler import CompiledBundle, compile_constitution
from agentos_constitution.schema import (
    Constitution,
    GraduatedSection,
    GraduatedThresholdsCfg,
    Leaf,
    Node,
    Principle,
    load_constitution,
)
from agentos_constitution.version import canonical_form, constitution_version
from agentos_constitution.wasm import build_wasm

__all__ = [
    "build_wasm",
    "canonical_form",
    "compile_constitution",
    "CompiledBundle",
    "constitution_version",
    "Constitution",
    "GraduatedSection",
    "GraduatedThresholdsCfg",
    "Leaf",
    "Node",
    "Principle",
    "load_constitution",
]
