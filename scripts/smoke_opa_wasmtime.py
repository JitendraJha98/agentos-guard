"""01-04 Task 1 (checkpoint:human-verify) — throwaway smoke test for opa-wasmtime.

This script is NOT production code and adds NOTHING to the locked dependencies.
It exists only to satisfy the BLOCKING human-verify checkpoint (RESEARCH A1):
prove that the WebSearch-discovered `opa-wasmtime` package correctly loads an
OPA-CLI-built WASM bundle and evaluates the Phase-1 egress-allowlist principle
(allow for an allowlisted host, deny for an attacker host) BEFORE the package is
added to `uv.lock` in Task 3.

It also resolves Open Question Q1: the exact Python object `OPAPolicy.evaluate()`
returns, so `_extract_bool` in Task 3 (policy.py) can parse it correctly.

Run (from repo root, against the throwaway venv that has opa-wasmtime installed):
    .smoke-venv/Scripts/python.exe scripts/smoke_opa_wasmtime.py

Prereqs the script handles itself:
  - compiles a throwaway egress.rego -> WASM with the PINNED OPA CLI
    (tools/opa/opa.exe, OPA v1.17.0) using:
        opa build -t wasm -e 'agentos/egress/allow' <rego>
    then extracts /policy.wasm from the produced bundle.tar.gz.
  - loads the .wasm via opa_wasmtime.OPAPolicy, set_data({"allowlist": [...]}),
    and evaluates one allow + one deny input.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OPA_BIN = REPO_ROOT / "tools" / "opa" / "opa.exe"
BUILD_DIR = REPO_ROOT / "scripts" / "_smoke_build"  # gitignored throwaway output

# The Phase-1 principle, authored directly as Rego (D-02). Hosts are supplied as a
# Rego `data` document at runtime via set_data, so the allowlist is configuration
# and the rule logic stays in Rego.
EGRESS_REGO = """package agentos.egress

import rego.v1

default allow := false

allow if {
\tinput.type == "tool_call"
\tinput.host in data.allowlist
}
"""

ALLOWLIST = ["api.example.com"]
INPUT_ALLOW = {"type": "tool_call", "host": "api.example.com"}
INPUT_DENY = {"type": "tool_call", "host": "attacker.example"}


def build_wasm() -> Path:
    """Compile the throwaway egress.rego to a policy.wasm with the pinned OPA CLI."""
    if not OPA_BIN.is_file():
        sys.exit(f"OPA CLI not found at {OPA_BIN} — download the pinned v1.17.0 release first.")
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    rego_path = BUILD_DIR / "egress.rego"
    rego_path.write_text(EGRESS_REGO, encoding="utf-8")

    bundle_path = BUILD_DIR / "bundle.tar.gz"
    # -e maps the entrypoint: data.agentos.egress.allow
    subprocess.run(
        [
            str(OPA_BIN),
            "build",
            "-t",
            "wasm",
            "-e",
            "agentos/egress/allow",
            str(rego_path),
            "-o",
            str(bundle_path),
        ],
        check=True,
        cwd=str(BUILD_DIR),
    )

    # The bundle is a tar.gz containing /policy.wasm (plus /data.json, /.manifest).
    with tarfile.open(bundle_path, "r:gz") as tf:
        member = next(m for m in tf.getmembers() if m.name.endswith("policy.wasm"))
        member.name = "egress.wasm"
        tf.extract(member, path=str(BUILD_DIR), filter="data")
    wasm_path = BUILD_DIR / "egress.wasm"
    print(f"[build] compiled WASM bundle -> {wasm_path} ({wasm_path.stat().st_size} bytes)")
    return wasm_path


def main() -> int:
    from opa_wasmtime import OPAPolicy  # imported here so a missing pkg fails loudly

    wasm_path = build_wasm()

    # Load ONCE (Pitfall 2 — never per request) and inject the allowlist as Rego data.
    policy = OPAPolicy(str(wasm_path))
    policy.set_data({"allowlist": ALLOWLIST})
    print(f"[load ] OPAPolicy loaded; allowlist data set to {ALLOWLIST}")
    print(f"[load ] entrypoints exposed by the bundle: {policy.entrypoints}")

    allow_result = policy.evaluate(INPUT_ALLOW)
    deny_result = policy.evaluate(INPUT_DENY)

    print("\n=== evaluate() RESULT SHAPE (resolves Open Question Q1) ===")
    print(f"  input  {INPUT_ALLOW}")
    print(f"  python type: {type(allow_result).__name__}")
    print(f"  repr       : {allow_result!r}")
    print(f"  json       : {json.dumps(allow_result)}")
    print(f"\n  input  {INPUT_DENY}")
    print(f"  repr       : {deny_result!r}")
    print(f"  json       : {json.dumps(deny_result)}")

    # Extract the boolean from the OPA result set: [{"result": <bool>}].
    def extract_bool(result) -> bool:
        if isinstance(result, list) and result and isinstance(result[0], dict):
            return bool(result[0].get("result"))
        return False

    allowed = extract_bool(allow_result)
    denied = not extract_bool(deny_result)

    print("\n=== ALLOW / DENY verdicts ===")
    print(f"  api.example.com  (allowlisted)     -> {'allow' if allowed else 'DENY'}")
    print(f"  attacker.example (not allowlisted) -> {'deny' if denied else 'ALLOW'}")

    ok = allowed and denied
    print(f"\nSMOKE TEST: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
