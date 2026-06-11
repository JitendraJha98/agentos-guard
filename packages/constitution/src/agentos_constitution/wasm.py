"""WASM build of compiled constitution Rego via the vendored OPA CLI (POL-02).

Mirrors the verified recipe in scripts/smoke_opa_wasmtime.py: `opa build -t wasm`
with the single entrypoint agentos/constitution/result, then extract policy.wasm
from the produced bundle.tar.gz.
"""

import subprocess
import tarfile
from pathlib import Path

# wasm.py -> agentos_constitution -> src -> constitution -> packages -> repo root
_REPO_ROOT = Path(__file__).resolve().parents[4]
OPA_BIN = _REPO_ROOT / "tools" / "opa" / "opa.exe"
ENTRYPOINT = "agentos/constitution/result"


def build_wasm(rego_text: str, out_dir: Path) -> Path:
    """opa build -t wasm -e agentos/constitution/result; extract policy.wasm."""
    if not OPA_BIN.is_file():
        raise FileNotFoundError(f"vendored OPA CLI not found at {OPA_BIN}")
    out_dir = Path(out_dir)
    rego_path = out_dir / "constitution.rego"
    rego_path.write_text(rego_text, encoding="utf-8")
    bundle_path = out_dir / "bundle.tar.gz"
    subprocess.run(
        [str(OPA_BIN), "build", "-t", "wasm", "-e", ENTRYPOINT,
         str(rego_path), "-o", str(bundle_path)],
        check=True, capture_output=True,
    )
    with tarfile.open(bundle_path, "r:gz") as tf:   # member is "/policy.wasm"
        member = next(m for m in tf.getmembers() if m.name.lstrip("/") == "policy.wasm")
        member.name = "policy.wasm"                 # strip the leading "/" for extraction
        tf.extract(member, path=str(out_dir), filter="data")
    return out_dir / "policy.wasm"
