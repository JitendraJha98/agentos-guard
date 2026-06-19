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


def build_wasm(rego_text: str, out_dir: Path, opa_bin: str | None = None) -> Path:
    """opa build -t wasm -e agentos/constitution/result; extract policy.wasm.

    `opa_bin` overrides the OPA CLI location (CI installs Linux OPA on PATH);
    the default is the vendored Windows exe (the original behavior).
    """
    opa = Path(opa_bin) if opa_bin is not None else OPA_BIN
    if not opa.is_file():
        raise FileNotFoundError(f"OPA CLI not found at {opa}")
    out_dir = Path(out_dir)
    rego_path = out_dir / "constitution.rego"
    rego_path.write_text(rego_text, encoding="utf-8")
    bundle_path = out_dir / "bundle.tar.gz"
    # Pass bare relative names with cwd=out_dir: OPA's loader parses the "C:" of a
    # drive-lettered absolute path as a `prefix:path` data-root annotation, stripping
    # the drive — which only resolves by accident when CWD shares that drive (breaks
    # cross-drive on Windows, e.g. repo on E: + temp on C:).
    subprocess.run(
        [str(opa), "build", "-t", "wasm", "-e", ENTRYPOINT,
         "constitution.rego", "-o", "bundle.tar.gz"],
        check=True, capture_output=True, cwd=out_dir,
    )
    with tarfile.open(bundle_path, "r:gz") as tf:   # member is "/policy.wasm"
        member = next(m for m in tf.getmembers() if m.name.lstrip("/") == "policy.wasm")
        member.name = "policy.wasm"                 # strip the leading "/" for extraction
        tf.extract(member, path=str(out_dir), filter="data")
    return out_dir / "policy.wasm"
