"""Shared-token API auth (Phase-5 P0).

`make_require_token` builds a FastAPI dependency that enforces `Authorization: Bearer <token>`;
missing/wrong tokens are a uniform 401. `resolve_api_token` resolves explicit arg -> env ->
ephemeral random (never silently wide-open).
"""

from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from agentos_controlplane.auth import make_require_token, resolve_api_token


def _client(token: str) -> TestClient:
    app = FastAPI()

    @app.get("/x", dependencies=[Depends(make_require_token(token))])
    def x() -> dict:
        return {"ok": True}

    return TestClient(app)


def test_require_token_rejects_missing_and_wrong_accepts_correct() -> None:
    client = _client("t")
    assert client.get("/x").status_code == 401
    assert client.get("/x", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/x", headers={"Authorization": "t"}).status_code == 401  # no Bearer prefix
    ok = client.get("/x", headers={"Authorization": "Bearer t"})
    assert ok.status_code == 200 and ok.json() == {"ok": True}


def test_require_token_non_ascii_header_is_401_not_500() -> None:
    """A raw high-byte Authorization header decodes into a non-ASCII str;
    secrets.compare_digest raises TypeError on non-ASCII. The gate must reject
    it as the uniform 401 (fail closed), NOT surface an unhandled TypeError as
    a 500 — the same contract already enforced for the dashboard session cookie."""
    client = _client("t")
    resp = client.get("/x", headers={"Authorization": b"Bearer \xe9\xe9\xe9"})
    assert resp.status_code == 401


def test_resolve_api_token_explicit_wins() -> None:
    assert resolve_api_token("x") == "x"


def test_resolve_api_token_falls_back_to_env(monkeypatch) -> None:
    monkeypatch.setenv("AGENTOS_API_TOKEN", "from-env")
    assert resolve_api_token() == "from-env"


def test_resolve_api_token_ephemeral_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("AGENTOS_API_TOKEN", raising=False)
    token = resolve_api_token()
    assert isinstance(token, str) and len(token) >= 16  # non-empty ephemeral
