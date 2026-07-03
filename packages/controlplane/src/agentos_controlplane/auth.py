"""Phase-5 shared-token API auth (P0). A single shared secret gates every control-plane route via
`Authorization: Bearer <token>`. Token resolution order: explicit arg -> AGENTOS_API_TOKEN env ->
an ephemeral random token (logged loudly; never silently wide-open). Per-principal authn/RBAC is a
later phase (documented limitation)."""

from __future__ import annotations

import logging
import os
import secrets

from fastapi import Header, HTTPException

log = logging.getLogger("agentos_controlplane.auth")


def resolve_api_token(explicit: str | None = None) -> str:
    token = explicit or os.environ.get("AGENTOS_API_TOKEN")
    if not token:
        token = secrets.token_urlsafe(32)
        log.warning(
            "AGENTOS_API_TOKEN not set and no token passed to create_app — generated an EPHEMERAL "
            "API token for this process. Set AGENTOS_API_TOKEN for a stable shared secret."
        )
    return token


def make_require_token(token: str):
    """Build a FastAPI dependency that enforces `Authorization: Bearer <token>`."""
    expected = f"Bearer {token}"

    def require_token(authorization: str | None = Header(default=None)) -> None:
        # constant-time compare; reject missing/short/incorrect uniformly as 401.
        ok = False
        if authorization is not None:
            try:
                ok = secrets.compare_digest(authorization, expected)
            except TypeError:
                # A raw high-byte Authorization header decodes into a non-ASCII str,
                # which compare_digest refuses; treat it as an invalid token (fail
                # closed to the uniform 401), not a 500.
                ok = False
        if not ok:
            raise HTTPException(status_code=401, detail="invalid or missing API token")

    return require_token
