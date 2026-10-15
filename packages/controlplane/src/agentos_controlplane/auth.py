"""Control-plane API auth.

Phase-5 shared-token auth (P0): a single shared secret gates every route via
`Authorization: Bearer <token>`. Token resolution order: explicit arg -> AGENTOS_API_TOKEN env ->
an ephemeral random token (logged loudly; never silently wide-open).

Phase 16 (AUTH-01..03) adds named principals with roles on top of it:

- The shared token keeps working as the BOOTSTRAP principal (role admin), so no deployment loses
  access on upgrade. Its actor names stay caller-claimed and unverified, exactly as before — the
  point of named principals is to stop depending on it.
- A named principal's token is `agp_<id hex>_<secret>`. Only SHA-256(secret) is stored.
- Roles are ordered viewer < operator < admin. `required_role` maps every route centrally: reads
  need viewer, writes need operator, and `ADMIN_ROUTES` lists the ones that change what the control
  plane itself enforces or discloses. One table, so a reviewer can audit it in one place.
- Actor binding: when a named principal calls a route whose body names an actor (`set_by`,
  `resolver`, `ratified_by`, `resolved_by`, `proposed_by`), the name MUST be the principal's own.
  Before this, whoever held the token could record a kill — or a "human ratification" — under
  anyone's name.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import Header, HTTPException, Request
from sqlalchemy import select

from agentos_controlplane.store.models import ApiPrincipal

log = logging.getLogger("agentos_controlplane.auth")

ROLES = ("viewer", "operator", "admin")
_RANK = {role: i for i, role in enumerate(ROLES)}
BOOTSTRAP = "bootstrap"
_PREFIX = "agp_"
# Body fields that NAME the acting human; bound to the authenticated principal (AUTH-03).
ACTOR_FIELDS = ("set_by", "resolver", "ratified_by", "resolved_by", "proposed_by")

# (method, route template) pairs that need admin. Everything else: GET/HEAD -> viewer, any other
# method -> operator. Admin = changes what is ENFORCED (constitution, trust, budgets, ABOM,
# ratification) or DISCLOSES evidence to a third party (disclosure, compliance export), or manages
# who may act (principals).
ADMIN_ROUTES = frozenset(
    {
        ("POST", "/constitutions"),
        ("PUT", "/trust-profiles/{agent_id}"),
        ("PUT", "/aboms/{agent_id}"),
        ("PUT", "/aboms/{agent_id}/declare"),
        ("PUT", "/economics/budgets/{agent_id}"),
        ("POST", "/amendments/{amendment_id}/ratify"),
        ("GET", "/audit/disclose/{seq}"),
        ("GET", "/compliance/export/{framework}"),
        ("GET", "/principals"),
        ("POST", "/principals"),
        ("POST", "/principals/{name}/revoke"),
    }
)


def required_role(method: str, path_template: str) -> str:
    if (method.upper(), path_template) in ADMIN_ROUTES:
        return "admin"
    return "viewer" if method.upper() in ("GET", "HEAD") else "operator"


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    bootstrap: bool = False

    def allows(self, role: str) -> bool:
        return _RANK[self.role] >= _RANK[role]


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _check_name(name: str) -> str:
    name = (name or "").strip()
    if not name or len(name) > 128 or name == BOOTSTRAP:
        raise ValueError("principal name must be 1-128 chars and not the reserved 'bootstrap'")
    if any(not (c.isalnum() or c in "._@-") for c in name):
        raise ValueError("principal name may contain only letters, digits and . _ @ -")
    return name


class PrincipalStore:
    """Named credentials. Lookups hit the table every request — the API is not the hot path, and a
    revocation must take effect on every instance at once, without a cache to invalidate."""

    def __init__(self, session_factory, audit) -> None:
        self._sf = session_factory
        self._audit = audit

    async def create(self, name: str, role: str, *, created_by: str) -> str:
        """Create a principal and return its token. The token is never retrievable again."""
        name = _check_name(name)
        if role not in _RANK:
            raise ValueError(f"role must be one of {ROLES}")
        pid, secret = uuid4(), secrets.token_urlsafe(32)
        with self._sf() as s:
            if s.scalar(select(ApiPrincipal).where(ApiPrincipal.name == name)) is not None:
                raise KeyError(f"principal {name!r} already exists")
            s.add(
                ApiPrincipal(
                    id=pid, name=name, role=role, token_hash=_hash(secret), created_by=created_by
                )
            )
            s.commit()
        await self._audit.append_event(
            "principal_created", {"name": name, "role": role, "set_by": created_by}
        )
        return f"{_PREFIX}{pid.hex}_{secret}"

    async def revoke(self, name: str, *, revoked_by: str) -> None:
        with self._sf() as s:
            row = s.scalar(select(ApiPrincipal).where(ApiPrincipal.name == name))
            if row is None:
                raise KeyError(f"unknown principal {name!r}")
            if row.revoked_at is not None:
                return  # idempotent, like certificate revocation
            row.revoked_at = datetime.now(timezone.utc)
            s.commit()
        await self._audit.append_event(
            "principal_revoked", {"name": name, "set_by": revoked_by}
        )

    def authenticate(self, token: str) -> Principal | None:
        if not token.startswith(_PREFIX):
            return None
        pid_hex, _, secret = token[len(_PREFIX):].partition("_")
        try:
            pid = UUID(hex=pid_hex)
        except ValueError:
            return None
        with self._sf() as s:
            row = s.get(ApiPrincipal, pid)
            if row is None or row.revoked_at is not None:
                return None
            if not secrets.compare_digest(row.token_hash, _hash(secret)):
                return None
            return Principal(name=row.name, role=row.role)

    def list(self) -> list[dict]:
        with self._sf() as s:
            rows = s.scalars(select(ApiPrincipal).order_by(ApiPrincipal.name)).all()
            return [
                {
                    "name": r.name,
                    "role": r.role,
                    "created_by": r.created_by,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "revoked": r.revoked_at is not None,
                }
                for r in rows
            ]


def resolve_api_token(explicit: str | None = None) -> str:
    token = explicit or os.environ.get("AGENTOS_API_TOKEN")
    if not token:
        token = secrets.token_urlsafe(32)
        log.warning(
            "AGENTOS_API_TOKEN not set and no token passed to create_app — generated an EPHEMERAL "
            "API token for this process. Set AGENTOS_API_TOKEN for a stable shared secret."
        )
    return token


def _safe_equal(a: str, b: str) -> bool:
    try:
        return secrets.compare_digest(a, b)
    except TypeError:
        # A raw high-byte header decodes into a non-ASCII str, which compare_digest refuses; treat
        # it as an invalid credential (fail closed to the uniform 401), not a 500.
        return False


def identify(credential: str | None, bootstrap_token: str, principals: PrincipalStore | None):
    """The principal a raw credential names, or None. Shared by the API and the dashboard."""
    if not credential:
        return None
    if _safe_equal(credential, bootstrap_token):
        return Principal(name=BOOTSTRAP, role="admin", bootstrap=True)
    if principals is not None:
        try:
            return principals.authenticate(credential)
        except (UnicodeEncodeError, ValueError):
            return None
    return None


def make_require_token(token: str):
    """Build a FastAPI dependency that enforces `Authorization: Bearer <token>` (shared token only;
    kept for callers that gate a single route outside `create_app`)."""
    expected = f"Bearer {token}"

    def require_token(authorization: str | None = Header(default=None)) -> None:
        # constant-time compare; reject missing/short/incorrect uniformly as 401.
        if authorization is None or not _safe_equal(authorization, expected):
            raise HTTPException(status_code=401, detail="invalid or missing API token")

    return require_token


def make_authenticator(bootstrap_token: str, principals: PrincipalStore | None):
    """The router-wide guard: authenticate (401), authorize by route (403), bind actors (403).

    The resolved principal is left on `request.state.principal` for handlers that need it.
    """

    async def authenticate(request: Request, authorization: str | None = Header(default=None)):
        credential = None
        if authorization is not None and authorization.startswith("Bearer "):
            credential = authorization[len("Bearer "):]
        principal = identify(credential, bootstrap_token, principals)
        if principal is None:
            raise HTTPException(status_code=401, detail="invalid or missing API token")

        # The route TEMPLATE, never the concrete URL: "/trust-profiles/a1" would match no admin
        # entry and silently downgrade. No template at all -> demand admin (fail closed).
        template = getattr(request.scope.get("route"), "path", None)
        needed = required_role(request.method, template) if template else "admin"
        if not principal.allows(needed):
            raise HTTPException(
                status_code=403, detail=f"role {principal.role!r} may not do this; needs {needed!r}"
            )

        if not principal.bootstrap and request.method not in ("GET", "HEAD"):
            await _bind_actor(request, principal)
        request.state.principal = principal
        return principal

    return authenticate


async def _bind_actor(request: Request, principal: Principal) -> None:
    # Deliberately NOT gated on Content-Type. Whether FastAPI parses a header-less body as JSON has
    # varied across versions (the pinned one refuses it with a 422); checking whatever parses as a
    # JSON object keeps the binding independent of that parser detail.
    try:
        body = json.loads(await request.body() or b"{}")
    except (ValueError, UnicodeDecodeError):
        return  # malformed JSON: the route's own validation answers it with a 422
    if not isinstance(body, dict):
        return
    for field in ACTOR_FIELDS:
        claimed = body.get(field)
        if claimed is not None and claimed != principal.name:
            raise HTTPException(
                status_code=403,
                detail=f"{field} must be the authenticated principal ({principal.name!r})",
            )
