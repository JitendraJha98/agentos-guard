"""EdDSA (Ed25519) identity engine — IDN-01 (issue) + IDN-02 (verify).

Source: 01-RESEARCH.md § Identity (the EdDSA issue/verify flow + the
algorithm-confusion security note); CONTEXT.md D-10.

Security invariant (do NOT regress): `verify` passes `algorithms=["EdDSA"]`
explicitly to `jwt.decode` and NEVER derives the algorithm from the token
header (algorithm-confusion — GHSA-ffqj-6fqr-9h24). The issuer is checked,
`sub` must equal the claimed agent_id, and the agent must be registered. Any
`jwt.InvalidTokenError` (tampered signature, wrong key, bad issuer, expired)
is terminal -> ok=False.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ISSUER = "agentos-guard"
ALGORITHM = "EdDSA"
# Bounded token validity (ASVS V3 partial; full rotation/revocation is Phase 7).
TOKEN_TTL = timedelta(hours=12)


@dataclass
class IdentityResult:
    """Outcome of stage-1 identity verification (consumed by the pipeline)."""

    ok: bool
    detail: str = ""
    trust_score: float = 0.0


class IdentityEngine:
    """Issues and verifies EdDSA JWTs against a single control-plane keypair.

    The registry-lookup seam (`is_registered`, `load_trust`) is injected so the
    engine stays decoupled from the persistence layer — the registry wires its
    own bound methods in.
    """

    def __init__(
        self,
        *,
        is_registered: Callable[[str], bool],
        load_trust: Callable[[str], float],
        private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self._is_registered = is_registered
        self._load_trust = load_trust
        # Generate the signing keypair once and hold it in the control plane.
        priv = private_key or Ed25519PrivateKey.generate()
        self._priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self._pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def public_key_pem(self) -> str:
        return self._pub_pem.decode("utf-8")

    def issue_token(self, agent_id: str) -> str:
        """IDN-01 — issue a signed EdDSA JWT carrying the agent_id as `sub`."""
        now = datetime.now(timezone.utc)
        claims = {
            "sub": agent_id,
            "iss": ISSUER,
            "iat": now,
            "exp": now + TOKEN_TTL,
        }
        return jwt.encode(claims, self._priv_pem, algorithm=ALGORITHM)

    def verify(self, token: str | None, claimed_agent_id: str) -> IdentityResult:
        """IDN-02 — verify signature + issuer + sub + registration.

        Forged/tampered/wrong-key/unregistered -> ok=False (terminal deny).
        """
        if not token:
            return IdentityResult(ok=False, detail="missing identity token")
        try:
            # Explicit algorithm allowlist — never header-derived (GHSA-ffqj-6fqr-9h24).
            claims = jwt.decode(
                token,
                self._pub_pem,
                algorithms=[ALGORITHM],
                issuer=ISSUER,
            )
        except jwt.InvalidTokenError as exc:
            return IdentityResult(ok=False, detail=f"invalid token: {type(exc).__name__}")

        sub = claims.get("sub")
        if sub != claimed_agent_id:
            return IdentityResult(ok=False, detail="sub does not match claimed agent_id")
        if not self._is_registered(sub):
            return IdentityResult(ok=False, detail="unknown/unregistered agent")
        return IdentityResult(ok=True, trust_score=self._load_trust(sub))
