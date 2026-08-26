"""TRST-05 — portable, longitudinal reputation: exportable across deployments, and quarantined on
arrival.

WHY EXPORT AT ALL. TRST-03 reputation is longitudinal — it is worth something precisely because it
accumulated over time. An agent moving between deployments, or a fleet rebuilt after an incident,
otherwise starts from the seed with its whole history discarded. Exporting lets that history travel.

WHY IMPORTED REPUTATION IS NEVER AUTHORITATIVE. An importable trust score that silently became the
local score would be a trust-laundering path BETWEEN deployments: stand up a permissive deployment,
farm a 0.99 there, export it, import it somewhere that matters. That is TRST-04's escalation with a
deployment boundary in place of a delegation edge, and TRST-04's answer applies unchanged — an
inherited claim is capped by what the receiver independently knows, never substituted for it.

So an import is stored as a CLAIM, attributed to the deployment that made it, and
`ReputationEngine.score` is not consulted for it. A caller that wants to act on a claim must decide
to trust that issuer, explicitly. This module gives them the evidence to make that decision — issuer,
signature, evidence counts, when it was exported — and does not make it for them.

CRYPTO-ECONOMICS ARE FENCED OUT (ADR-0007). The requirement is explicit that any stake/slashing
economics live ONLY in an optional backend and are NEVER required to run the control plane. So this
module ships a `ReputationBackend` Protocol and no implementation of one: core exports and imports a
signed bundle over ordinary storage, a deployment that wires no backend loses nothing, and nothing
here imports a chain, a token, or a stake. A test asserts that absence, because "optional" decays
into "required" the moment one code path assumes it.

WHAT THE SIGNATURE PROVES, AND WHAT IT DOES NOT. It proves the bundle came from the holder of that
key and was not altered in transit. It does NOT make the score true: a deployment can honestly sign a
reputation it farmed dishonestly. Authentication of the issuer and trust in the issuer are different
questions, and conflating them is exactly how the laundering path opens.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from agentos_controlplane.audit import canonical_json

# Domain separation, like AUD-06's leaf/node prefixes and POL-12's vote domain: a reputation bundle
# signature must never verify as an audit record or a consensus vote, and vice versa.
REPUTATION_DOMAIN = b"agentos-guard/portable-reputation/v1\x00"

_MAX_AGENTS = 1000
_SCHEMA = 1

CLAIMED = "claimed"


@runtime_checkable
class ReputationBackend(Protocol):
    """The OPTIONAL, deployment-pluggable backend (ADR-0007).

    Deliberately a Protocol with no implementation in core. A deployment that wires none keeps every
    capability this module offers — export, import, inspect — because the bundle is ordinary signed
    JSON over ordinary storage. Any stake/slashing economics a deployment wants belong behind THIS
    seam and nowhere else; core must stay runnable, and testable, with the seam empty.
    """

    def publish(self, bundle: dict) -> str: ...

    def fetch(self, locator: str) -> dict: ...


@dataclass(frozen=True)
class ReputationClaim:
    """One imported agent reputation, and who claims it.

    `score` is the ISSUER's number. It is deliberately not called `trust`: local trust is what this
    deployment computed, and giving the two the same name is how one gets substituted for the other.
    """

    agent_id: str
    score: float
    issuer: str
    good: float
    bad: float
    signals: int
    exported_at: str
    status: str = CLAIMED
    signature_verified: bool = False

    def as_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "claimed_score": self.score,
            "issuer": self.issuer,
            "good": self.good,
            "bad": self.bad,
            "signals": self.signals,
            "exported_at": self.exported_at,
            "status": self.status,
            "signature_verified": self.signature_verified,
        }


@dataclass(frozen=True)
class ImportResult:
    """What an import produced, and — the load-bearing half — what it did NOT change."""

    claims: tuple[ReputationClaim, ...] = ()
    issuer: str | None = None
    signature_verified: bool = False
    rejected: str | None = None
    local_trust_modified: bool = False  # always False; asserted, not merely documented

    def as_dict(self) -> dict:
        return {
            "claims": [c.as_dict() for c in self.claims],
            "issuer": self.issuer,
            "signature_verified": self.signature_verified,
            "rejected": self.rejected,
            "local_trust_modified": self.local_trust_modified,
        }


def bundle_message(bundle: dict) -> bytes:
    """The exact bytes signed over a bundle: everything except the signature block itself.

    Reuses the audit `canonical_json` so a receiver reproduces them byte-identically without needing
    our serializer.
    """
    payload = {k: v for k, v in bundle.items() if k not in ("signature", "signing_key_id")}
    return REPUTATION_DOMAIN + canonical_json(payload)


class PortableReputation:
    """Exports local reputation as a signed bundle; imports a foreign one as a claim.

    `engine` is the TRST-03 `ReputationEngine` — reused rather than re-derived, so an exported number
    is the same number this deployment acts on. `signer` is the control-plane identity engine.
    """

    def __init__(self, engine, *, issuer: str, signer=None) -> None:
        if not (issuer or "").strip():
            # An unattributed bundle cannot be evaluated by a receiver: "should I trust this score"
            # is unanswerable without knowing who is asserting it.
            raise ValueError("issuer is required: an unattributed reputation bundle is unusable")
        self._engine = engine
        self._issuer = issuer.strip()
        self._signer = signer

    def export(self, agent_ids, *, now: float | None = None) -> dict:
        """A signed bundle of this deployment's reputation for `agent_ids`.

        Carries the EVIDENCE COUNTS alongside the score, not just the number. A receiver deciding
        whether to believe a 0.99 needs to know whether it rests on four signals or four thousand —
        the same reason TEST-07 refuses to ship a rate without its sample size.
        """
        ids = sorted({str(a) for a in agent_ids})[:_MAX_AGENTS]
        entries = []
        for agent_id in ids:
            breakdown = self._engine.breakdown(agent_id, now=now)
            entries.append(
                {
                    "agent_id": agent_id,
                    "score": round(float(breakdown.score), 6),
                    "good": round(float(breakdown.good), 6),
                    "bad": round(float(breakdown.bad), 6),
                    "signals": int(breakdown.signals),
                }
            )
        bundle = {
            "schema": _SCHEMA,
            "issuer": self._issuer,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "agents": entries,
            "note": (
                "These are the ISSUER's numbers. A signature proves this bundle came from the "
                "issuer unaltered; it does not make the scores true — a deployment can honestly "
                "sign a reputation it farmed dishonestly. Import treats these as CLAIMS."
            ),
        }
        if self._signer is not None:
            bundle["signature"] = self._signer.sign_record(bundle_message(bundle)).hex()
            bundle["signing_key_id"] = self._signer.public_key_id
        return bundle

    @staticmethod
    def import_bundle(bundle: dict, *, public_key_pem=None) -> ImportResult:
        """Read a foreign bundle into CLAIMS. Never touches local trust.

        Static on purpose: importing has no business holding a reference to the local engine, and a
        method that cannot reach local state cannot accidentally write it. That is the invariant this
        whole module exists to preserve, enforced by construction rather than by care.
        """
        try:
            schema = int(bundle["schema"])
            issuer = str(bundle["issuer"])
            exported_at = str(bundle.get("exported_at", ""))
            agents = list(bundle["agents"])
        except (KeyError, TypeError, ValueError):
            return ImportResult(rejected="the bundle is malformed")
        if schema != _SCHEMA:
            # Refused rather than best-effort parsed: a future schema may mean something different
            # by the same field name, and guessing is how a score changes meaning in transit.
            return ImportResult(rejected=f"unsupported bundle schema {schema}")

        verified = False
        if public_key_pem is not None:
            signature = bundle.get("signature")
            if signature is None:
                return ImportResult(
                    issuer=issuer, rejected="a key was supplied but the bundle is unsigned"
                )
            try:
                verified = _verify(public_key_pem, bytes.fromhex(str(signature)),
                                   bundle_message(bundle))
            except ValueError:
                return ImportResult(issuer=issuer, rejected="the signature is not valid hex")
            if not verified:
                return ImportResult(issuer=issuer, rejected="the signature does not verify")

        claims = []
        for entry in agents[:_MAX_AGENTS]:
            try:
                claims.append(
                    ReputationClaim(
                        agent_id=str(entry["agent_id"]),
                        score=float(entry["score"]),
                        issuer=issuer,
                        good=float(entry.get("good", 0.0)),
                        bad=float(entry.get("bad", 0.0)),
                        signals=int(entry.get("signals", 0)),
                        exported_at=exported_at,
                        signature_verified=verified,
                    )
                )
            except (KeyError, TypeError, ValueError):
                return ImportResult(issuer=issuer, rejected="an agent entry is malformed")
        return ImportResult(
            claims=tuple(claims),
            issuer=issuer,
            signature_verified=verified,
            local_trust_modified=False,
        )

    @staticmethod
    def bundle_digest(bundle: dict) -> str:
        """A stable id for a bundle, so a receiver can say which one they imported."""
        return hashlib.sha256(bundle_message(bundle)).hexdigest()


def _verify(public_key_pem, signature: bytes, message: bytes) -> bool:
    """Ed25519 verify over the REPUTATION domain only.

    Not routed through `audit.verify_record_signature`, which prepends the AUDIT domain: borrowing it
    would put reputation bundles and audit records in one signing domain with the same key often
    signing both — the collision domain separation exists to prevent. Same reasoning as POL-12's
    vote verifier.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    pem = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
    try:
        load_pem_public_key(pem).verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
