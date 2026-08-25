"""POL-12 — Byzantine-tolerant quorum for `require_consensus`: signed votes, 3f+1 arithmetic,
equivocation detection, and a certificate a third party can verify offline.

WHAT THIS IS NOT. It is **not a replicated state machine** and not a consensus protocol. There is
**no leader**, **no view change**, no membership reconfiguration, and no liveness guarantee under
partition. It does not implement PBFT, Tendermint or HotStuff, and it makes no claim about behaviour
during a network split.

That paragraph is first because "BFT" names a family of replicated-state-machine protocols, and a
reader who sees "Byzantine fault tolerant" on a governance product will assume the strong reading.
Building a real PBFT here would have meant a network consensus layer, a multi-node test harness and
partition testing — none of which exist in this project (and D-14: no Docker on the development
machine). Something that compiled, passed single-process tests and had never survived a partition
would be worse than this, because the NAME would promise a guarantee nothing had verified.

WHAT IT IS: Byzantine-tolerant agreement ARITHMETIC over AUTHENTICATED, NON-REPUDIABLE votes. Four
properties, in the order they matter:

1. AUTHENTICATION BEFORE ARITHMETIC. A quorum rule that tolerates f malicious voters is worthless if
   a ballot can be forged, attributed to a voter who never cast it, or replayed from one action onto
   another. Every vote is signed over `(action_id, outcome, voter_id, approve)`. The OUTCOME is in
   there deliberately: without it, a voter's approval of a `sandbox` replays as approval of an
   `allow` — the voter agreed to containment, not to execution.

2. 3f+1 ARITHMETIC. Tolerating f Byzantine voters needs n >= 3f+1 and a quorum of 2f+1, so that any
   two quorums intersect in at least one honest voter — which is what stops two contradictory
   decisions from both looking legitimate. A certificate whose stated quorum is below that threshold
   is refused however many signatures it carries.

3. EQUIVOCATION. One voter, two different votes on one action, is the defining Byzantine behaviour.
   Last-write-wins silently lets one liar choose the outcome. Both votes are kept, the voter counts
   for NEITHER, and the equivocation is reported as a finding.

4. A CERTIFICATE. The signed votes themselves, so a third party re-derives the decision without
   trusting us. `verify_certificate` is a pure function for that reason — same spirit as AUD-06's
   inclusion proofs.

An honest note about the shipped default: POL-09's 2-of-3 tolerates one voter being DOWN, not one
voter LYING. `byzantine_tolerance(3)` is 0, and it returns 0 rather than rounding up.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from agentos_controlplane.audit import canonical_json

_log = logging.getLogger(__name__)

# Domain separation, like AUD-08's SIG_DOMAIN and AUD-06's leaf/node prefixes: a vote signature must
# never verify as anything else signed by the same key, and vice versa.
#
# This is why votes are NOT verified through `audit.verify_record_signature`, which would have been
# the obvious reuse: that function prepends the AUDIT domain, so borrowing it would put votes and
# audit records in one signing domain — and a voter's key is often the control plane's own. Sharing a
# domain is precisely the collision domain separation exists to prevent, so the verify below is
# deliberately its own four lines rather than a reuse that quietly weakens both.
VOTE_DOMAIN = b"agentos-guard/consensus-vote/v1\x00"


def _verify_vote(public_key_pem, signature: bytes, message: bytes) -> bool:
    """Ed25519 verify over the VOTE domain only. False on an invalid signature, never a raise."""
    pem = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
    try:
        load_pem_public_key(pem).verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def byzantine_tolerance(voters: int) -> int:
    """How many Byzantine voters a set of `voters` can tolerate: floor((n-1)/3).

    The classical bound. Below n=4 the answer is 0 — three voters tolerate no Byzantine member — and
    it is returned as 0 rather than rounded up, because POL-09's shipped default is 2-of-3 and an
    operator is entitled to know that configuration survives a voter being DOWN, not one LYING.
    """
    return max(0, (int(voters) - 1) // 3)


def required_quorum(voters: int) -> int:
    """The 2f+1 quorum for the f that `voters` can tolerate.

    At n=3 this is 1, which is honest arithmetic on a fault model of f=0 rather than a recommendation:
    a set that tolerates no Byzantine voter has no Byzantine-safe quorum to offer.
    """
    return 2 * byzantine_tolerance(voters) + 1


def vote_message(action_id: str, outcome: str, voter_id: str, approve: bool) -> bytes:
    """The exact bytes a voter signs.

    Reuses the audit `canonical_json` so a verifier reproduces them byte-identically, and includes the
    OUTCOME as well as the action: a signature over the action alone would let approval of a
    `sandbox` be replayed as approval of an `allow`.
    """
    return VOTE_DOMAIN + canonical_json(
        {"action_id": str(action_id), "approve": bool(approve),
         "outcome": str(outcome), "voter_id": str(voter_id)}
    )


@dataclass(frozen=True)
class Vote:
    """One voter's signed ballot on one action."""

    voter_id: str
    approve: bool
    signature: str  # hex

    def as_dict(self) -> dict:
        return {"voter_id": self.voter_id, "approve": self.approve, "signature": self.signature}


@dataclass(frozen=True)
class QuorumCertificate:
    """The votes, and what they were votes ON — everything a verifier needs and nothing else."""

    action_id: str
    outcome: str
    voters: tuple[str, ...]   # the full voter SET, so 3f+1 can be checked, not just who replied
    quorum: int
    votes: tuple[Vote, ...]

    def as_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "outcome": self.outcome,
            "voters": list(self.voters),
            "quorum": self.quorum,
            "votes": [v.as_dict() for v in self.votes],
        }


@dataclass(frozen=True)
class CertificateResult:
    """Why a certificate did or did not carry a quorum.

    `equivocators` is separate from a failure reason because a lying voter is a SECURITY event and not
    merely a vote that did not count — a caller may deny the action and still want to know who lied.
    """

    ok: bool
    approvals: int = 0
    equivocators: tuple[str, ...] = ()
    reason: str | None = None


def verify_certificate(certificate, public_keys: dict) -> CertificateResult:
    """Re-derive the decision from the certificate alone.

    PURE: no database, no I/O, no clock. An auditor holding the certificate and the voters' public
    keys can run this and needs nothing from us — which is the point of issuing a certificate rather
    than an assertion that quorum was reached.

    Malformed input is a False result with a reason, never a traceback: certificates come from
    outside, and a traceback is easy to mistake for "the check did not run".
    """
    try:
        cert = certificate if isinstance(certificate, dict) else certificate.as_dict()
        action_id = str(cert["action_id"])
        outcome = str(cert["outcome"])
        voters = [str(v) for v in cert["voters"]]
        quorum = int(cert["quorum"])
        raw_votes = list(cert["votes"])
    except (AttributeError, KeyError, TypeError, ValueError):
        return CertificateResult(False, reason="the certificate is malformed")

    if not voters:
        return CertificateResult(False, reason="the certificate names no voter set")
    # The stated quorum has to be Byzantine-safe for the set it claims. A certificate asserting that
    # 2 of 7 reached quorum is not Byzantine-tolerant however many valid signatures it carries, and
    # calling it "quorum reached" would be exactly the over-claim this module opens by refusing.
    minimum = required_quorum(len(voters))
    if quorum < minimum:
        return CertificateResult(
            False,
            reason=(
                f"stated quorum {quorum} is below the Byzantine-safe minimum {minimum} for "
                f"{len(voters)} voters (tolerates f={byzantine_tolerance(len(voters))})"
            ),
        )
    if quorum > len(voters):
        return CertificateResult(False, reason="stated quorum exceeds the voter set")

    # Authenticate first, then count. A vote that does not verify is not a vote — it is discarded
    # rather than counted as a "no", because attributing an opinion to a voter who did not express
    # one is its own falsehood.
    seen: dict[str, set[bool]] = {}
    for raw in raw_votes:
        try:
            vote = raw if isinstance(raw, dict) else raw.as_dict()
            voter_id, approve = str(vote["voter_id"]), bool(vote["approve"])
            signature = bytes.fromhex(str(vote["signature"]))
        except (AttributeError, KeyError, TypeError, ValueError):
            return CertificateResult(False, reason="a vote in the certificate is malformed")
        if voter_id not in voters:
            return CertificateResult(
                False, reason=f"vote from {voter_id!r}, who is not in the voter set"
            )
        key = public_keys.get(voter_id)
        if key is None:
            return CertificateResult(
                False, reason=f"no public key supplied for voter {voter_id!r}"
            )
        message = vote_message(action_id, outcome, voter_id, approve)
        if not _verify_vote(key, signature, message):
            # Covers forgery AND replay: the message binds the action and the outcome, so a genuine
            # signature from another action or another outcome does not verify here.
            return CertificateResult(
                False, reason=f"signature from voter {voter_id!r} does not verify"
            )
        seen.setdefault(voter_id, set()).add(approve)

    equivocators = tuple(sorted(v for v, positions in seen.items() if len(positions) > 1))
    approvals = sum(
        1 for v, positions in seen.items() if v not in equivocators and positions == {True}
    )
    if approvals < quorum:
        return CertificateResult(
            False,
            approvals=approvals,
            equivocators=equivocators,
            reason=f"{approvals} approvals is short of the stated quorum {quorum}",
        )
    return CertificateResult(True, approvals=approvals, equivocators=equivocators)


class ByzantineConsensusCoordinator:
    """POL-12 on the POL-09 seam.

    Satisfies the same `ConsensusCoordinator` protocol `governed_call` already consumes, so
    `require_consensus` gains Byzantine tolerance with NO change to the enforcement path — the Phase-9
    seam was built for exactly this substitution, and using it means there is still one outcome map.

    A voter that errors, times out or stays silent contributes no vote. That is Phase 9's rule
    unchanged, and the certificate now makes it distinguishable from a voter that voted `no`: silence
    is an absent ballot, not an opinion.
    """

    def __init__(self, voters: dict, public_keys: dict, audit, *, quorum: int | None = None) -> None:
        """`voters` maps voter_id -> an async callable (action, decision) -> Vote | None."""
        if not voters:
            raise ValueError("a coordinator with no voters would deny every action forever")
        minimum = required_quorum(len(voters))
        self._quorum = minimum if quorum is None else int(quorum)
        # Refused at CONSTRUCTION rather than per action, the posture POL-09 already takes toward an
        # impossible quorum: a configuration that can never be Byzantine-safe is an operator error to
        # surface at startup, not a decision to get wrong quietly on every action.
        if self._quorum < minimum:
            raise ValueError(
                f"quorum {self._quorum} is below the Byzantine-safe minimum {minimum} for "
                f"{len(voters)} voters; tolerating f={byzantine_tolerance(len(voters))} needs 2f+1"
            )
        if self._quorum > len(voters):
            raise ValueError(f"quorum {self._quorum} exceeds the {len(voters)} voters")
        missing = sorted(set(voters) - set(public_keys))
        if missing:
            # An unverifiable voter is worse than an absent one: it would sit in the voter set,
            # inflate n (and so the tolerance claim), and never contribute a countable vote.
            raise ValueError(f"no public key supplied for voter(s): {missing}")
        self._voters = dict(voters)
        self._public_keys = dict(public_keys)
        self._audit = audit

    async def reach_consensus(self, action, decision) -> bool:
        """Collect signed votes, certify, and return True only on a verified quorum."""
        import asyncio

        async def _ask(voter_id, fn):
            try:
                return await fn(action, decision)
            except Exception:
                # Isolated per voter, like POL-09: one unreachable voter must not deny by exception
                # when the remaining honest voters can still form a quorum.
                _log.warning("consensus voter %r failed", voter_id, exc_info=True)
                return None

        gathered = await asyncio.gather(
            *(_ask(vid, fn) for vid, fn in self._voters.items())
        )
        votes = tuple(v for v in gathered if isinstance(v, Vote))
        certificate = QuorumCertificate(
            action_id=str(action.id),
            outcome=decision.outcome.value,
            voters=tuple(sorted(self._voters)),
            quorum=self._quorum,
            votes=votes,
        )
        result = verify_certificate(certificate, self._public_keys)
        if result.equivocators:
            # A lying voter is a security event in its own right, recorded even though the action is
            # about to be denied: the operator needs to know WHICH voter, not just that quorum failed.
            await self._audit.append_event(
                "voter_equivocated",
                {"action_id": certificate.action_id, "voters": list(result.equivocators)},
            )
        await self._audit.append_event(
            "quorum_certified",
            {
                "action_id": certificate.action_id,
                "outcome": certificate.outcome,
                "quorum": certificate.quorum,
                "voters": len(certificate.voters),
                "approvals": result.approvals,
                "equivocators": len(result.equivocators),
                "reached": result.ok,
            },
        )
        self.last_certificate = certificate
        return result.ok
