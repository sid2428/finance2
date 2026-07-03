"""Feature 5 — Dynamic Risk Scorer + Cryptographic Step-Up Quorum.

Computes the final risk score (accumulated graduated risk + bounded ML score)
and maps it to a band:

    score < LOW_BAND      -> ALLOW      (frictionless, risk-based auth)
    LOW_BAND..STEPUP_BAND -> STEP_UP    (m-of-n quorum, four-eyes)
    >= STEPUP_BAND        -> BLOCK

The step-up challenge is bound to the exact cart hash (PSD2 SCA dynamic
linking) so an approval cannot be replayed for a different transaction, and the
initiator (maker) is structurally excluded from the eligible approvers
(checker) — segregation of duties.
"""

from __future__ import annotations

import uuid

from ..config import RISK_LOW_BAND, RISK_STEPUP_BAND
from ..crypto import hash_object, verify
from ..models import StepUpChallenge, Verdict
from ..ml import RiskModel, default_risk_model
from .context import DecisionContext

STAGE = "f5_risk_stepup"


def cart_hash(ctx: DecisionContext) -> str:
    return hash_object(ctx.bundle.cart.model_dump(mode="json", exclude={"proof"}))


def required_quorum(score: float) -> int:
    """Higher risk demands a larger quorum."""
    midpoint = (RISK_LOW_BAND + RISK_STEPUP_BAND) / 2
    return 3 if score >= midpoint else 2


def run(ctx: DecisionContext, risk_model: RiskModel | None = None) -> Verdict:
    risk_model = risk_model or default_risk_model()
    ctx.record_model(risk_model.name, risk_model.version)

    # ML score only ADDS to accumulated graduated risk — never subtracts.
    model_score = risk_model.score(ctx)
    ctx.risk_score = min(100.0, ctx.risk_score + model_score)

    if ctx.risk_score < RISK_LOW_BAND:
        return Verdict.ALLOW
    if ctx.risk_score >= RISK_STEPUP_BAND:
        return Verdict.BLOCK

    # STEP_UP: build a quorum challenge bound to this cart.
    initiator = ctx.initiator
    eligible = [g for g in ctx.bundle.guardians if g != initiator]  # four-eyes
    m = required_quorum(ctx.risk_score)
    if len(eligible) < m:
        # Cannot assemble a lawful quorum → fail-closed to BLOCK.
        return Verdict.BLOCK

    challenge = StepUpChallenge(
        challenge_id=str(uuid.uuid4()),
        cart_hash=cart_hash(ctx),
        required_m=m,
        initiator=initiator,
        eligible_approvers=eligible,
    )
    ctx.stepup = challenge
    return Verdict.STEP_UP


def verify_quorum(
    challenge: StepUpChallenge,
    contributions: dict[str, str],
    pubkey_resolver,
) -> tuple[bool, int]:
    """Return (satisfied, remaining). Each contribution is an Ed25519 signature
    over the challenge cart_hash. Maker (initiator) signatures are rejected."""
    valid_signers: set[str] = set()
    payload = challenge.cart_hash.encode("utf-8")
    for signer_did, sig in contributions.items():
        if signer_did == challenge.initiator:
            continue  # maker != checker
        if signer_did not in challenge.eligible_approvers:
            continue
        pub = pubkey_resolver(signer_did)
        if pub is not None and verify(pub, payload, sig):
            valid_signers.add(signer_did)
    remaining = max(0, challenge.required_m - len(valid_signers))
    return (len(valid_signers) >= challenge.required_m, remaining)
