"""Feature 5 — Dynamic Risk Scorer + Cryptographic Step-Up Quorum.

Computes the final risk score (accumulated graduated risk + bounded ML score)
and maps it to a band:

    score < LOW_BAND      -> ALLOW      (frictionless, risk-based auth)
    LOW_BAND..STEPUP_BAND -> STEP_UP    (m-of-n quorum, four-eyes)
    >= STEPUP_BAND        -> BLOCK

Human-Not-Present (AP2 v0.2 autonomous mode) exercises a visibly different
policy path: unbounded delegated authority is refused outright, a baseline
risk contribution is added, and both bands tighten (see ``config.py``). An
AEGIS STEP_UP on an HNP flow is the compliance-plane analogue of AP2's
``unresolved_constraint`` fallback — it brings a human back into the loop.

The step-up challenge is bound to the exact cart hash (PSD2 SCA dynamic
linking) so an approval cannot be replayed for a different transaction, and the
initiator (maker) is structurally excluded from the eligible approvers
(checker) — segregation of duties.
"""

from __future__ import annotations

import uuid

from ..config import (
    HNP_BASELINE_RISK,
    HNP_RISK_LOW_BAND,
    HNP_RISK_STEPUP_BAND,
    RISK_LOW_BAND,
    RISK_STEPUP_BAND,
)
from ..crypto import hash_object, verify
from ..models import Severity, Signal, StepUpChallenge, Verdict
from ..ml import RiskModel, default_risk_model
from .context import DecisionContext

STAGE = "f5_risk_stepup"


def cart_hash(ctx: DecisionContext) -> str:
    return hash_object(ctx.bundle.cart.model_dump(mode="json", exclude={"proof"}))


def required_quorum(score: float, low_band: float = RISK_LOW_BAND,
                    stepup_band: float = RISK_STEPUP_BAND) -> int:
    """Higher risk demands a larger quorum (bands tighten under HNP)."""
    midpoint = (low_band + stepup_band) / 2
    return 3 if score >= midpoint else 2


def run(ctx: DecisionContext, risk_model: RiskModel | None = None) -> Verdict:
    risk_model = risk_model or default_risk_model()
    ctx.record_model(risk_model.name, risk_model.version)

    hnp = not ctx.bundle.payment.human_present
    if hnp:
        # Autonomous spend requires explicit, user-approved bounded authority.
        if ctx.bundle.intent.max_value_usd is None:
            ctx.add_signal(Signal(
                code="AGENT.HNP.UNBOUNDED_AUTHORITY",
                detail=(
                    "Human-Not-Present payment under an intent with no "
                    "max_value_usd — unbounded delegated authority is refused"
                ),
                severity=Severity.HIGH,
                hard_block=True,
                stage=STAGE,
            ))
            return Verdict.BLOCK
        ctx.add_signal(Signal(
            code="AGENT.HNP.UNATTENDED",
            detail=(
                "Human-Not-Present mandate: baseline risk "
                f"+{HNP_BASELINE_RISK:.0f}, tightened bands "
                f"({HNP_RISK_LOW_BAND:.0f}/{HNP_RISK_STEPUP_BAND:.0f} vs "
                f"{RISK_LOW_BAND:.0f}/{RISK_STEPUP_BAND:.0f} attended)"
            ),
            severity=Severity.LOW,
            risk_delta=HNP_BASELINE_RISK,
            stage=STAGE,
        ))
    low_band = HNP_RISK_LOW_BAND if hnp else RISK_LOW_BAND
    stepup_band = HNP_RISK_STEPUP_BAND if hnp else RISK_STEPUP_BAND

    # ML score only ADDS to accumulated graduated risk — never subtracts.
    model_score = risk_model.score(ctx)
    ctx.risk_score = min(100.0, ctx.risk_score + model_score)

    if ctx.risk_score < low_band:
        return Verdict.ALLOW
    if ctx.risk_score >= stepup_band:
        return Verdict.BLOCK

    # STEP_UP: build a quorum challenge bound to this cart.
    initiator = ctx.initiator
    eligible = [g for g in ctx.bundle.guardians if g != initiator]  # four-eyes
    m = required_quorum(ctx.risk_score, low_band, stepup_band)
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
