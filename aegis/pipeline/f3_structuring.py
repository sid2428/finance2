"""Feature 3 — Structuring & Velocity Analyzer (financial-crime detection at
the intent layer).

Detects deliberate slicing of a large payment into sub-threshold transfers
(31 U.S.C. §5324) *before the first transfer settles*, plus per-agent velocity
caps. Structuring is a graduated signal (raises risk + drafts a SAR); a hard
velocity-cap breach is a fail-closed block.
"""

from __future__ import annotations

from ..config import (
    CTR_THRESHOLD_USD,
    STRUCTURING_MIN_CLUSTER,
    STRUCTURING_WINDOW_SECONDS,
    VELOCITY_MAX_COUNT_24H,
    VELOCITY_MAX_VALUE_24H_USD,
)
from ..models import Severity, Signal
from ..state import VelocityStore, default_velocity_store
from .context import DecisionContext

STAGE = "f3_structuring"


def _beneficiary_ref(ctx: DecisionContext) -> str:
    b = ctx.bundle.cart.beneficiary
    if b and (b.account_ref or b.wallet or b.legal_name):
        return b.account_ref or b.wallet or b.legal_name  # type: ignore[return-value]
    return ctx.bundle.cart.merchant_did


def run(ctx: DecisionContext, store: VelocityStore | None = None) -> None:
    store = store or default_velocity_store()
    agent = ctx.initiator
    beneficiary = _beneficiary_ref(ctx)
    amount = ctx.bundle.cart.total_usd
    now = ctx.now

    struct_key = f"struct:{agent}:{beneficiary}"
    vel_key = f"vel:{agent}"

    # Read the prior rolling window BEFORE recording this transfer, so the
    # exact window can be reconstructed for audit replay, then record.
    prior_struct = store.window(struct_key, now, STRUCTURING_WINDOW_SECONDS)
    prior_vel = store.window(vel_key, now, STRUCTURING_WINDOW_SECONDS)
    ctx.velocity_snapshot = {
        struct_key: [list(e) for e in prior_struct],
        vel_key: [list(e) for e in prior_vel],
    }
    store.record(struct_key, now, amount)
    store.record(vel_key, now, amount)

    struct_window = prior_struct + [(now, amount)]
    vel_window = prior_vel + [(now, amount)]

    # --- Velocity caps (hard, fail-closed) ---
    vel_count = len(vel_window)
    vel_value = sum(a for _, a in vel_window)
    if vel_count > VELOCITY_MAX_COUNT_24H or vel_value > VELOCITY_MAX_VALUE_24H_USD:
        ctx.add_signal(Signal(
            code="AGENT.AML.VELOCITY_EXCEEDED",
            detail=(
                f"Agent {agent}: {vel_count} transfers / {vel_value:.2f} USD in 24h "
                f"exceeds caps ({VELOCITY_MAX_COUNT_24H} / {VELOCITY_MAX_VALUE_24H_USD:.0f})"
            ),
            severity=Severity.HIGH,
            hard_block=True,
            stage=STAGE,
        ))
        return

    # --- Structuring cluster (graduated + SAR draft) ---
    amounts = [a for _, a in struct_window]
    total = sum(amounts)
    each_below = all(a < CTR_THRESHOLD_USD for a in amounts)
    if (
        len(amounts) >= STRUCTURING_MIN_CLUSTER
        and each_below
        and total >= CTR_THRESHOLD_USD
    ):
        detail = (
            f"{len(amounts)} sub-threshold transfers to {beneficiary} summing "
            f"{total:.2f} USD within 24h (each < {CTR_THRESHOLD_USD:.0f} CTR threshold)"
        )
        ctx.add_signal(Signal(
            code="AGENT.AML.STRUCTURING_SUSPECTED",
            detail=detail,
            severity=Severity.HIGH,
            hard_block=False,
            risk_delta=45.0,
            stage=STAGE,
            recommend="FILE_SAR",
        ))
        ctx.sar_draft = _draft_sar(ctx, agent, beneficiary, amounts, total)


def _draft_sar(ctx, agent, beneficiary, amounts, total) -> dict:
    """Auto-draft a Suspicious Activity Report payload for compliance review."""
    return {
        "report_type": "SAR",
        "filing_institution": "AEGIS Control Plane",
        "subject_agent_did": agent,
        "beneficiary": beneficiary,
        "activity": "Suspected structuring (31 U.S.C. §5324)",
        "transaction_count": len(amounts),
        "aggregate_usd": round(total, 2),
        "individual_amounts_usd": [round(a, 2) for a in amounts],
        "window_hours": STRUCTURING_WINDOW_SECONDS / 3600,
        "mandate_id": ctx.mandate_id,
        "narrative": (
            f"Agent {agent} initiated {len(amounts)} transfers to {beneficiary}, "
            f"each below the {CTR_THRESHOLD_USD:.0f} USD CTR threshold, aggregating "
            f"{total:.2f} USD within a {STRUCTURING_WINDOW_SECONDS/3600:.0f}h window. "
            "Pattern is consistent with deliberate structuring to evade reporting."
        ),
        "status": "DRAFT_PENDING_REVIEW",
    }
