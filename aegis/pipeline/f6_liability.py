"""Feature 6 — Liability Attribution Engine ("who pays when it breaks").

Resolves liability apportionment across user / agent-developer / merchant / PSP
at authorization time, modeled on the EMV liability shift (the least-secure
party — whoever failed to meet the security bar — carries the loss), with a
Reg E / Reg Z consumer-protection floor capping consumer exposure on
unauthorized transactions.

The resulting split is written into the signed decision envelope, so a later
dispute references a pre-agreed, cryptographically recorded apportionment.
"""

from __future__ import annotations

from ..config import REG_E_CONSUMER_CAP_RATIO
from .context import DecisionContext

STAGE = "f6_liability"

_PARTIES = ("user", "agent_developer", "merchant", "psp")


def _normalize(weights: dict[str, float]) -> dict[str, float]:
    total = sum(weights.values())
    if total <= 0:
        # No control failed → PSP (the operator of the rail) holds residual
        # baseline liability, as in a fully-compliant EMV chargeback.
        return {"user": 0.0, "agent_developer": 0.0, "merchant": 0.0, "psp": 1.0}
    return {k: round(v / total, 4) for k, v in weights.items()}


def _redistribute(weights: dict[str, float], overflow: float, to: list[str]) -> dict[str, float]:
    if overflow <= 0 or not to:
        return weights
    share = overflow / len(to)
    for p in to:
        weights[p] = weights.get(p, 0.0) + share
    return weights


def apportion(ctx: DecisionContext, is_unauthorized: bool = False) -> tuple[dict[str, float], str]:
    c = ctx.controls
    weights = {p: 0.0 for p in _PARTIES}

    # EMV-style: each unmet control shifts weight to the responsible party.
    if not c.merchant_verified_payment_challenge:
        weights["merchant"] += 0.6
    if not c.user_completed_required_stepup:
        weights["user"] += 0.3
    if not c.agent_sdk_pinned_intent_constraints:
        weights["agent_developer"] += 0.4
    if not c.psp_ran_sanctions_screen:
        weights["psp"] += 0.5

    weights = _normalize(weights)

    # Reg E / Reg Z consumer floor on unauthorized transactions.
    if is_unauthorized and weights["user"] > REG_E_CONSUMER_CAP_RATIO:
        overflow = weights["user"] - REG_E_CONSUMER_CAP_RATIO
        weights["user"] = REG_E_CONSUMER_CAP_RATIO
        weights = _redistribute(weights, overflow, ["merchant", "psp", "agent_developer"])
        weights = {k: round(v, 4) for k, v in weights.items()}
        basis = "EMV_SHIFT+REG_E_FLOOR"
    else:
        basis = "EMV_SHIFT"

    return weights, basis


def run(ctx: DecisionContext) -> None:
    # A mandate carrying an intent-drift/injection finding is treated as
    # potentially unauthorized for consumer-floor purposes.
    unauthorized = any(
        s.code == "AGENT.SEC.INTENT_DRIFT" for s in ctx.signals
    )
    weights, basis = apportion(ctx, is_unauthorized=unauthorized)
    ctx.liability = weights
    ctx.liability_basis = basis
