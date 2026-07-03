"""Dynamic risk scorer (Feature 5 input).

Blends deterministic features (amount, corridor risk, counterparty novelty,
velocity pressure) with a bounded ML-style contribution. Output is 0..100.

Crucially, the score is *added to* the risk already accumulated from graduated
signals; it never subtracts and never touches hard blocks (the orchestrator has
already short-circuited those). This keeps the model SR 11-7 governable.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

from ..config import RESTRICTED_JURISDICTIONS

if TYPE_CHECKING:  # avoid ml -> pipeline -> ml import cycle at runtime
    from ..pipeline.context import DecisionContext

MODEL_NAME = "aegis-risk-scorer"
MODEL_VERSION = "logistic-blend-v1"

_HIGHER_RISK_CORRIDORS = {"RU", "BY", "VE", "MM"}


class RiskModel:
    name = MODEL_NAME
    version = MODEL_VERSION

    def features(self, ctx: DecisionContext) -> dict[str, float]:
        cart = ctx.bundle.cart
        amount = cart.total_usd

        # Amount pressure: log-scaled, saturating.
        amount_feat = min(1.0, math.log10(max(amount, 1.0)) / 6.0)

        corridor_feat = 0.0
        for j in ctx.bundle.touched_jurisdictions:
            if j.iso in RESTRICTED_JURISDICTIONS:
                corridor_feat = 1.0
            elif j.iso in _HIGHER_RISK_CORRIDORS:
                corridor_feat = max(corridor_feat, 0.6)

        # Counterparty novelty: no prior relationship signal in the intent's
        # allowed-merchants set → treat as novel.
        novel = 0.0
        if cart.merchant_did not in ctx.bundle.intent.allowed_merchants:
            novel = 1.0

        # Not human-present raises risk (agent-initiated, unattended).
        unattended = 0.0 if ctx.bundle.payment.human_present else 1.0

        return {
            "amount": amount_feat,
            "corridor": corridor_feat,
            "novelty": novel,
            "unattended": unattended,
        }

    def score(self, ctx: DecisionContext) -> float:
        f = self.features(ctx)
        # Weighted logistic blend → 0..100.
        z = (
            -1.4
            + 2.2 * f["amount"]
            + 2.6 * f["corridor"]
            + 1.1 * f["novelty"]
            + 0.7 * f["unattended"]
        )
        prob = 1.0 / (1.0 + math.exp(-z))
        return round(prob * 100.0, 2)


_DEFAULT = RiskModel()


def default_risk_model() -> RiskModel:
    return _DEFAULT
