"""Feature 7 — Explainable Reason-Code Emitter.

Assembles the DecisionEnvelope: ISO-20022-style external reason codes, a plain
-language rationale, the SR 11-7 model provenance (every ML contribution with
its version), the liability split, and the pinned ruleset/world-snapshot hashes
for replay. Signing + hash-chaining into the append-only ledger is done by the
ledger store (see ``ledger/store.py``).
"""

from __future__ import annotations

import uuid

from ..models import DecisionEnvelope, Verdict
from .context import DecisionContext

STAGE = "f7_reasoncodes"

_VERDICT_LEAD = {
    Verdict.ALLOW: "Transaction permitted.",
    Verdict.STEP_UP: "Additional authorization required before settlement.",
    Verdict.BLOCK: "Transaction blocked before settlement.",
}


def humanize(ctx: DecisionContext, verdict: Verdict) -> str:
    lead = _VERDICT_LEAD[verdict]
    if not ctx.signals:
        return f"{lead} No control findings; passed all pipeline stages."
    parts = [lead]
    for s in ctx.signals:
        tag = "BLOCKING" if s.hard_block else s.severity.value
        parts.append(f"[{tag}] {s.code}: {s.detail}")
    if ctx.stepup:
        parts.append(
            f"Step-up: {ctx.stepup.required_m}-of-{len(ctx.stepup.eligible_approvers)} "
            f"quorum bound to cart {ctx.stepup.cart_hash[:12]}…"
        )
    parts.append(f"Risk score: {ctx.risk_score:.1f}/100.")
    return " ".join(parts)


def build_envelope(ctx: DecisionContext, verdict: Verdict) -> DecisionEnvelope:
    # De-duplicate reason codes preserving order.
    seen: set[str] = set()
    reason_codes = []
    for s in ctx.signals:
        if s.code not in seen:
            seen.add(s.code)
            reason_codes.append(s.code)

    return DecisionEnvelope(
        decision_id=str(uuid.uuid4()),
        mandate_id=ctx.mandate_id,
        verdict=verdict,
        reason_codes=reason_codes,
        rationale=humanize(ctx, verdict),
        signals=list(ctx.signals),
        risk_score=round(ctx.risk_score, 2),
        model_provenance=dict(ctx.models_used),
        liability=ctx.liability,
        liability_basis=ctx.liability_basis,
        stepup=ctx.stepup,
        sar_draft=ctx.sar_draft,
        ruleset_version=ctx.ruleset_version,
        world_snapshot_hash=ctx.world_snapshot_hash,
        # prev_envelope_hash / this_hash / signature are set by the ledger.
    )
