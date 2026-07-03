"""Feature 1 — Jurisdiction-Aware Mandate Firewall (conflict-of-laws resolver).

Resolves every touched jurisdiction (buyer / merchant / rail / data-residency)
and applies the *strictest binding* rule:

  * FATF Rec. 16 Travel Rule — threshold = min() across touched jurisdictions;
    at/above it, originator+beneficiary attestation must be present else BLOCK.
  * GDPR Art. 44-49 data residency — EU buyer PII must be processed in the EU
    enclave else BLOCK.
  * Rail eligibility — a corridor touching a restricted jurisdiction is BLOCK.

This is the Python analogue of ``policy/jurisdiction.rego``; the Rego bundle is
the production authority, this mirrors it for the standalone reference build.
"""

from __future__ import annotations

from ..config import RESTRICTED_JURISDICTIONS
from ..data import travel_rule_threshold
from ..models import Severity, Signal
from .context import DecisionContext

STAGE = "f1_jurisdiction"


def _applicable_threshold(ctx: DecisionContext) -> float:
    touched = ctx.bundle.touched_jurisdictions
    thresholds = [travel_rule_threshold(j.iso) for j in touched]
    # Strictest binding = the lowest threshold in play. No jurisdiction info is
    # itself a control gap → fall back to the global default.
    return min(thresholds) if thresholds else travel_rule_threshold("")


def _travel_rule_fields_present(ctx: DecisionContext) -> bool:
    orig = ctx.bundle.intent.originator
    benef = ctx.bundle.cart.beneficiary or ctx.bundle.intent.beneficiary
    return bool(orig.legal_name and orig.account_ref and benef and benef.legal_name)


def run(ctx: DecisionContext) -> None:
    amount_usd = ctx.bundle.cart.total_usd

    # --- Rail eligibility (restricted corridor) ---
    for j in ctx.bundle.touched_jurisdictions:
        if j.iso in RESTRICTED_JURISDICTIONS:
            ctx.add_signal(Signal(
                code="AGENT.JUR.RAIL_INELIGIBLE",
                detail=f"Corridor touches restricted jurisdiction {j.iso} ({j.role})",
                severity=Severity.HIGH,
                hard_block=True,
                stage=STAGE,
            ))
            return

    # --- FATF Travel Rule ---
    threshold = _applicable_threshold(ctx)
    if amount_usd >= threshold and not _travel_rule_fields_present(ctx):
        ctx.add_signal(Signal(
            code="AGENT.JUR.TRAVELRULE_MISSING",
            detail=(
                f"Transfer of {amount_usd:.2f} USD >= strictest threshold "
                f"{threshold:.2f}; originator/beneficiary attestation absent"
            ),
            severity=Severity.HIGH,
            hard_block=True,
            stage=STAGE,
        ))
        return

    # --- Data residency (GDPR Art. 44-49) ---
    buyer_eu = any(
        j.role == "buyer" and j.iso in _EU_ISO
        for j in ctx.bundle.touched_jurisdictions
    )
    if buyer_eu and ctx.bundle.processing_region != "EU":
        ctx.add_signal(Signal(
            code="AGENT.JUR.DATA_RESIDENCY",
            detail=(
                "EU-domiciled buyer PII processed outside EU enclave "
                f"(processing_region={ctx.bundle.processing_region})"
            ),
            severity=Severity.HIGH,
            hard_block=True,
            stage=STAGE,
        ))
        return


_EU_ISO = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
    "SI", "ES", "SE", "EU",
}
