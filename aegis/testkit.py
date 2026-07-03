"""Helpers to construct and cryptographically sign AP2 mandate bundles for the
demo and the test suite. Not used in production — this is the "agent side"
that would sign mandates before submitting them to AEGIS.
"""

from __future__ import annotations

from datetime import timedelta

from .crypto import KeyRing
from .gateway.verify import sign_mandate
from .models import (
    Amount,
    CartMandate,
    IntentMandate,
    Jurisdiction,
    LineItem,
    MandateBundle,
    Party,
    PaymentInstrument,
    PaymentMandate,
    utcnow,
)


def ensure_key(keyring: KeyRing, did: str):
    if keyring.private_key(did) is None:
        keyring.create(did)


def build_bundle(
    keyring: KeyRing,
    *,
    mandate_id: str = "m-001",
    intent_text: str = "Buy one espresso machine under 200 GBP",
    max_value_usd: float | None = 260.0,
    total_usd: float = 250.0,
    line_items: list[LineItem] | None = None,
    buyer_did: str = "did:aegis:buyer-1",
    merchant_did: str = "did:aegis:merchant-1",
    merchant_legal_name: str = "Bright Beans Coffee Ltd",
    beneficiary: Party | None = None,
    initiator_did: str | None = None,
    touched: list[Jurisdiction] | None = None,
    processing_region: str = "US",
    guardians: list[str] | None = None,
    human_present: bool = False,
    allowed_merchants: list[str] | None = None,
    refund_period_days: int = 14,
    settlement_rail: str = "sim",
    originator: Party | None = None,
    sign: bool = True,
) -> MandateBundle:
    initiator_did = initiator_did or buyer_did
    for did in {buyer_did, merchant_did, initiator_did, *(guardians or [])}:
        ensure_key(keyring, did)

    if line_items is None:
        line_items = [
            LineItem(sku="ESP-100", description="espresso machine",
                     quantity=1, unit_price_usd=total_usd)
        ]
    if touched is None:
        touched = [
            Jurisdiction(iso="US", role="buyer"),
            Jurisdiction(iso="GB", role="merchant"),
            Jurisdiction(iso="US", role="rail"),
        ]
    if originator is None:
        originator = Party(legal_name="Alex Buyer", account_ref="acct-buyer-1")
    if beneficiary is None:
        beneficiary = Party(legal_name=merchant_legal_name, account_ref="acct-merch-1")

    intent = IntentMandate(
        mandate_id=f"{mandate_id}-intent",
        natural_language_description=intent_text,
        max_value_usd=max_value_usd,
        allowed_merchants=allowed_merchants if allowed_merchants is not None else [merchant_did],
        requires_refundability=True,
        intent_expiry=utcnow() + timedelta(hours=1),
        signer_did=buyer_did,
        originator=originator,
        beneficiary=beneficiary,
    )
    cart = CartMandate(
        mandate_id=f"{mandate_id}-cart",
        intent_ref=intent.mandate_id,
        line_items=line_items,
        total_usd=total_usd,
        refund_period_days=refund_period_days,
        merchant_did=merchant_did,
        merchant_legal_name=merchant_legal_name,
        beneficiary=beneficiary,
    )
    payment = PaymentMandate(
        mandate_id=mandate_id,
        cart_ref=cart.mandate_id,
        instrument=PaymentInstrument(kind="card", reference="tok-4242"),
        human_present=human_present,
        settlement_rail=settlement_rail,
        initiator_agent=initiator_did,
    )

    if sign:
        sign_mandate(intent, buyer_did, keyring.private_key(buyer_did))
        sign_mandate(cart, merchant_did, keyring.private_key(merchant_did))
        sign_mandate(payment, initiator_did, keyring.private_key(initiator_did))

    return MandateBundle(
        intent=intent,
        cart=cart,
        payment=payment,
        touched_jurisdictions=touched,
        processing_region=processing_region,
        guardians=guardians or [],
    )
