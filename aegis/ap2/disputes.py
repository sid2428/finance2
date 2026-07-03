"""Feature 6 — checkout_hash Dispute Reconciliation & Programmable Refund Engine.

AP2 hands us the join key (``checkout_hash``) to reconstruct the entire
authorized truth of a transaction. Given a checkout_hash, this engine reassembles
the Checkout <-> Payment <-> Receipt tuple and auto-adjudicates: was it inside
the signed refund window? did the settled cart match the WYSIWYS anchor the user
approved? was there a valid receipt? The evidence package builds itself from
cryptographic artifacts — automated chargeback representment, not screenshots.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional

from .scope_ledger import MandateReceipt
from .wysiwys import verify_wysiwys


@dataclass
class CheckoutRecord:
    checkout_hash: str
    requires_refundability: bool
    refund_period_days: int
    shown_digest: str            # WYSIWYS anchor the user approved
    merchant_name: str


@dataclass
class PaymentRecord:
    mandate_id: str
    closed_payload: dict         # the verified closed-mandate payload


@dataclass
class DisputeClaim:
    type: Literal["REFUND_REQUEST", "NOT_AUTHORIZED"]
    filed_at: int                # epoch seconds


@dataclass
class Adjudication:
    outcome: Literal["GRANT", "DENY", "ESCALATE"]
    rationale: str
    evidence: list = field(default_factory=list)   # list[(party_favored, note)]

    @staticmethod
    def grant(rationale, evidence): return Adjudication("GRANT", rationale, evidence)

    @staticmethod
    def deny(rationale, evidence): return Adjudication("DENY", rationale, evidence)

    @staticmethod
    def escalate(rationale): return Adjudication("ESCALATE", rationale, [])


class DisputeStore:
    """Indexes the cryptographic artifacts by ``checkout_hash`` (the join key)."""

    def __init__(self, verifier_pub: bytes):
        self._verifier_pub = verifier_pub
        self._checkouts: dict[str, CheckoutRecord] = {}
        self._payments: dict[str, PaymentRecord] = {}     # keyed by checkout_hash
        self._receipts: dict[str, MandateReceipt] = {}    # keyed by mandate_id

    def record(self, checkout: CheckoutRecord, payment: PaymentRecord,
               receipt: Optional[MandateReceipt]) -> None:
        self._checkouts[checkout.checkout_hash] = checkout
        self._payments[checkout.checkout_hash] = payment
        if receipt is not None:
            self._receipts[payment.mandate_id] = receipt

    def checkout_by_hash(self, h): return self._checkouts.get(h)
    def payment_by_checkout_hash(self, h): return self._payments.get(h)
    def receipt_for(self, mandate_id): return self._receipts.get(mandate_id)

    @property
    def verifier_pub(self) -> bytes:
        return self._verifier_pub


def adjudicate_dispute(checkout_hash: str, claim: DisputeClaim,
                       store: DisputeStore) -> Adjudication:
    checkout = store.checkout_by_hash(checkout_hash)
    payment = store.payment_by_checkout_hash(checkout_hash)
    receipt = store.receipt_for(payment.mandate_id) if payment else None
    if not (checkout and payment and receipt):
        return Adjudication.escalate("incomplete mandate chain — manual review")

    evidence: list = []

    if claim.type == "REFUND_REQUEST":
        if not checkout.requires_refundability:
            evidence.append(("merchant", "cart was signed non-refundable"))
            return Adjudication.deny("cart signed non-refundable", evidence)
        days_elapsed = (claim.filed_at - receipt.issued_at) / 86400.0
        if days_elapsed > checkout.refund_period_days:
            evidence.append(("merchant", f"filed {days_elapsed:.1f}d > {checkout.refund_period_days}d window"))
            return Adjudication.deny("outside signed refund window", evidence)
        evidence.append(("consumer", "within signed refund window; refundable cart"))
        return Adjudication.grant("within refund window; refundable cart", evidence)

    if claim.type == "NOT_AUTHORIZED":
        if not receipt.verify(store.verifier_pub) or receipt.result != "success":
            evidence.append(("consumer", "no valid authorization receipt"))
            return Adjudication.grant("no valid authorization receipt", evidence)
        wy = verify_wysiwys(payment.closed_payload, checkout.shown_digest)
        if not wy.ok:
            evidence.append(("consumer", "settled cart != approved cart (WYSIWYS drift)"))
            return Adjudication.grant("settled cart != approved cart", evidence)
        evidence.append(("merchant", "valid receipt + WYSIWYS match"))
        return Adjudication.deny("authorized & matches approved cart", evidence)

    return Adjudication.escalate(f"unknown claim type {claim.type}")
