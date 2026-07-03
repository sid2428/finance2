"""Features 5 & 6 — WYSIWYS oracle and checkout_hash dispute reconciliation."""

from __future__ import annotations

from aegis.crypto import generate_keypair
from aegis.ap2.disputes import (
    CheckoutRecord,
    DisputeClaim,
    DisputeStore,
    PaymentRecord,
    adjudicate_dispute,
)
from aegis.ap2.scope_ledger import MandateReceipt
from aegis.ap2.wysiwys import bind_shown_confirmation, verify_wysiwys

SHOWN = {
    "amount": {"currency": "USD", "value_usd": 150.0},
    "merchant_name": "Rabbit Co",
    "line_items": [{"title": "rabbit", "quantity": 1, "price": 150.0}],
}
CLOSED_OK = {
    "payment_amount": {"currency": "USD", "value_usd": 150.0},
    "payee": {"name": "Rabbit Co"},
    "line_items": [{"title": "rabbit", "quantity": 1, "price": 150.0}],
}


def test_wysiwys_matches_approved_cart():
    assert verify_wysiwys(CLOSED_OK, bind_shown_confirmation(SHOWN)).ok


def test_wysiwys_detects_amount_inflation():
    digest = bind_shown_confirmation(SHOWN)
    inflated = {**CLOSED_OK, "payment_amount": {"currency": "USD", "value_usd": 1500.0}}
    r = verify_wysiwys(inflated, digest)
    assert not r.ok and r.code == "AGENT.WYSIWYS.DRIFT"


def test_wysiwys_detects_payee_swap():
    digest = bind_shown_confirmation(SHOWN)
    swapped = {**CLOSED_OK, "payee": {"name": "Attacker LLC"}}
    assert not verify_wysiwys(swapped, digest).ok


def _store():
    vk, vpub = generate_keypair()
    store = DisputeStore(vpub)
    return store, vk, vpub


def test_refund_within_window_granted():
    store, vk, _ = _store()
    digest = bind_shown_confirmation(SHOWN)
    co = CheckoutRecord("chash", requires_refundability=True, refund_period_days=30,
                        shown_digest=digest, merchant_name="Rabbit Co")
    rc = MandateReceipt.issue(vk, reference="h", result="success", amount_usd=150.0,
                              issued_at=0, mandate_id="pmid")
    store.record(co, PaymentRecord("pmid", CLOSED_OK), rc)
    adj = adjudicate_dispute("chash", DisputeClaim("REFUND_REQUEST", 86400), store)
    assert adj.outcome == "GRANT"


def test_refund_outside_window_denied():
    store, vk, _ = _store()
    co = CheckoutRecord("chash", requires_refundability=True, refund_period_days=30,
                        shown_digest=bind_shown_confirmation(SHOWN), merchant_name="Rabbit Co")
    rc = MandateReceipt.issue(vk, reference="h", result="success", amount_usd=150.0,
                              issued_at=0, mandate_id="pmid")
    store.record(co, PaymentRecord("pmid", CLOSED_OK), rc)
    adj = adjudicate_dispute("chash", DisputeClaim("REFUND_REQUEST", 40 * 86400), store)
    assert adj.outcome == "DENY"


def test_not_authorized_denied_when_receipt_and_wysiwys_match():
    store, vk, _ = _store()
    co = CheckoutRecord("chash", requires_refundability=True, refund_period_days=30,
                        shown_digest=bind_shown_confirmation(SHOWN), merchant_name="Rabbit Co")
    rc = MandateReceipt.issue(vk, reference="h", result="success", amount_usd=150.0,
                              issued_at=0, mandate_id="pmid")
    store.record(co, PaymentRecord("pmid", CLOSED_OK), rc)
    adj = adjudicate_dispute("chash", DisputeClaim("NOT_AUTHORIZED", 0), store)
    assert adj.outcome == "DENY"


def test_not_authorized_granted_on_wysiwys_drift():
    store, vk, _ = _store()
    digest = bind_shown_confirmation(SHOWN)
    settled = {**CLOSED_OK, "payment_amount": {"currency": "USD", "value_usd": 1500.0}}
    co = CheckoutRecord("chash", requires_refundability=True, refund_period_days=30,
                        shown_digest=digest, merchant_name="Rabbit Co")
    rc = MandateReceipt.issue(vk, reference="h", result="success", amount_usd=1500.0,
                              issued_at=0, mandate_id="pmid")
    store.record(co, PaymentRecord("pmid", settled), rc)
    adj = adjudicate_dispute("chash", DisputeClaim("NOT_AUTHORIZED", 0), store)
    assert adj.outcome == "GRANT"     # settled cart != approved cart


def test_incomplete_chain_escalates():
    store, _, _ = _store()
    adj = adjudicate_dispute("missing", DisputeClaim("REFUND_REQUEST", 0), store)
    assert adj.outcome == "ESCALATE"
