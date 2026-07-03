"""Feature 3 — scope ledger (double-spend / receipt-driven scope reduction)."""

from __future__ import annotations

import pytest

from aegis.crypto import generate_keypair
from aegis.ap2.scope_ledger import (
    DoubleSpend,
    MandateReceipt,
    ReceiptInvalid,
    ScopeExceeded,
    ScopeLedger,
)


@pytest.fixture()
def ledger():
    vk, vpub = generate_keypair()
    return ScopeLedger(vpub), vk


def test_overlapping_reservation_is_double_spend(ledger):
    led, _ = ledger
    scope = led.open_scope("open-1", count=3, value_usd=1000.0)
    led.reserve(scope, "hashA", 200.0)
    with pytest.raises(DoubleSpend):
        led.reserve(scope, "hashB", 200.0)


def test_receipt_reduces_scope_monotonically(ledger):
    led, vk = ledger
    scope = led.open_scope("open-1", count=3, value_usd=1000.0)
    led.reserve(scope, "hashA", 200.0)
    rc = MandateReceipt.issue(vk, reference="hashA", result="success",
                              amount_usd=200.0, issued_at=1, mandate_id="open-1")
    led.apply_receipt(scope, rc)
    assert scope.remaining_value_usd == 800.0
    assert scope.remaining_count == 2
    assert "hashA" in scope.consumed_hashes


def test_settled_hash_cannot_be_reused(ledger):
    led, vk = ledger
    scope = led.open_scope("open-1", count=3, value_usd=1000.0)
    led.reserve(scope, "hashA", 200.0)
    led.apply_receipt(scope, MandateReceipt.issue(
        vk, reference="hashA", result="success", amount_usd=200.0, issued_at=1, mandate_id="o"))
    with pytest.raises(DoubleSpend):
        led.reserve(scope, "hashA", 200.0)


def test_error_receipt_releases_authority(ledger):
    led, vk = ledger
    scope = led.open_scope("open-1", count=3, value_usd=1000.0)
    led.reserve(scope, "hashA", 200.0)
    led.apply_receipt(scope, MandateReceipt.issue(
        vk, reference="hashA", result="error", amount_usd=200.0, issued_at=1, mandate_id="o"))
    assert scope.remaining_value_usd == 1000.0   # restored
    assert "hashA" not in scope.consumed_hashes
    led.reserve(scope, "hashB", 300.0)           # now free to reserve again


def test_scope_value_exceeded(ledger):
    led, _ = ledger
    scope = led.open_scope("open-1", count=3, value_usd=100.0)
    with pytest.raises(ScopeExceeded):
        led.reserve(scope, "hashA", 200.0)


def test_tampered_receipt_rejected(ledger):
    led, vk = ledger
    scope = led.open_scope("open-1", count=3, value_usd=1000.0)
    led.reserve(scope, "hashA", 200.0)
    rc = MandateReceipt.issue(vk, reference="hashA", result="success",
                              amount_usd=200.0, issued_at=1, mandate_id="o")
    rc.raw_jwt = rc.raw_jwt[:-4] + "AAAA"        # corrupt signature
    with pytest.raises(ReceiptInvalid):
        led.apply_receipt(scope, rc)
