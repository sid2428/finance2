"""Feature 7 — adversarial fuzzer: every attack must be rejected."""

from __future__ import annotations

from aegis.ap2.constraints import (
    compile_mcc_allowlist,
    compile_spend_curve,
    default_registry,
)
from aegis.ap2.mandates import build_chain
from aegis.ap2.sandbox import MandateFuzzer
from aegis.ap2.verifier import VerifyContext


def _chain_ctx():
    reg = default_registry()
    cons = [compile_spend_curve(200.0, 24.0), compile_mcc_allowlist(["5734"])]
    ch = build_chain(
        constraints=cons, allowed_merchants=["m1", "m2", "m3"],
        cart_merchant={"id": "m2", "name": "Bright Beans", "mcc": "5734"},
        payment_amount={"value_usd": 180.0, "currency": "USD", "value": 180.0},
        line_items=[{"title": "espresso machine", "quantity": 1, "price": 180.0}],
    )
    ctx = VerifyContext(now=1_000_100, nonce=ch.nonce, registry=reg,
                        issuer_resolver=lambda i: ch.issuer_pub)
    return ch, ctx


def test_baseline_passes_and_all_attacks_rejected():
    ch, ctx = _chain_ctx()
    report = MandateFuzzer().run(ch, ctx)
    assert report.baseline_ok
    assert report.attempted == 8
    assert report.escaped == []      # no attack may verify
    assert report.clean


def test_report_counts_consistent():
    ch, ctx = _chain_ctx()
    report = MandateFuzzer().run(ch, ctx)
    assert report.rejected == report.attempted - len(report.escaped)
