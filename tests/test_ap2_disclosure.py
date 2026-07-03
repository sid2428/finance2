"""Feature 2 — minimal-disclosure solver + decoy privacy budget."""

from __future__ import annotations

from aegis.ap2 import sdjwt as S
from aegis.ap2.constraints import (
    compile_merchant_allowlist,
    compile_spend_curve,
    default_registry,
)
from aegis.ap2.disclosure import minimal_disclosure_set, observable_slots
from aegis.ap2.mandates import build_chain
from aegis.ap2.verifier import VerifyContext, verify_delegation_chain


def _chain(merchant_decoys=0):
    cons = [compile_spend_curve(500.0, 24.0), compile_merchant_allowlist()]
    return build_chain(
        constraints=cons, allowed_merchants=[f"m{i}" for i in range(12)],
        cart_merchant={"id": "m3", "name": "Shop3", "mcc": "5999"},
        payment_amount={"value_usd": 100.0, "currency": "USD", "value": 100.0},
        line_items=[{"title": "thing", "quantity": 1, "price": 100.0}],
        merchant_decoys=merchant_decoys,
    )


def test_solver_discloses_exactly_one_merchant():
    ch = _chain()
    reg = default_registry()
    mds = minimal_disclosure_set(ch.open_m, ch.closed_m.payload, reg, {"now": 1_000_100})
    assert len(mds) == 1
    revealed = [S.parse_disclosure(r).value for r in ch.open_m.disclosures
                if S.parse_disclosure(r).digest in mds]
    assert revealed == ["m3"]


def test_minimal_presentation_still_verifies():
    ch = _chain()
    reg = default_registry()
    ctx = VerifyContext(now=1_000_100, nonce=ch.nonce, registry=reg,
                        issuer_resolver=lambda i: ch.issuer_pub)
    mds = minimal_disclosure_set(ch.open_m, ch.closed_m.payload, reg, {"now": 1_000_100})
    sub = S.present(ch.open_m, mds)
    assert verify_delegation_chain([sub.serialize(), ch.closed_m.serialize()],
                                   ch.checkout_jwt, ctx).ok


def test_decoys_hide_real_merchant_count():
    plain = _chain(merchant_decoys=0)
    padded = _chain(merchant_decoys=5)
    assert observable_slots(plain.open_m) == 12
    assert observable_slots(padded.open_m) == 17   # observer cannot infer real 12


def test_observable_slots_invariant_to_disclosure():
    ch = _chain(merchant_decoys=5)
    reg = default_registry()
    mds = minimal_disclosure_set(ch.open_m, ch.closed_m.payload, reg, {"now": 1_000_100})
    sub = S.present(ch.open_m, mds)
    # Revealing one merchant does not change the number of observable slots.
    assert observable_slots(sub) == observable_slots(ch.open_m)
