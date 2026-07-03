"""Feature 4 — delegation-chain verifier (the single gate)."""

from __future__ import annotations

import copy

import pytest

from aegis.ap2 import sdjwt as S
from aegis.ap2.constraints import (
    compile_mcc_allowlist,
    compile_spend_curve,
    default_registry,
)
from aegis.ap2.mandates import build_chain, seal_closed
from aegis.ap2.verifier import VerifyContext, verify_delegation_chain


@pytest.fixture()
def chain_ctx():
    reg = default_registry()
    cons = [compile_spend_curve(200.0, 24.0), compile_mcc_allowlist(["5734"])]
    ch = build_chain(
        constraints=cons, allowed_merchants=["m1", "m2", "m3"],
        cart_merchant={"id": "m2", "name": "Bright Beans", "mcc": "5734"},
        payment_amount={"value_usd": 180.0, "currency": "USD", "value": 180.0},
        line_items=[{"title": "espresso machine", "quantity": 1, "price": 180.0}],
        open_iat=1_000_000, closed_iat=1_000_100,
    )
    ctx = VerifyContext(now=1_000_100, nonce=ch.nonce, registry=reg,
                        issuer_resolver=lambda i: ch.issuer_pub)
    return ch, ctx


def test_valid_chain_passes(chain_ctx):
    ch, ctx = chain_ctx
    assert verify_delegation_chain(ch.as_list(), ch.checkout_jwt, ctx).ok


def test_unknown_issuer_fails(chain_ctx):
    ch, ctx = chain_ctx
    ctx.issuer_resolver = lambda i: None
    assert verify_delegation_chain(ch.as_list(), ch.checkout_jwt, ctx).code == "invalid_credential"


def test_wrong_kb_key_fails(chain_ctx):
    ch, ctx = chain_ctx
    from aegis.crypto import generate_keypair
    wrong, _ = generate_keypair()
    tampered = seal_closed(ch.closed_m.payload, wrong, nonce=ch.nonce, aud=ch.aud,
                           closed_iat=ch.closed_iat)
    res = verify_delegation_chain([ch.open_m.serialize(), tampered.serialize()],
                                  ch.checkout_jwt, ctx)
    assert not res.ok and res.code == "invalid_credential"


def test_sd_hash_rebind_fails(chain_ctx):
    ch, ctx = chain_ctx
    p = copy.deepcopy(ch.closed_m.payload)
    p["sd_hash"] = "A" * 43
    tampered = seal_closed(p, ch.agent_key, nonce=ch.nonce, aud=ch.aud, closed_iat=ch.closed_iat)
    res = verify_delegation_chain([ch.open_m.serialize(), tampered.serialize()],
                                  ch.checkout_jwt, ctx)
    assert not res.ok and "rebind" in res.detail


def test_checkout_hash_mismatch_fails(chain_ctx):
    ch, ctx = chain_ctx
    res = verify_delegation_chain(ch.as_list(), "some.other.jwt", ctx)
    assert not res.ok and res.code == "invalid_mandate"


def test_amount_mutation_fails(chain_ctx):
    ch, ctx = chain_ctx
    p = copy.deepcopy(ch.closed_m.payload)
    p["payment_amount"]["value_usd"] = 1800.0
    tampered = seal_closed(p, ch.agent_key, nonce=ch.nonce, aud=ch.aud, closed_iat=ch.closed_iat)
    res = verify_delegation_chain([ch.open_m.serialize(), tampered.serialize()],
                                  ch.checkout_jwt, ctx)
    assert not res.ok


def test_constraint_drop_fails(chain_ctx):
    ch, ctx = chain_ctx
    p = copy.deepcopy(ch.closed_m.payload)
    p["constraints"] = p["constraints"][1:]
    tampered = seal_closed(p, ch.agent_key, nonce=ch.nonce, aud=ch.aud, closed_iat=ch.closed_iat)
    res = verify_delegation_chain([ch.open_m.serialize(), tampered.serialize()],
                                  ch.checkout_jwt, ctx)
    assert not res.ok and "mutated" in res.detail
