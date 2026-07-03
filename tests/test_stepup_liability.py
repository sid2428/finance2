"""Features 5 & 6 — step-up quorum (four-eyes) and liability apportionment."""

from __future__ import annotations

from aegis.config import REG_E_CONSUMER_CAP_RATIO
from aegis.models import StepUpChallenge
from aegis.pipeline.context import ControlEvidence, DecisionContext
from aegis.pipeline.f5_risk_stepup import required_quorum, verify_quorum
from aegis.pipeline.f6_liability import apportion


# --- Feature 5: quorum -----------------------------------------------------

def _challenge(initiator, approvers, m):
    return StepUpChallenge(
        challenge_id="c1", cart_hash="a" * 64, required_m=m,
        initiator=initiator, eligible_approvers=approvers,
    )


def test_maker_cannot_be_checker(system):
    kr = system.keyring
    for did in ["maker", "g1", "g2"]:
        kr.create(did)
    ch = _challenge("maker", ["g1", "g2"], 2)
    payload = ch.cart_hash.encode()
    contribs = {
        "maker": kr.sign_as("maker", payload),   # must be ignored
        "g1": kr.sign_as("g1", payload),
    }
    satisfied, remaining = verify_quorum(ch, contribs, kr.public_key)
    assert not satisfied and remaining == 1      # maker sig does not count


def test_m_of_n_quorum_satisfied(system):
    kr = system.keyring
    for did in ["maker", "g1", "g2", "g3"]:
        kr.create(did)
    ch = _challenge("maker", ["g1", "g2", "g3"], 2)
    payload = ch.cart_hash.encode()
    contribs = {g: kr.sign_as(g, payload) for g in ["g1", "g2"]}
    satisfied, remaining = verify_quorum(ch, contribs, kr.public_key)
    assert satisfied and remaining == 0


def test_signature_over_wrong_cart_is_rejected(system):
    # SCA dynamic linking: a signature bound to a different cart must not count.
    kr = system.keyring
    for did in ["maker", "g1", "g2"]:
        kr.create(did)
    ch = _challenge("maker", ["g1", "g2"], 2)
    wrong = b"different-cart-hash"
    contribs = {g: kr.sign_as(g, wrong) for g in ["g1", "g2"]}
    satisfied, _ = verify_quorum(ch, contribs, kr.public_key)
    assert not satisfied


def test_required_quorum_scales_with_risk():
    assert required_quorum(45.0) == 2
    assert required_quorum(70.0) == 3


# --- Feature 6: liability --------------------------------------------------

def _ctx(**controls):
    from aegis.testkit import build_bundle
    from aegis.crypto import KeyRing
    bundle = build_bundle(KeyRing())
    return DecisionContext(bundle=bundle, controls=ControlEvidence(**controls))


def test_fully_compliant_defaults_to_psp_residual():
    weights, basis = apportion(_ctx())
    assert basis == "EMV_SHIFT"
    assert weights["psp"] == 1.0
    assert abs(sum(weights.values()) - 1.0) < 1e-9


def test_unmet_merchant_control_shifts_to_merchant():
    weights, _ = apportion(_ctx(merchant_verified_payment_challenge=False))
    assert weights["merchant"] > 0
    assert weights["merchant"] == max(weights.values())


def test_reg_e_consumer_floor_caps_user_on_unauthorized():
    # Only the user's control failed; unauthorized -> user share capped.
    weights, basis = apportion(
        _ctx(user_completed_required_stepup=False), is_unauthorized=True
    )
    assert basis == "EMV_SHIFT+REG_E_FLOOR"
    assert weights["user"] <= REG_E_CONSUMER_CAP_RATIO + 1e-9
    assert abs(sum(weights.values()) - 1.0) < 1e-9
