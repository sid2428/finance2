"""WS1 — AP2 v0.2 flow conformance at the compliance plane.

Replays the two normative AP2 v0.2 flows (Human Present / "direct", and Human
Not Present / "autonomous" — ap2-protocol.org/ap2/flows/) through the full
AEGIS pipeline, plus the HNP policy differential the plan requires: HNP must
exercise a *visibly different* policy path, not just a feature weight.

Mapping notes (full matrix in CONFORMANCE.md):
  * AEGIS's STEP_UP verdict is the compliance-plane analogue of AP2's
    ``unresolved_constraint`` fallback — both bring a human back in the loop.
  * The intent/cart/payment trio maps onto v0.2's open/closed Checkout +
    Payment mandates; the advanced track (aegis/ap2) speaks the SD-JWT forms.
"""

from __future__ import annotations

from aegis.models import Verdict


HNP_GUARDIANS = ["did:aegis:g1", "did:aegis:g2", "did:aegis:g3"]


# --- Human Present ("direct") flow -------------------------------------------

def test_human_present_purchase_allows_frictionlessly(system, make_bundle):
    """AP2 direct flow: user approved the closed mandates on a trusted
    surface. Clean, modest-value purchase settles without friction."""
    env = system.orchestrator.evaluate(
        make_bundle(total_usd=120.0, human_present=True))
    assert env.verdict == Verdict.ALLOW
    assert "AGENT.HNP.UNATTENDED" not in env.reason_codes


# --- Human Not Present ("autonomous") flow -----------------------------------

def test_hnp_same_transaction_takes_stricter_path(system, make_bundle):
    """The identical transaction, attended vs autonomous: HNP must score
    higher and carry the explicit unattended reason code."""
    attended = system.orchestrator.evaluate(
        make_bundle(mandate_id="hp-1", total_usd=120.0, human_present=True))
    autonomous = system.orchestrator.evaluate(
        make_bundle(mandate_id="hnp-1", total_usd=120.0, human_present=False))

    assert "AGENT.HNP.UNATTENDED" in autonomous.reason_codes
    assert autonomous.risk_score > attended.risk_score


def test_hnp_within_bounded_authority_steps_up_not_allows(system, make_bundle):
    """An amount that sails through attended forces a human back into the
    loop when the agent acts alone — AEGIS's STEP_UP is the analogue of
    AP2's unresolved_constraint fallback."""
    attended = system.orchestrator.evaluate(
        make_bundle(mandate_id="hp-2", total_usd=60.0, human_present=True,
                    guardians=HNP_GUARDIANS))
    autonomous = system.orchestrator.evaluate(
        make_bundle(mandate_id="hnp-2", total_usd=60.0, human_present=False,
                    guardians=HNP_GUARDIANS))

    assert attended.verdict == Verdict.ALLOW
    assert autonomous.verdict == Verdict.STEP_UP
    assert autonomous.stepup is not None
    # SCA dynamic linking: the challenge is bound to this exact cart.
    assert autonomous.stepup.cart_hash


def test_hnp_unbounded_authority_is_refused(system, make_bundle):
    """Autonomous spend requires an explicit user-approved value bound: an
    HNP payment under an intent with no max_value_usd fails closed."""
    env = system.orchestrator.evaluate(
        make_bundle(total_usd=50.0, human_present=False, max_value_usd=None))
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.HNP.UNBOUNDED_AUTHORITY" in env.reason_codes

    # The same unbounded intent is fine when a human approved THIS checkout.
    attended = system.orchestrator.evaluate(
        make_bundle(mandate_id="hp-3", total_usd=50.0, human_present=True,
                    max_value_usd=None))
    assert "AGENT.HNP.UNBOUNDED_AUTHORITY" not in attended.reason_codes


def test_hnp_block_band_is_tighter(system, make_bundle):
    """A value that merely steps up attended blocks outright under HNP."""
    attended = system.orchestrator.evaluate(
        make_bundle(mandate_id="hp-4", total_usd=6500.0, max_value_usd=9000.0,
                    human_present=True, guardians=HNP_GUARDIANS))
    autonomous = system.orchestrator.evaluate(
        make_bundle(mandate_id="hnp-4", total_usd=6500.0, max_value_usd=9000.0,
                    human_present=False, guardians=HNP_GUARDIANS))

    assert attended.verdict == Verdict.STEP_UP
    assert autonomous.verdict == Verdict.BLOCK


def test_hnp_policy_path_is_replayable(system, make_bundle):
    """The HNP differential is deterministic evidence, not a live judgment:
    the decision replays byte-for-byte."""
    env = system.orchestrator.evaluate(
        make_bundle(mandate_id="hnp-5", total_usd=60.0, human_present=False,
                    guardians=HNP_GUARDIANS))
    result = system.orchestrator.replay(env.decision_id)
    assert result.matches_original
    assert result.reason_codes_match
    assert result.world_snapshot_matches


# --- receipts: the settlement-outcome artifact --------------------------------

def test_receipt_error_falls_back_without_authority_leak(system):
    """AP2 receipts carry status success/error with a reference hash; an
    error receipt must release (not consume) open-mandate authority.
    Exercised at the scope-ledger layer the AP2 track shares."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from aegis.ap2.scope_ledger import MandateReceipt, ScopeLedger

    verifier = Ed25519PrivateKey.generate()
    ledger = ScopeLedger(verifier.public_key().public_bytes_raw())
    scope = ledger.open_scope("om-err", count=2, value_usd=500.0)
    ledger.reserve(scope, "hash-x", 200.0)

    err = MandateReceipt.issue(verifier, reference="hash-x", result="error",
                               amount_usd=200.0, issued_at=1_000_000,
                               mandate_id="om-err")
    ledger.apply_receipt(scope, err)
    assert scope.remaining_count == 2            # authority released, not spent
    assert scope.remaining_value_usd == 500.0
    assert "hash-x" not in scope.consumed_hashes
