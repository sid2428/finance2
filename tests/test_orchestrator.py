"""Orchestrator invariants: fail-closed, signature gating, the ML-cannot-lift-a
-hard-block guardrail (SR 11-7), and the single-authority settlement gate."""

from __future__ import annotations

import pytest

from aegis.adapters import SettlementRefused, settle
from aegis.models import Party, Verdict


def test_signature_failure_blocks(system, make_bundle):
    b = make_bundle(human_present=True)
    b.intent.proof.signature = "00" * 64      # corrupt the intent signature
    env = system.orchestrator.evaluate(b)
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.SIG.INVALID" in env.reason_codes


def test_missing_proof_blocks(system, make_bundle):
    b = make_bundle(sign=False)
    env = system.orchestrator.evaluate(b)
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.SIG.INVALID" in env.reason_codes


def test_stage_exception_fails_closed(system, make_bundle, monkeypatch):
    # Simulate a dependency blowing up mid-pipeline: must resolve to BLOCK.
    import aegis.pipeline.f2_sanctions as f2

    def boom(ctx):
        raise RuntimeError("sanctions feed unavailable")

    monkeypatch.setattr(f2, "run", boom)
    env = system.orchestrator.evaluate(make_bundle(human_present=True))
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.SYS.FAILCLOSED" in env.reason_codes


def test_ml_cannot_lift_a_hard_block(system, make_bundle):
    # A sanctions hard block must stand regardless of risk scoring. Because the
    # pipeline short-circuits, the risk model is never even consulted.
    b = make_bundle(
        merchant_legal_name="Bank Melli Iran",
        beneficiary=Party(legal_name="Bank Melli Iran", account_ref="x"),
        human_present=True,
    )
    env = system.orchestrator.evaluate(b)
    assert env.verdict == Verdict.BLOCK
    assert "aegis-risk-scorer" not in env.model_provenance   # model never ran


def test_settlement_refused_for_block(system, make_bundle):
    b = make_bundle(
        merchant_legal_name="Bank Melli Iran",
        beneficiary=Party(legal_name="Bank Melli Iran", account_ref="x"),
        human_present=True,
    )
    env = system.orchestrator.evaluate(b)
    with pytest.raises(SettlementRefused):
        settle(env, b.payment, system.settlement, system.ledger)


def test_settlement_allowed_for_allow(system, make_bundle):
    b = make_bundle(total_usd=100.0, human_present=True)
    env = system.orchestrator.evaluate(b)
    assert env.verdict == Verdict.ALLOW
    result = settle(env, b.payment, system.settlement, system.ledger)
    assert result.settled


def test_settlement_refused_for_stepup_without_quorum(system, make_bundle):
    b = make_bundle(
        total_usd=6500.0,
        max_value_usd=9000.0,
        buyer_did="did:aegis:buyer-x",
        initiator_did="did:aegis:buyer-x",
        beneficiary=Party(legal_name="Bright Beans Coffee Ltd", account_ref="acct-2"),
        guardians=["did:aegis:g1", "did:aegis:g2", "did:aegis:g3", "did:aegis:g4"],
    )
    env = system.orchestrator.evaluate(b)
    assert env.verdict == Verdict.STEP_UP
    with pytest.raises(SettlementRefused):
        settle(env, b.payment, system.settlement, system.ledger, quorum_satisfied=False)


def test_tampered_envelope_cannot_settle(system, make_bundle):
    b = make_bundle(total_usd=100.0, human_present=True)
    env = system.orchestrator.evaluate(b)
    env.verdict = Verdict.ALLOW
    env.mandate_id = b.payment.mandate_id
    env.reason_codes = ["FORGED"]              # mutate after signing
    with pytest.raises(SettlementRefused):     # signature no longer verifies
        settle(env, b.payment, system.settlement, system.ledger)
