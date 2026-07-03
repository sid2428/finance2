"""Feature 7 — hash-chained ledger, signatures, and audit replay determinism."""

from __future__ import annotations

from aegis.models import Verdict


def test_chain_valid_after_multiple_decisions(system, make_bundle):
    for i in range(4):
        system.orchestrator.evaluate(make_bundle(mandate_id=f"m-{i}", human_present=True))
    ok, bad = system.ledger.verify_chain()
    assert ok and bad is None
    assert len(system.ledger.all()) == 4


def test_every_envelope_is_signed(system, make_bundle):
    env = system.orchestrator.evaluate(make_bundle(human_present=True))
    assert env.signature
    assert system.ledger.verify_signature(env)


def test_tampering_breaks_chain(system, make_bundle):
    system.orchestrator.evaluate(make_bundle(mandate_id="a", human_present=True))
    system.orchestrator.evaluate(make_bundle(mandate_id="b", human_present=True))
    victim = system.ledger.all()[0]
    victim.reason_codes = victim.reason_codes + ["TAMPERED"]
    ok, bad = system.ledger.verify_chain()
    assert not ok
    assert bad == 0


def test_replay_reproduces_verdict_deterministically(system, make_bundle):
    env = system.orchestrator.evaluate(make_bundle(total_usd=120.0, human_present=True))
    result = system.orchestrator.replay(env.decision_id)
    assert result.matches_original
    assert result.world_snapshot_matches
    assert result.reason_codes_match
    assert result.reproduced_verdict == env.verdict


def test_replay_of_blocked_decision(system, make_bundle):
    from aegis.models import Party
    env = system.orchestrator.evaluate(make_bundle(
        merchant_legal_name="Bank Melli Iran",
        beneficiary=Party(legal_name="Bank Melli Iran", account_ref="x"),
        human_present=True,
    ))
    assert env.verdict == Verdict.BLOCK
    result = system.orchestrator.replay(env.decision_id)
    assert result.matches_original
    assert result.reproduced_verdict == Verdict.BLOCK
