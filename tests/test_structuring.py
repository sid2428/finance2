"""Feature 3 — structuring & velocity."""

from __future__ import annotations

from aegis.models import LineItem, Party, Verdict


def _transfer(make_bundle, i, amount, agent, benef):
    return make_bundle(
        mandate_id=f"s-{i}",
        intent_text="Transfer funds to Beneficiary",
        max_value_usd=None,
        total_usd=amount,
        line_items=[LineItem(sku="TRF", description="Transfer funds to Beneficiary",
                             quantity=1, unit_price_usd=amount)],
        buyer_did=agent,
        initiator_did=agent,
        merchant_did="did:aegis:benef-merchant",
        merchant_legal_name="Beneficiary Co",
        beneficiary=benef,
        guardians=["did:aegis:g1", "did:aegis:g2", "did:aegis:g3", "did:aegis:g4"],
    )


def test_single_transfer_no_structuring(system, make_bundle):
    agent = "did:aegis:agentA"
    benef = Party(legal_name="Beneficiary Co", account_ref="acct-b")
    env = system.orchestrator.evaluate(_transfer(make_bundle, 0, 3600, agent, benef),
                                       now=1_000_000.0)
    assert "AGENT.AML.STRUCTURING_SUSPECTED" not in env.reason_codes
    assert env.sar_draft is None


def test_structuring_cluster_triggers_sar(system, make_bundle):
    agent = "did:aegis:smurf"
    benef = Party(legal_name="Beneficiary Co", account_ref="acct-b")
    last = None
    for i in range(3):
        last = system.orchestrator.evaluate(
            _transfer(make_bundle, i, 3600, agent, benef), now=1_000_000.0 + i * 60
        )
    assert "AGENT.AML.STRUCTURING_SUSPECTED" in last.reason_codes
    assert last.sar_draft is not None
    assert last.sar_draft["transaction_count"] == 3
    assert last.sar_draft["aggregate_usd"] == 10800.0
    # High structuring risk pushes over the step-up band -> BLOCK.
    assert last.verdict == Verdict.BLOCK


def test_transfers_to_different_beneficiaries_do_not_cluster(system, make_bundle):
    agent = "did:aegis:agentB"
    last = None
    for i in range(3):
        benef = Party(legal_name=f"Benef {i}", account_ref=f"acct-{i}")
        last = system.orchestrator.evaluate(
            _transfer(make_bundle, i, 3600, agent, benef), now=1_000_000.0 + i * 60
        )
    assert "AGENT.AML.STRUCTURING_SUSPECTED" not in last.reason_codes


def test_velocity_cap_hard_blocks(system, make_bundle):
    # A single transfer above the per-agent 24h value cap fails closed.
    agent = "did:aegis:whale"
    benef = Party(legal_name="Beneficiary Co", account_ref="acct-b")
    env = system.orchestrator.evaluate(
        _transfer(make_bundle, 0, 300_000.0, agent, benef), now=1_000_000.0
    )
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.AML.VELOCITY_EXCEEDED" in env.reason_codes
