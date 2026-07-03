"""Feature 1 — jurisdiction firewall."""

from __future__ import annotations

from aegis.models import Jurisdiction, Party, Verdict


def test_clean_transfer_allows(system, make_bundle):
    b = make_bundle(total_usd=180.0, human_present=True)
    env = system.orchestrator.evaluate(b)
    assert env.verdict == Verdict.ALLOW


def test_travel_rule_missing_attestation_blocks(system, make_bundle):
    # Above the strictest touched threshold (GB=1000) with no originator/
    # beneficiary attestation -> hard block.
    b = make_bundle(
        total_usd=5000.0,
        originator=Party(),                 # attestation absent
        beneficiary=Party(),
    )
    env = system.orchestrator.evaluate(b)
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.JUR.TRAVELRULE_MISSING" in env.reason_codes


def test_travel_rule_present_passes_firewall(system, make_bundle):
    b = make_bundle(
        total_usd=5000.0,
        originator=Party(legal_name="Alex Buyer", account_ref="acct-1"),
        beneficiary=Party(legal_name="Bright Beans Coffee Ltd", account_ref="acct-2"),
        human_present=True,
    )
    env = system.orchestrator.evaluate(b)
    assert "AGENT.JUR.TRAVELRULE_MISSING" not in env.reason_codes


def test_eu_buyer_outside_enclave_blocks(system, make_bundle):
    b = make_bundle(
        total_usd=50.0,
        touched=[
            Jurisdiction(iso="DE", role="buyer"),
            Jurisdiction(iso="US", role="merchant"),
        ],
        processing_region="US",
    )
    env = system.orchestrator.evaluate(b)
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.JUR.DATA_RESIDENCY" in env.reason_codes


def test_eu_buyer_in_enclave_passes(system, make_bundle):
    b = make_bundle(
        total_usd=50.0,
        touched=[
            Jurisdiction(iso="DE", role="buyer"),
            Jurisdiction(iso="DE", role="merchant"),
        ],
        processing_region="EU",
        human_present=True,
    )
    env = system.orchestrator.evaluate(b)
    assert "AGENT.JUR.DATA_RESIDENCY" not in env.reason_codes


def test_restricted_corridor_blocks(system, make_bundle):
    b = make_bundle(
        total_usd=100.0,
        touched=[
            Jurisdiction(iso="US", role="buyer"),
            Jurisdiction(iso="IR", role="merchant"),
        ],
    )
    env = system.orchestrator.evaluate(b)
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.JUR.RAIL_INELIGIBLE" in env.reason_codes
