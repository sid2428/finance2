"""Feature 2 — sanctions & PEP interdiction."""

from __future__ import annotations

from aegis.data import default_ownership_graph, default_watchlist
from aegis.models import Party, Verdict
from aegis.pipeline.f2_sanctions import ofac_50_percent, screen_name


def test_exact_sanctioned_name_blocks(system, make_bundle):
    b = make_bundle(
        merchant_legal_name="Bank Melli Iran",
        beneficiary=Party(legal_name="Bank Melli Iran", account_ref="acct-x"),
        human_present=True,
    )
    env = system.orchestrator.evaluate(b)
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.SANC.SDN_HIT" in env.reason_codes


def test_transliterated_name_blocks_via_fuzzy(system, make_bundle):
    # 'Ivan Petroff Volkoff' is a transliteration of SDN 'Ivan Petrov Volkov'.
    b = make_bundle(
        merchant_legal_name="Ivan Petroff Volkoff",
        beneficiary=Party(legal_name="Ivan Petroff Volkoff", account_ref="acct-x"),
        human_present=True,
    )
    env = system.orchestrator.evaluate(b)
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.SANC.SDN_HIT" in env.reason_codes


def test_pep_flags_edd_but_does_not_block(system, make_bundle):
    b = make_bundle(
        merchant_legal_name="Adaeze Okonkwo",     # PEP entry
        beneficiary=Party(legal_name="Adaeze Okonkwo", account_ref="acct-p"),
        human_present=True,
        total_usd=50.0,
        guardians=["did:aegis:g1", "did:aegis:g2", "did:aegis:g3"],
    )
    env = system.orchestrator.evaluate(b)
    assert "AGENT.SANC.PEP_EDD" in env.reason_codes
    # PEP raises risk (EDD / step-up) but is never a hard block.
    pep = [s for s in env.signals if s.code == "AGENT.SANC.PEP_EDD"][0]
    assert not pep.hard_block
    assert env.verdict != Verdict.BLOCK


def test_ofac_50_percent_rule_blocks(system, make_bundle):
    # SHELL-900 is 55% owned by sanctioned parties (30% + 25%).
    b = make_bundle(
        merchant_legal_name="Perfectly Normal Trading Co",
        beneficiary=Party(legal_name="Perfectly Normal Trading Co",
                          account_ref="SHELL-900"),
        human_present=True,
    )
    env = system.orchestrator.evaluate(b)
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.SANC.OFAC_50PCT" in env.reason_codes


def test_ownership_share_below_threshold_passes():
    graph = default_ownership_graph()
    assert ofac_50_percent("SHELL-900", graph) >= 0.50   # 0.55
    assert ofac_50_percent("SHELL-901", graph) < 0.50    # 0.20


def test_clean_name_does_not_match():
    hits = screen_name("Bright Beans Coffee Ltd", default_watchlist())
    assert hits == []
