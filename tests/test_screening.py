"""WS2 — pluggable screening data plane.

Acceptance criteria under test:
  * the pipeline runs unmodified against all three providers via configuration
    (offline fixtures, yente/OpenSanctions, Moov Watchman — the HTTP providers
    exercised through injected fake transports);
  * every verdict records list provenance (provider, dataset, version);
  * stale list data fails CLOSED with AGENT.SANC.STALE_LIST;
  * provider outage fails CLOSED with AGENT.SANC.PROVIDER_UNAVAILABLE;
  * audit replay reuses recorded screening responses — never a live call.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aegis.models import Party, Verdict
from aegis.runtime import build_system
from aegis.screening import (
    ListProvenance,
    OfflineFixtureProvider,
    ScreeningUnavailable,
    WatchmanProvider,
    YenteProvider,
    provider_from_env,
)
from aegis.testkit import build_bundle

NOW = 1_800_000_000.0            # pinned decision clock
FRESH_TS = NOW - 3600            # list refreshed an hour before the decision
STALE_TS = NOW - 30 * 24 * 3600  # list a month old — beyond the bound


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _sanctioned_bundle(keyring, name="Bank Melli Iran"):
    return build_bundle(
        keyring,
        merchant_legal_name=name,
        beneficiary=Party(legal_name=name, account_ref="acct-x"),
        human_present=True,
    )


# --- fake transports for the HTTP providers ---------------------------------

def fake_yente_http(last_export=FRESH_TS, sanctioned=("bank melli iran",),
                    pep=()):
    def http(method, url, payload=None, timeout=5.0):
        if url.endswith("/catalog"):
            return 200, {"datasets": [{
                "name": "default", "version": "20270115",
                "last_export": _iso(last_export),
            }]}
        name = payload["queries"]["q"]["properties"]["name"][0]
        results = []
        if name.lower() in sanctioned:
            results.append({
                "id": "NK-123", "caption": name, "score": 0.97,
                "schema": "Organization", "datasets": ["us_ofac_sdn"],
                "properties": {"topics": ["sanction"]},
            })
        if name.lower() in pep:
            results.append({
                "id": "Q-456", "caption": name, "score": 0.95,
                "schema": "Person", "datasets": ["peps"],
                "properties": {"topics": ["role.pep"]},
            })
        return 200, {"responses": {"q": {"results": results}}}
    return http


def fake_watchman_http(timestamp=FRESH_TS, sanctioned_substr="Melli"):
    def http(method, url, payload=None, timeout=5.0):
        if "/downloads" in url:
            return 200, [{"timestamp": _iso(timestamp)}]
        if sanctioned_substr and sanctioned_substr in url:
            return 200, {"SDNs": [{
                "entityID": "12345", "sdnName": "BANK MELLI IRAN",
                "sdnType": "entity", "match": 0.95,
            }]}
        return 200, {"SDNs": []}
    return http


# --- one pipeline, three data planes ----------------------------------------

@pytest.fixture(params=["offline", "yente", "watchman"])
def provider(request):
    if request.param == "offline":
        return OfflineFixtureProvider()
    if request.param == "yente":
        return YenteProvider("http://yente.test", http=fake_yente_http())
    return WatchmanProvider("http://watchman.test", http=fake_watchman_http())


def test_sdn_hit_blocks_on_every_provider(provider):
    system = build_system(screening=provider)
    env = system.orchestrator.evaluate(
        _sanctioned_bundle(system.keyring), now=NOW)
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.SANC.SDN_HIT" in env.reason_codes


def test_clean_name_allows_on_every_provider(provider):
    system = build_system(screening=provider)
    env = system.orchestrator.evaluate(
        build_bundle(system.keyring, total_usd=100.0, human_present=True),
        now=NOW)
    assert env.verdict == Verdict.ALLOW


def test_every_verdict_records_list_provenance(provider):
    system = build_system(screening=provider)
    env = system.orchestrator.evaluate(
        build_bundle(system.keyring, total_usd=100.0, human_present=True),
        now=NOW)
    assert env.screening is not None
    assert env.screening["provider"] == provider.name
    assert env.screening["dataset_version"]
    # Provenance is inside the signed envelope, so it is attested evidence.
    assert system.ledger.verify_signature(env)


def test_yente_pep_topic_maps_to_edd_not_block():
    provider = YenteProvider(
        "http://yente.test",
        http=fake_yente_http(sanctioned=(), pep=("adaeze okonkwo",)))
    system = build_system(screening=provider)
    bundle = build_bundle(
        system.keyring,
        merchant_legal_name="Adaeze Okonkwo",
        beneficiary=Party(legal_name="Adaeze Okonkwo", account_ref="acct-p"),
        human_present=True, total_usd=50.0,
        guardians=["did:aegis:g1", "did:aegis:g2", "did:aegis:g3"],
    )
    env = system.orchestrator.evaluate(bundle, now=NOW)
    assert "AGENT.SANC.PEP_EDD" in env.reason_codes
    assert env.verdict != Verdict.BLOCK


# --- freshness contract: stale list => fail closed ---------------------------

@pytest.mark.parametrize("stale_provider", [
    YenteProvider("http://yente.test",
                  http=fake_yente_http(last_export=STALE_TS)),
    WatchmanProvider("http://watchman.test",
                     http=fake_watchman_http(timestamp=STALE_TS)),
])
def test_stale_list_fails_closed(stale_provider):
    system = build_system(screening=stale_provider)
    # Even a perfectly clean transaction is blocked: no verdict is ever
    # produced against list data older than the freshness bound.
    env = system.orchestrator.evaluate(
        build_bundle(system.keyring, total_usd=100.0, human_present=True),
        now=NOW)
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.SANC.STALE_LIST" in env.reason_codes
    # The stale provenance itself is recorded as evidence.
    assert env.screening is not None


def test_provider_outage_fails_closed():
    def down(method, url, payload=None, timeout=5.0):
        raise ScreeningUnavailable(f"connection refused: {url}")

    system = build_system(
        screening=YenteProvider("http://yente.test", http=down))
    env = system.orchestrator.evaluate(
        build_bundle(system.keyring, total_usd=100.0, human_present=True),
        now=NOW)
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.SANC.PROVIDER_UNAVAILABLE" in env.reason_codes


# --- replay determinism: recorded responses, never a live call ---------------

class CountingProvider(OfflineFixtureProvider):
    def __init__(self):
        super().__init__()
        self.calls = 0

    def screen(self, name):
        self.calls += 1
        return super().screen(name)


def test_replay_uses_recorded_screening_not_live_calls():
    provider = CountingProvider()
    system = build_system(screening=provider)
    env = system.orchestrator.evaluate(
        build_bundle(system.keyring, total_usd=100.0, human_present=True),
        now=NOW)
    live_calls = provider.calls
    assert live_calls > 0

    result = system.orchestrator.replay(env.decision_id)
    assert result.matches_original
    assert result.reason_codes_match
    assert provider.calls == live_calls   # replay made zero live calls


def test_replay_reproduces_unavailable_outcome():
    class Flaky:
        name = "flaky"
        def provenance(self):
            raise ScreeningUnavailable("data plane down")
        def screen(self, name):
            raise ScreeningUnavailable("data plane down")

    system = build_system(screening=Flaky())
    env = system.orchestrator.evaluate(
        build_bundle(system.keyring, total_usd=100.0, human_present=True),
        now=NOW)
    assert "AGENT.SANC.PROVIDER_UNAVAILABLE" in env.reason_codes

    result = system.orchestrator.replay(env.decision_id)
    assert result.matches_original
    assert result.reason_codes_match


# --- configuration seam -------------------------------------------------------

def test_provider_from_env_selects_implementation():
    assert isinstance(provider_from_env({}), OfflineFixtureProvider)
    y = provider_from_env({"AEGIS_SCREENING_PROVIDER": "yente",
                           "AEGIS_YENTE_URL": "http://y:8000"})
    assert isinstance(y, YenteProvider)
    w = provider_from_env({"AEGIS_SCREENING_PROVIDER": "watchman",
                           "AEGIS_WATCHMAN_URL": "http://w:8084"})
    assert isinstance(w, WatchmanProvider)
    with pytest.raises(ValueError):
        provider_from_env({"AEGIS_SCREENING_PROVIDER": "vibes"})


def test_offline_provenance_is_static_fixture():
    prov = OfflineFixtureProvider().provenance()
    assert isinstance(prov, ListProvenance)
    assert prov.generated_at is None      # static fixtures: demo-mode exemption
    assert prov.dataset_version           # content-hash pinned
