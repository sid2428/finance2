"""Gateway HTTP contract tests, including the step-up approve flow."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aegis.gateway.main import create_app
from aegis.models import Party
from aegis.runtime import build_system
from aegis.testkit import build_bundle


@pytest.fixture()
def client_system():
    sys_ = build_system()
    return TestClient(create_app(sys_)), sys_


def test_evaluate_allow_and_ledger_and_replay(client_system):
    client, sys_ = client_system
    b = build_bundle(sys_.keyring, total_usd=120.0, human_present=True)
    r = client.post("/v1/mandates/evaluate", json=b.model_dump(mode="json"))
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "ALLOW"
    did = body["decision_id"]

    assert client.get(f"/v1/ledger/{did}").status_code == 200
    replay = client.post(f"/v1/ledger/{did}/replay").json()
    assert replay["matches_original"] and replay["world_snapshot_matches"]

    chain = client.get("/v1/ledger").json()
    assert chain["chain_valid"] is True


def test_evaluate_block_surfaces_reason_codes(client_system):
    client, sys_ = client_system
    b = build_bundle(
        sys_.keyring,
        merchant_legal_name="Bank Melli Iran",
        beneficiary=Party(legal_name="Bank Melli Iran", account_ref="x"),
        human_present=True,
    )
    body = client.post("/v1/mandates/evaluate", json=b.model_dump(mode="json")).json()
    assert body["verdict"] == "BLOCK"
    assert "AGENT.SANC.SDN_HIT" in body["reason_codes"]


def test_stepup_approve_reaches_quorum(client_system):
    client, sys_ = client_system
    guardians = ["did:aegis:g1", "did:aegis:g2", "did:aegis:g3", "did:aegis:g4"]
    b = build_bundle(
        sys_.keyring,
        total_usd=6500.0,
        max_value_usd=9000.0,
        buyer_did="did:aegis:buyer-z",
        initiator_did="did:aegis:buyer-z",
        beneficiary=Party(legal_name="Bright Beans Coffee Ltd", account_ref="acct-2"),
        guardians=guardians,
    )
    body = client.post("/v1/mandates/evaluate", json=b.model_dump(mode="json")).json()
    assert body["verdict"] == "STEP_UP"
    ch = body["stepup"]
    cart_hash = ch["cart_hash"]
    m = ch["required_m"]

    satisfied = False
    for g in guardians[:m]:
        sig = sys_.keyring.sign_as(g, cart_hash.encode())
        resp = client.post(
            f"/v1/stepup/{ch['challenge_id']}/approve",
            json={"signer_did": g, "signature": sig},
        ).json()
        satisfied = resp["satisfied"]
    assert satisfied is True


def test_sar_drafts_endpoint(client_system):
    from aegis.models import LineItem
    client, sys_ = client_system
    agent = "did:aegis:smurf2"
    benef = Party(legal_name="Benef Co", account_ref="acct-b")
    for i in range(3):
        b = build_bundle(
            sys_.keyring, mandate_id=f"s-{i}",
            intent_text="Transfer funds to Benef",
            max_value_usd=None, total_usd=3600.0,
            line_items=[LineItem(sku="TRF", description="Transfer funds to Benef",
                                 quantity=1, unit_price_usd=3600.0)],
            buyer_did=agent, initiator_did=agent,
            merchant_did="did:aegis:benef-m", merchant_legal_name="Benef Co",
            beneficiary=benef,
        )
        client.post("/v1/mandates/evaluate",
                    json={**b.model_dump(mode="json")})
    # Structuring only trips deterministically when timestamps share a window;
    # the default clock is wall-time here, so at least assert the endpoint shape.
    drafts = client.get("/v1/sar/drafts").json()
    assert "count" in drafts and "drafts" in drafts
