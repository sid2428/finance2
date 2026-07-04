"""WS3 — durable state: kill-and-restart survival, WORM enforcement,
fail-closed startup on corruption, cross-restart deterministic replay, and
offline evidence verification with only the public key."""

from __future__ import annotations

import json
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.ap2.scope_ledger import DoubleSpend, MandateReceipt, ScopeLedger
from aegis.ledger.evidence import verify_evidence, write_evidence
from aegis.models import LineItem, Party, Verdict
from aegis.runtime import DB_FILE, LEDGER_KEY_FILE, build_system
from aegis.storage import LedgerCorruptionError, SqliteScopeStore
from aegis.testkit import build_bundle
from aegis.tools.verify_evidence import main as verify_cli


@pytest.fixture()
def data_dir(tmp_path):
    return tmp_path / "aegis-data"


def _evaluate_one(system, *, mandate_id="p-001", total_usd=100.0, now=1_000_000.0):
    bundle = build_bundle(system.keyring, mandate_id=mandate_id,
                          total_usd=total_usd, human_present=True)
    return system.orchestrator.evaluate(bundle, now=now)


# --- kill-and-restart survival ---------------------------------------------

def test_restart_preserves_ledger_and_chain(data_dir):
    sys1 = build_system(data_dir)
    env_a = _evaluate_one(sys1, mandate_id="p-001")
    env_b = _evaluate_one(sys1, mandate_id="p-002", now=1_000_060.0)
    head = sys1.ledger.head_hash()
    sys1.close()

    sys2 = build_system(data_dir)
    try:
        assert [e.decision_id for e in sys2.ledger.all()] == \
               [env_a.decision_id, env_b.decision_id]
        assert sys2.ledger.head_hash() == head
        ok, bad = sys2.ledger.verify_chain()
        assert ok and bad is None
        # New decisions chain onto the persisted head.
        env_c = _evaluate_one(sys2, mandate_id="p-003", now=1_000_120.0)
        assert env_c.prev_envelope_hash == head
    finally:
        sys2.close()


def test_cross_restart_replay_is_deterministic(data_dir):
    sys1 = build_system(data_dir)
    env = _evaluate_one(sys1, mandate_id="p-010")
    assert env.verdict == Verdict.ALLOW
    sys1.close()

    # A decision recorded yesterday must replay byte-for-byte today from
    # durable state alone (fresh process, no in-memory carry-over).
    sys2 = build_system(data_dir)
    try:
        result = sys2.orchestrator.replay(env.decision_id)
        assert result.matches_original
        assert result.world_snapshot_matches
        assert result.reason_codes_match
    finally:
        sys2.close()


def test_structuring_cluster_survives_restart(data_dir):
    """A smurfing cluster spread across process lifetimes is exactly the case
    the in-memory demo store cannot catch."""
    benef = Party(legal_name="Beneficiary Co", account_ref="acct-b")

    def transfer(system, i, now):
        bundle = build_bundle(
            system.keyring,
            mandate_id=f"s-{i}",
            intent_text="Transfer funds to Beneficiary",
            max_value_usd=None,
            total_usd=3600,
            line_items=[LineItem(sku="TRF", description="Transfer funds to Beneficiary",
                                 quantity=1, unit_price_usd=3600)],
            buyer_did="did:aegis:smurf",
            initiator_did="did:aegis:smurf",
            merchant_did="did:aegis:benef-merchant",
            merchant_legal_name="Beneficiary Co",
            beneficiary=benef,
            guardians=["did:aegis:g1", "did:aegis:g2",
                       "did:aegis:g3", "did:aegis:g4"],
        )
        return system.orchestrator.evaluate(bundle, now=now)

    sys1 = build_system(data_dir)
    transfer(sys1, 0, 1_000_000.0)
    transfer(sys1, 1, 1_000_060.0)
    sys1.close()

    sys2 = build_system(data_dir)
    try:
        env = transfer(sys2, 2, 1_000_120.0)
        assert "AGENT.AML.STRUCTURING_SUSPECTED" in env.reason_codes
        assert env.sar_draft is not None
        assert env.sar_draft["transaction_count"] == 3
    finally:
        sys2.close()


# --- WORM enforcement and fail-closed startup -------------------------------

def test_worm_store_rejects_update_and_delete(data_dir):
    sys1 = build_system(data_dir)
    _evaluate_one(sys1)
    sys1.close()

    conn = sqlite3.connect(str(data_dir / DB_FILE))
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("UPDATE decision_ledger SET envelope = '{}'")
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM decision_ledger")
    finally:
        conn.close()


def test_tampered_chain_blocks_startup(data_dir):
    sys1 = build_system(data_dir)
    env = _evaluate_one(sys1)
    sys1.close()

    # Even an attacker who drops the WORM triggers cannot escape detection:
    # the rewritten history no longer verifies against the hash chain.
    conn = sqlite3.connect(str(data_dir / DB_FILE))
    try:
        conn.execute("DROP TRIGGER worm_no_update")
        tampered = json.loads(conn.execute(
            "SELECT envelope FROM decision_ledger WHERE decision_id = ?",
            (env.decision_id,)).fetchone()[0])
        tampered["verdict"] = "ALLOW" if env.verdict != Verdict.ALLOW else "BLOCK"
        conn.execute("UPDATE decision_ledger SET envelope = ? WHERE decision_id = ?",
                     (json.dumps(tampered), env.decision_id))
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(LedgerCorruptionError):
        build_system(data_dir)


def test_signing_key_swap_is_refused(data_dir):
    sys1 = build_system(data_dir)
    _evaluate_one(sys1)
    sys1.close()

    # Losing/replacing the signing key must not silently continue the chain.
    (data_dir / LEDGER_KEY_FILE).unlink()
    with pytest.raises(LedgerCorruptionError):
        build_system(data_dir)


# --- evidence export ---------------------------------------------------------

def test_evidence_bundle_verifies_offline(data_dir, tmp_path):
    sys1 = build_system(data_dir)
    env = _evaluate_one(sys1)
    path = write_evidence(sys1.ledger, env.decision_id, tmp_path / "evidence.json")
    sys1.close()

    # The documented external procedure: only the file, only the embedded key.
    assert verify_cli([str(path)]) == 0

    bundle = json.loads(path.read_text(encoding="utf-8"))
    ok, checks = verify_evidence(bundle)
    assert ok and all(checks.values())

    # Any tampering (here: flipping the verdict) must fail verification.
    bundle["envelope"]["verdict"] = "ALLOW" if env.verdict != Verdict.ALLOW else "BLOCK"
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(json.dumps(bundle), encoding="utf-8")
    assert verify_cli([str(tampered_path)]) == 1


# --- scope-ledger durability (AP2 track) ------------------------------------

def test_scope_state_survives_restart(data_dir):
    verifier = Ed25519PrivateKey.generate()
    verifier_pub = verifier.public_key().public_bytes_raw()
    db = data_dir / DB_FILE

    store1 = SqliteScopeStore(db)
    ledger1 = ScopeLedger(verifier_pub, store=store1)
    scope = ledger1.open_scope("om-1", count=3, value_usd=900.0)
    ledger1.reserve(scope, "hash-a", 300.0)
    receipt = MandateReceipt.issue(verifier, reference="hash-a", result="success",
                                   amount_usd=300.0, issued_at=1_000_000,
                                   mandate_id="om-1")
    ledger1.apply_receipt(scope, receipt)
    store1.close()

    store2 = SqliteScopeStore(db)
    try:
        ledger2 = ScopeLedger(verifier_pub, store=store2)
        restored = ledger2.scope("om-1")
        assert restored.remaining_count == 2
        assert restored.remaining_value_usd == 600.0
        assert "hash-a" in restored.consumed_hashes
        # The consumed hash stays spent across restarts — no double spend.
        with pytest.raises(DoubleSpend):
            ledger2.reserve(restored, "hash-a", 100.0)
    finally:
        store2.close()
