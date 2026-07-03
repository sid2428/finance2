"""SD-JWT primitives: signing, disclosure, decoys, KB-JWT, tamper detection."""

from __future__ import annotations

from aegis.crypto import generate_keypair
from aegis.ap2 import sdjwt as S


def _issue():
    sk, pub = generate_keypair()
    jwt, discs = S.issue_sd_jwt(
        sk,
        claims={"iss": "did:issuer", "constraints": [{"type": "x"}]},
        sd_object={"secret": "v1"},
        sd_array={"allowed_merchants": ["m1", "m2", "m3"]},
        decoys=4,
    )
    return sk, pub, jwt, discs


def test_roundtrip_sign_and_verify():
    sk, pub, jwt, _ = _issue()
    parsed = S.SDJWT.parse(jwt.serialize())
    assert S.verify_jws(parsed.issuer_jwt, pub)


def test_disclose_reveals_all_by_default():
    sk, pub, jwt, _ = _issue()
    proc, ok = S.disclose(S.SDJWT.parse(jwt.serialize()))
    assert ok
    assert proc["secret"] == "v1"
    assert set(proc["allowed_merchants"]) == {"m1", "m2", "m3"}


def test_selective_presentation():
    sk, pub, jwt, discs = _issue()
    m2 = [d for d in discs if d.value == "m2"][0]
    sub = S.present(S.SDJWT.parse(jwt.serialize()), {m2.digest})
    proc, ok = S.disclose(sub)
    assert ok and proc["allowed_merchants"] == ["m2"]


def test_forged_disclosure_fails():
    sk, pub, jwt, _ = _issue()
    bad = S.SDJWT(issuer_jwt=jwt.issuer_jwt, disclosures=jwt.disclosures + ["Zm9vYmFy"])
    _, ok = S.disclose(bad)
    assert not ok


def test_kb_jwt_binding():
    sk, pub, jwt, _ = _issue()
    parsed = S.SDJWT.parse(jwt.serialize())
    kb = S.make_kb_jwt(sk, nonce="n1", aud="v", iat=1, sd_hash=parsed.sd_hash())
    jwk = S.jwk_from_public(pub)
    assert S.verify_kb_jwt(kb, jwk, expected_nonce="n1", expected_sd_hash=parsed.sd_hash())
    assert not S.verify_kb_jwt(kb, jwk, expected_nonce="wrong", expected_sd_hash=parsed.sd_hash())
    assert not S.verify_kb_jwt(kb, jwk, expected_nonce="n1", expected_sd_hash="wrong")


def test_issuer_hash_stable_under_disclosure():
    sk, pub, jwt, discs = _issue()
    full = S.SDJWT.parse(jwt.serialize())
    m2 = [d for d in discs if d.value == "m2"][0]
    sub = S.present(full, {m2.digest})
    # sd_hash changes with disclosure; issuer_hash does not.
    assert full.sd_hash() != sub.sd_hash()
    assert full.issuer_hash() == sub.issuer_hash()
