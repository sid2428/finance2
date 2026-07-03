"""Open/Closed mandate construction on top of the SD-JWT primitives.

An **open mandate** is an issuer-signed SD-JWT carrying the agent's
proof-of-possession key (``cnf``), the locked ``constraints`` the closed
mandate must satisfy, and selectively-disclosable ``allowed_merchants``.

A **closed mandate** is signed by the agent's ``cnf`` key and binds the open
mandate to a concrete transaction via ``sd_hash`` (-> open) and
``checkout_hash`` (-> merchant checkout), with a Key-Binding JWT proving
possession against a verifier nonce.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..crypto import generate_keypair
from . import sdjwt as S
from .constraints import CompiledConstraint


@dataclass
class Chain:
    """Everything a verifier / fuzzer needs for one open->closed delegation."""

    open_m: S.SDJWT
    closed_m: S.SDJWT
    issuer_pub: bytes
    agent_key: Ed25519PrivateKey
    agent_jwk: dict
    checkout_jwt: str
    nonce: str
    aud: str
    open_iat: int
    closed_iat: int = 0
    merchant_disclosures: list = field(default_factory=list)

    def as_list(self) -> list[str]:
        return [self.open_m.serialize(), self.closed_m.serialize()]


def make_checkout_jwt(merchant_key: Ed25519PrivateKey, checkout: dict) -> str:
    return S.sign_jws({"typ": "checkout+jwt"}, checkout, merchant_key)


def build_open_mandate(
    issuer_key: Ed25519PrivateKey,
    *,
    iss: str,
    open_iat: int,
    agent_jwk: dict,
    constraints: list[CompiledConstraint],
    allowed_merchants: list[str],
    decoys: int = 0,
    merchant_decoys: int = 0,
) -> tuple[S.SDJWT, list[S.Disclosure]]:
    claims = {
        "iss": iss,
        "iat": open_iat,
        "cnf": {"jwk": agent_jwk},
        "constraints": [c.canonical for c in constraints],
    }
    return S.issue_sd_jwt(
        issuer_key,
        claims=claims,
        sd_array={"allowed_merchants": allowed_merchants},
        sd_array_decoys={"allowed_merchants": merchant_decoys},
        decoys=decoys,
        header={"typ": "open-mandate+sd-jwt"},
    )


def build_closed_mandate(
    agent_key: Ed25519PrivateKey,
    *,
    iss: str,
    open_mandate: S.SDJWT,
    open_iat: int,
    constraints_canonical: list[dict],
    checkout_jwt: str,
    payment_amount: dict,
    payee: dict,
    line_items: list[dict],
    closed_iat: int,
    nonce: str,
    aud: str,
) -> S.SDJWT:
    payload = {
        "iss": iss,
        "iat": closed_iat,
        "open_iat": open_iat,
        "constraints": constraints_canonical,      # copied unchanged from open
        "sd_hash": open_mandate.issuer_hash(),      # binds -> exact open mandate (stable under disclosure)
        "checkout_hash": S.sha256_b64u(checkout_jwt.encode("ascii")),
        "payment_amount": payment_amount,
        "payee": payee,
        "line_items": line_items,
    }
    closed = S.SDJWT(
        issuer_jwt=S.sign_jws({"typ": "closed-mandate+sd-jwt"}, payload, agent_key)
    )
    closed.kb_jwt = S.make_kb_jwt(
        agent_key, nonce=nonce, aud=aud, iat=closed_iat, sd_hash=closed.sd_hash()
    )
    return closed


def seal_closed(
    payload: dict, key: Ed25519PrivateKey, *, nonce: str, aud: str, closed_iat: int
) -> S.SDJWT:
    """(Re)sign a closed-mandate payload and attach a fresh KB-JWT. Used by the
    fuzzer to model a compromised agent that re-signs a mutated mandate."""
    closed = S.SDJWT(issuer_jwt=S.sign_jws({"typ": "closed-mandate+sd-jwt"}, payload, key))
    closed.kb_jwt = S.make_kb_jwt(
        key, nonce=nonce, aud=aud, iat=closed_iat, sd_hash=closed.sd_hash()
    )
    return closed


def build_chain(
    *,
    constraints: list[CompiledConstraint],
    allowed_merchants: list[str],
    cart_merchant: dict,
    payment_amount: dict,
    line_items: list[dict],
    open_iat: int = 1_000_000,
    closed_iat: int = 1_000_100,
    nonce: str = "nonce-xyz",
    aud: str = "did:verifier:aegis",
    decoys: int = 0,
    merchant_decoys: int = 0,
    checkout: Optional[dict] = None,
) -> Chain:
    """Build a fully-valid open->closed chain for tests / demo / fuzzer baseline."""
    issuer_key, issuer_pub = generate_keypair()
    agent_key, agent_pub = generate_keypair()
    merchant_key, _ = generate_keypair()
    agent_jwk = S.jwk_from_public(agent_pub)

    open_m, discs = build_open_mandate(
        issuer_key, iss="did:issuer:trusted-surface", open_iat=open_iat,
        agent_jwk=agent_jwk, constraints=constraints,
        allowed_merchants=allowed_merchants, decoys=decoys,
        merchant_decoys=merchant_decoys,
    )

    checkout = checkout or {
        "merchant": cart_merchant, "line_items": line_items,
        "amount": payment_amount, "iat": closed_iat,
    }
    checkout_jwt = make_checkout_jwt(merchant_key, checkout)

    closed_m = build_closed_mandate(
        agent_key, iss="did:agent:shopping", open_mandate=open_m, open_iat=open_iat,
        constraints_canonical=[c.canonical for c in constraints],
        checkout_jwt=checkout_jwt, payment_amount=payment_amount,
        payee=cart_merchant, line_items=line_items, closed_iat=closed_iat,
        nonce=nonce, aud=aud,
    )

    return Chain(
        open_m=open_m, closed_m=closed_m, issuer_pub=issuer_pub,
        agent_key=agent_key, agent_jwk=agent_jwk, checkout_jwt=checkout_jwt,
        nonce=nonce, aud=aud, open_iat=open_iat, closed_iat=closed_iat,
        merchant_disclosures=discs,
    )
