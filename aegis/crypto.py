"""Cryptographic primitives: Ed25519 signing/verification, canonical
serialization, SHA-256 hashing, and a DID key registry.

All decision envelopes, ledger entries, and step-up quorum contributions are
Ed25519-signed. Canonicalization is deterministic (sorted keys, tight
separators) so the same logical object always produces the same bytes — a hard
requirement for hash-chaining and audit replay.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic UTF-8 JSON: sorted keys, no insignificant whitespace.

    ``default=str`` lets datetimes / UUIDs / Decimals serialize predictably.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_object(obj: Any) -> str:
    return sha256_hex(canonical_bytes(obj))


# --- Ed25519 ---------------------------------------------------------------

def generate_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """Return (private_key, public_key_raw_bytes)."""
    sk = Ed25519PrivateKey.generate()
    pub_raw = sk.public_key().public_bytes_raw()
    return sk, pub_raw


def sign(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    """Sign ``payload`` and return a hex signature string."""
    return private_key.sign(payload).hex()


def verify(public_key_raw: bytes, payload: bytes, signature_hex: str) -> bool:
    """Verify a hex signature against raw public-key bytes. Never raises."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(public_key_raw)
        pub.verify(bytes.fromhex(signature_hex), payload)
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass
class KeyRing:
    """DID -> key material. Resolves public keys for verification and, for
    demo/test principals we control, holds private keys for signing.

    In production public keys are resolved via DID documents and private keys
    live in an HSM/KMS — never in application memory. This class is the local
    stand-in for that resolver.
    """

    _pub: dict[str, bytes] = field(default_factory=dict)
    _priv: dict[str, Ed25519PrivateKey] = field(default_factory=dict)

    def create(self, did: str) -> Ed25519PrivateKey:
        """Mint a keypair for a principal we control (demo/test)."""
        sk, pub = generate_keypair()
        self._priv[did] = sk
        self._pub[did] = pub
        return sk

    def register_pub(self, did: str, public_key_raw: bytes) -> None:
        self._pub[did] = public_key_raw

    def public_key(self, did: str) -> bytes | None:
        return self._pub.get(did)

    def private_key(self, did: str) -> Ed25519PrivateKey | None:
        return self._priv.get(did)

    def sign_as(self, did: str, payload: bytes) -> str:
        sk = self._priv.get(did)
        if sk is None:
            raise KeyError(f"no private key held for DID {did!r}")
        return sign(sk, payload)
