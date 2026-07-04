"""Key persistence for durable mode.

Two concerns, kept separate:

1. **DID public-key directory** (``PersistentKeyRing``): the DID -> Ed25519
   public-key bindings the gateway verifies mandates against. In production
   these come from DID documents; here they persist in SQLite so that a
   decision recorded yesterday can have its signatures re-verified (and thus
   replayed) today. Private keys held for demo principals are NOT persisted.

2. **Ledger signing key** (``load_or_create_signing_key``): DEMO-GRADE custody.
   The Ed25519 private key that signs decision envelopes is stored as raw
   bytes in a file next to the database. This is explicitly a placeholder for
   the WS8 keystore/HSM abstraction — it exists so the durability guarantees
   (chain continuity across restarts) are real, not to model production key
   custody. The threat model treats this file as compromised-if-host-is.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..crypto import KeyRing
from .sqlite_util import SqliteBase

_SCHEMA = """
CREATE TABLE IF NOT EXISTS did_public_keys (
    did     TEXT PRIMARY KEY,
    pub_hex TEXT NOT NULL
);
"""


class _DidDirectory(SqliteBase):
    def __init__(self, path):
        super().__init__(path)
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def put(self, did: str, pub: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO did_public_keys (did, pub_hex) VALUES (?, ?) "
                "ON CONFLICT(did) DO UPDATE SET pub_hex = excluded.pub_hex",
                (did, pub.hex()),
            )
            self._conn.commit()

    def all(self) -> dict[str, bytes]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT did, pub_hex FROM did_public_keys"
            ).fetchall()
        return {did: bytes.fromhex(h) for did, h in rows}


class PersistentKeyRing(KeyRing):
    """KeyRing whose public-key directory survives restarts."""

    def __init__(self, path: Path | str):
        super().__init__()
        self._dir = _DidDirectory(path)
        for did, pub in self._dir.all().items():
            super().register_pub(did, pub)

    def create(self, did: str):
        sk = super().create(did)
        self._dir.put(did, self.public_key(did))
        return sk

    def register_pub(self, did: str, public_key_raw: bytes) -> None:
        super().register_pub(did, public_key_raw)
        self._dir.put(did, public_key_raw)

    def close(self) -> None:
        self._dir.close()


def load_or_create_signing_key(path: Path | str) -> tuple[Ed25519PrivateKey, bytes]:
    """Load the ledger signing key from ``path`` or mint one. DEMO-GRADE —
    see module docstring; replaced by the keystore interface in WS8."""
    p = Path(path)
    if p.exists():
        sk = Ed25519PrivateKey.from_private_bytes(p.read_bytes())
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
        sk = Ed25519PrivateKey.generate()
        p.write_bytes(sk.private_bytes_raw())
    return sk, sk.public_key().public_bytes_raw()
