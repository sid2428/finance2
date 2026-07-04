"""Append-only, hash-chained, Ed25519-signed decision ledger.

Each appended envelope carries ``prev_envelope_hash`` (the previous entry's
``this_hash``), making after-the-fact tampering detectable — altering any
historical envelope breaks the chain at the next verification/replay.

Persistence is a seam (``LedgerBackend``): the in-memory backend is the
zero-infrastructure demo default; ``SqliteLedgerBackend`` is the durable WORM
store. Opening a durable backend **re-verifies the entire chain from genesis
and refuses to serve if verification fails** — a compliance evidence store
must fail closed on its own corruption.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..crypto import canonical_bytes, sha256_hex, sign, verify
from ..models import DecisionEnvelope
from ..storage.ledger_backend import (
    LedgerBackend,
    LedgerCorruptionError,
    MemoryLedgerBackend,
)

GENESIS_HASH = "0" * 64


@dataclass
class EvaluationArchive:
    """Inputs needed to deterministically replay a decision. Not part of the
    signed envelope, but retained alongside it (as an audit system would keep
    the original request)."""

    bundle: dict            # MandateBundle JSON
    now: float
    controls: dict
    velocity_snapshot: dict
    # Recorded screening responses + provenance (WS2), so replay reuses the
    # exact provider answers instead of making a live call. Defaulted for
    # archives written before this field existed.
    screening_snapshot: dict = field(default_factory=dict)


class DecisionLedger:
    def __init__(
        self,
        signing_key: Ed25519PrivateKey,
        signing_pub: bytes,
        backend: Optional[LedgerBackend] = None,
    ):
        self._signing_key = signing_key
        self._signing_pub = signing_pub
        self._backend = backend if backend is not None else MemoryLedgerBackend()
        self._entries: list[DecisionEnvelope] = []
        self._by_id: dict[str, DecisionEnvelope] = {}

        # Key continuity: the chain is bound to one signing key. Reopening an
        # existing store with a different key is refused.
        stored_pub = self._backend.init_meta("signing_pub_hex", signing_pub.hex())
        if stored_pub != signing_pub.hex():
            raise LedgerCorruptionError(
                "ledger store was created with a different signing key "
                f"(stored {stored_pub[:16]}…, supplied {signing_pub.hex()[:16]}…)"
            )

        # Load persisted history and verify it before serving anything.
        for row in self._backend.entries():
            env = DecisionEnvelope.model_validate(row)
            self._entries.append(env)
            self._by_id[env.decision_id] = env
        if self._entries:
            ok, bad_seq = self.verify_chain()
            if not ok:
                raise LedgerCorruptionError(
                    f"ledger chain verification failed at seq {bad_seq}; "
                    "refusing to serve from a corrupt evidence store"
                )

    @property
    def signing_pub(self) -> bytes:
        return self._signing_pub

    def close(self) -> None:
        close = getattr(self._backend, "close", None)
        if callable(close):
            close()

    def head_hash(self) -> str:
        return self._entries[-1].this_hash if self._entries else GENESIS_HASH

    def append(
        self,
        envelope: DecisionEnvelope,
        archive: Optional[EvaluationArchive] = None,
    ) -> DecisionEnvelope:
        """Chain, sign, hash, and append. Mutates and returns the envelope."""
        envelope.prev_envelope_hash = self.head_hash()
        # Sign the canonical payload (everything except signature + this_hash).
        envelope.signature = sign(self._signing_key, envelope.signing_payload())
        # this_hash covers the fully-signed envelope (incl. signature + prev).
        envelope.this_hash = sha256_hex(
            canonical_bytes(envelope.model_dump(mode="json", exclude={"this_hash"}))
        )

        self._entries.append(envelope)
        self._by_id[envelope.decision_id] = envelope
        self._backend.append(
            envelope.decision_id,
            envelope.model_dump(mode="json"),
            archive.__dict__ if archive is not None else None,
        )
        return envelope

    def get(self, decision_id: str) -> Optional[DecisionEnvelope]:
        return self._by_id.get(decision_id)

    def archive_for(self, decision_id: str) -> Optional[EvaluationArchive]:
        raw = self._backend.archive_for(decision_id)
        return EvaluationArchive(**raw) if raw is not None else None

    def all(self) -> list[DecisionEnvelope]:
        return list(self._entries)

    # -- integrity -------------------------------------------------------
    def verify_signature(self, env: DecisionEnvelope) -> bool:
        return verify(self._signing_pub, env.signing_payload(), env.signature)

    def verify_chain(self) -> tuple[bool, Optional[int]]:
        """Verify signatures + hash linkage. Returns (ok, first_bad_seq)."""
        prev = GENESIS_HASH
        for i, env in enumerate(self._entries):
            if env.prev_envelope_hash != prev:
                return (False, i)
            if not self.verify_signature(env):
                return (False, i)
            recomputed = sha256_hex(
                canonical_bytes(env.model_dump(mode="json", exclude={"this_hash"}))
            )
            if recomputed != env.this_hash:
                return (False, i)
            prev = env.this_hash
        return (True, None)
