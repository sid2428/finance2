"""Append-only, hash-chained, Ed25519-signed decision ledger.

Each appended envelope carries ``prev_envelope_hash`` (the previous entry's
``this_hash``), making after-the-fact tampering detectable — altering any
historical envelope breaks the chain at the next verification/replay. The
in-memory list is the PostgreSQL ``decision_ledger`` table analogue; an optional
JSONL sink mirrors the WORM object-store anchoring.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..crypto import canonical_bytes, hash_object, sha256_hex, sign, verify
from ..models import DecisionEnvelope

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


class DecisionLedger:
    def __init__(
        self,
        signing_key: Ed25519PrivateKey,
        signing_pub: bytes,
        persist_path: Optional[Path | str] = None,
    ):
        self._signing_key = signing_key
        self._signing_pub = signing_pub
        self._entries: list[DecisionEnvelope] = []
        self._by_id: dict[str, DecisionEnvelope] = {}
        self._archive: dict[str, EvaluationArchive] = {}
        self._persist_path = Path(persist_path) if persist_path else None

    @property
    def signing_pub(self) -> bytes:
        return self._signing_pub

    def head_hash(self) -> str:
        return self._entries[-1].this_hash if self._entries else GENESIS_HASH

    def append(
        self,
        envelope: DecisionEnvelope,
        archive: Optional[EvaluationArchive] = None,
    ) -> DecisionEnvelope:
        """Chain, sign, hash, and append. Mutates and returns the envelope."""
        envelope.prev_envelope_hash = self.head_hash()
        envelope.ts = envelope.ts  # keep as-set
        # Sign the canonical payload (everything except signature + this_hash).
        envelope.signature = sign(self._signing_key, envelope.signing_payload())
        # this_hash covers the fully-signed envelope (incl. signature + prev).
        envelope.this_hash = sha256_hex(
            canonical_bytes(envelope.model_dump(mode="json", exclude={"this_hash"}))
        )

        self._entries.append(envelope)
        self._by_id[envelope.decision_id] = envelope
        if archive is not None:
            self._archive[envelope.decision_id] = archive
        self._persist(envelope)
        return envelope

    def get(self, decision_id: str) -> Optional[DecisionEnvelope]:
        return self._by_id.get(decision_id)

    def archive_for(self, decision_id: str) -> Optional[EvaluationArchive]:
        return self._archive.get(decision_id)

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

    def _persist(self, env: DecisionEnvelope) -> None:
        if self._persist_path is None:
            return
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        with self._persist_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(env.model_dump(mode="json"), default=str) + "\n")
