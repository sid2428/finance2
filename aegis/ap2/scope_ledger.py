"""Feature 3 — Open-Mandate Scope Ledger (receipt-driven double-spend prevention).

An open mandate is *reusable* authority, which makes it a double-spend risk: a
prompt-injected agent may try to bind the same open mandate to several
overlapping closed mandates before any receipt returns. The scope ledger is an
integrity-protected state machine — held OUTSIDE the agent's LLM context — that
tracks remaining authority per open mandate and monotonically reduces it on each
Verifier-signed Mandate Receipt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import sdjwt as S


class DoubleSpend(RuntimeError):
    pass


class ScopeExceeded(RuntimeError):
    pass


class ReceiptInvalid(RuntimeError):
    pass


# --- Mandate Receipt (Verifier-signed JWT) --------------------------------

@dataclass
class MandateReceipt:
    reference: str            # sd_hash of the final closed mandate
    result: str               # "success" | "error"
    amount_usd: float
    issued_at: int
    mandate_id: str
    raw_jwt: str = ""

    @staticmethod
    def issue(verifier_key: Ed25519PrivateKey, *, reference: str, result: str,
              amount_usd: float, issued_at: int, mandate_id: str) -> "MandateReceipt":
        payload = {"reference": reference, "result": result,
                   "amount_usd": amount_usd, "issued_at": issued_at,
                   "mandate_id": mandate_id}
        jwt = S.sign_jws({"typ": "mandate-receipt+jwt"}, payload, verifier_key)
        return MandateReceipt(raw_jwt=jwt, **payload)

    @staticmethod
    def parse(jwt: str) -> "MandateReceipt":
        payload = S.parse_jws(jwt)[1]
        return MandateReceipt(raw_jwt=jwt, **{k: payload[k] for k in
                              ("reference", "result", "amount_usd", "issued_at", "mandate_id")})

    def verify(self, verifier_pub: bytes) -> bool:
        return bool(self.raw_jwt) and S.verify_jws(self.raw_jwt, verifier_pub)


@dataclass
class OpenMandateScope:
    mandate_id: str
    remaining_count: int
    remaining_value_usd: float
    consumed_hashes: set[str] = field(default_factory=set)
    outstanding: set[str] = field(default_factory=set)


@dataclass
class Reservation:
    mandate_id: str
    sd_hash: str


class MemoryScopeStore:
    """Default demo scope store — nothing survives the process (by design).
    ``aegis.storage.SqliteScopeStore`` is the durable implementation."""

    def __init__(self) -> None:
        self._scopes: dict[str, OpenMandateScope] = {}

    def get(self, mandate_id: str) -> OpenMandateScope | None:
        return self._scopes.get(mandate_id)

    def put(self, scope: OpenMandateScope) -> None:
        self._scopes[scope.mandate_id] = scope


class ScopeLedger:
    """Tamper-evident scope state the agent's LLM cannot write to.

    All mutations flow through this state machine and are written back to the
    store, so with a durable store no reservation or receipted reduction is
    lost across restarts."""

    def __init__(self, verifier_pub: bytes, store=None):
        self._verifier_pub = verifier_pub
        self._store = store if store is not None else MemoryScopeStore()

    def open_scope(self, mandate_id: str, count: int, value_usd: float) -> OpenMandateScope:
        existing = self._store.get(mandate_id)
        if existing is not None:
            return existing          # never silently reset live authority
        scope = OpenMandateScope(mandate_id, count, value_usd)
        self._store.put(scope)
        return scope

    def scope(self, mandate_id: str) -> OpenMandateScope:
        scope = self._store.get(mandate_id)
        if scope is None:
            raise KeyError(f"no scope for open mandate {mandate_id!r}")
        return scope

    def reserve(self, scope: OpenMandateScope, closed_sd_hash: str,
                amount_usd: float) -> Reservation:
        if closed_sd_hash in scope.consumed_hashes:
            raise DoubleSpend("closed mandate already settled")
        # Any outstanding (unreceipted) reservation blocks a new draw on the
        # same open mandate — overlapping spend must await its receipt.
        if scope.outstanding and closed_sd_hash not in scope.outstanding:
            raise DoubleSpend("overlapping closed mandate outstanding — await receipt")
        if closed_sd_hash in scope.outstanding:
            raise DoubleSpend("closed mandate already reserved")
        if scope.remaining_count < 1:
            raise ScopeExceeded("no remaining count authority")
        if amount_usd > scope.remaining_value_usd + 1e-9:
            raise ScopeExceeded("beyond remaining value authority")
        scope.outstanding.add(closed_sd_hash)
        self._store.put(scope)
        return Reservation(scope.mandate_id, closed_sd_hash)

    def apply_receipt(self, scope: OpenMandateScope, receipt: MandateReceipt) -> None:
        if not receipt.verify(self._verifier_pub):
            raise ReceiptInvalid("receipt signature invalid or missing")
        h = receipt.reference
        scope.outstanding.discard(h)
        if receipt.result == "success":
            if h in scope.consumed_hashes:
                self._store.put(scope)  # persist the outstanding release
                return  # idempotent
            scope.consumed_hashes.add(h)
            scope.remaining_count -= 1
            scope.remaining_value_usd -= receipt.amount_usd   # monotonic reduction
        # result == "error": authority released (outstanding discarded), no leak
        self._store.put(scope)
