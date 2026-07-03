"""Settlement adapters and the single authority gate to money movement.

Design invariant: a settlement adapter cannot be invoked without a valid signed
decision envelope authorizing settlement. ``settle()`` enforces this — it
verifies the envelope's Ed25519 signature against the ledger's signing key and
refuses anything that is not an ALLOW (or a STEP_UP whose quorum is satisfied).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Protocol

from ..ledger import DecisionLedger
from ..models import DecisionEnvelope, PaymentMandate, Verdict


class SettlementRefused(RuntimeError):
    """Raised when settlement is attempted without valid authorization."""


@dataclass
class SettlementResult:
    settled: bool
    rail: str
    settlement_ref: str
    decision_id: str


class SettlementAdapter(Protocol):
    rail: str

    def submit(self, payment: PaymentMandate) -> str: ...


class SimulatorAdapter:
    """In-memory settlement rail for tests/demo. Records every settled payment."""

    rail = "sim"

    def __init__(self) -> None:
        self.settled: list[str] = []

    def submit(self, payment: PaymentMandate) -> str:
        ref = f"sim-{uuid.uuid4().hex[:12]}"
        self.settled.append(ref)
        return ref


def settle(
    envelope: DecisionEnvelope,
    payment: PaymentMandate,
    adapter: SettlementAdapter,
    ledger: DecisionLedger,
    quorum_satisfied: bool = False,
) -> SettlementResult:
    """The ONLY path to settlement. Fail-closed on any authorization gap."""
    # 1. The envelope must be authentic (signed by the ledger key).
    if not ledger.verify_signature(envelope):
        raise SettlementRefused("decision envelope signature invalid")

    # 2. The envelope must actually authorize this payment's mandate chain.
    if envelope.mandate_id != payment.mandate_id:
        raise SettlementRefused("envelope does not authorize this payment mandate")

    # 3. Verdict gate.
    if envelope.verdict == Verdict.ALLOW:
        pass
    elif envelope.verdict == Verdict.STEP_UP:
        if not quorum_satisfied:
            raise SettlementRefused("STEP_UP verdict but quorum not satisfied")
    else:  # BLOCK or anything else
        raise SettlementRefused(f"verdict {envelope.verdict} does not permit settlement")

    ref = adapter.submit(payment)
    return SettlementResult(
        settled=True,
        rail=adapter.rail,
        settlement_ref=ref,
        decision_id=envelope.decision_id,
    )
