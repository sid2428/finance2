"""DecisionContext — the immutable-ish world snapshot a decision is a pure
function of, plus the mutable accumulators the pipeline writes into.

The deterministic core requires: ``verdict = f(mandate, world_snapshot,
ruleset_version)``. We pin the ruleset and a hash of the world snapshot at
context-build time so the decision can be replayed byte-for-byte later.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from ..config import RULESET_VERSION
from ..crypto import hash_object
from ..models import MandateBundle, Signal, StepUpChallenge


@dataclass
class ControlEvidence:
    """Attestations of which security controls each party met — drives the
    liability apportionment (Feature 6)."""

    merchant_verified_payment_challenge: bool = True
    user_completed_required_stepup: bool = True
    agent_sdk_pinned_intent_constraints: bool = True
    psp_ran_sanctions_screen: bool = True


@dataclass
class DecisionContext:
    bundle: MandateBundle
    ruleset_version: str = RULESET_VERSION
    controls: ControlEvidence = field(default_factory=ControlEvidence)
    # Deterministic evaluation clock (epoch seconds). Pinned so structuring /
    # velocity windows and step-up TTLs are replayable.
    now: float = field(default_factory=time.time)

    # Accumulators written by stages.
    signals: list[Signal] = field(default_factory=list)
    risk_score: float = 0.0
    models_used: dict[str, str] = field(default_factory=dict)
    stepup: Optional[StepUpChallenge] = None
    sar_draft: Optional[dict] = None
    liability: dict[str, float] = field(default_factory=dict)
    liability_basis: str = ""
    # Prior velocity-window entries read by Feature 3, captured so a later
    # audit replay can reconstruct the exact sliding window deterministically.
    velocity_snapshot: dict = field(default_factory=dict)
    # Screening evidence captured at decision time (WS2): list provenance goes
    # into the signed envelope; the full provider responses go into the replay
    # archive so audit replay never makes a live provider call.
    screening_provenance: Optional[dict] = None
    screening_log: dict = field(default_factory=dict)
    screening_error: Optional[str] = None

    # Pinned snapshot hash (set in __post_init__).
    world_snapshot_hash: str = ""

    def __post_init__(self) -> None:
        snapshot = {
            "bundle": self.bundle.model_dump(mode="json"),
            "ruleset_version": self.ruleset_version,
            "now": self.now,
            "controls": self.controls.__dict__,
        }
        self.world_snapshot_hash = hash_object(snapshot)

    # -- convenience accessors -------------------------------------------
    @property
    def mandate_id(self) -> str:
        return self.bundle.payment.mandate_id

    @property
    def initiator(self) -> str:
        return self.bundle.payment.initiator_agent

    def add_signal(self, signal: Signal) -> None:
        self.signals.append(signal)
        if signal.risk_delta:
            # ML/heuristic signals may only RAISE risk, never lower it.
            self.risk_score = min(100.0, self.risk_score + max(0.0, signal.risk_delta))

    def record_model(self, name: str, version: str) -> None:
        self.models_used[name] = version

    @property
    def has_hard_block(self) -> bool:
        return any(s.hard_block for s in self.signals)
