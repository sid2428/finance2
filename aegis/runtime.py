"""Wiring: assemble a ready-to-use AEGIS system (keyring, ledger, orchestrator,
settlement adapter, stores) behind one container."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .adapters import SimulatorAdapter
from .crypto import KeyRing, generate_keypair
from .ledger import DecisionLedger
from .pipeline import Orchestrator
from .state import StepUpStore, VelocityStore


@dataclass
class AegisSystem:
    keyring: KeyRing
    ledger: DecisionLedger
    orchestrator: Orchestrator
    settlement: SimulatorAdapter
    velocity: VelocityStore
    stepup: StepUpStore


def build_system(persist_path: Optional[Path | str] = None) -> AegisSystem:
    keyring = KeyRing()
    signing_key, signing_pub = generate_keypair()
    ledger = DecisionLedger(signing_key, signing_pub, persist_path=persist_path)

    velocity = VelocityStore()
    stepup = StepUpStore()

    orchestrator = Orchestrator(
        ledger=ledger,
        keyring=keyring,
        velocity_store=velocity,
        stepup_store=stepup,
    )
    return AegisSystem(
        keyring=keyring,
        ledger=ledger,
        orchestrator=orchestrator,
        settlement=SimulatorAdapter(),
        velocity=velocity,
        stepup=stepup,
    )
