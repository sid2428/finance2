"""Wiring: assemble a ready-to-use AEGIS system (keyring, ledger, orchestrator,
settlement adapter, stores) behind one container.

Two modes, one code path (WS3):

* **Demo mode** (``data_dir=None``): everything in memory, fresh keys — the
  zero-infrastructure default for tests and demos. Nothing survives exit,
  by design.
* **Durable mode** (``data_dir=...``): SQLite-backed WORM decision ledger
  (chain re-verified on open; refuses to serve on corruption), durable
  velocity counters and open-mandate scope state, persistent DID directory,
  and an on-disk ledger signing key (demo-grade custody — see
  ``aegis/storage/keys.py``; replaced by the WS8 keystore abstraction).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .adapters import SimulatorAdapter
from .ap2.scope_ledger import MemoryScopeStore
from .crypto import KeyRing, generate_keypair
from .ledger import DecisionLedger
from .pipeline import Orchestrator
from .screening import ScreeningProvider
from .state import StepUpStore, VelocityStore
from .storage import (
    PersistentKeyRing,
    SqliteLedgerBackend,
    SqliteScopeStore,
    SqliteVelocityStore,
    load_or_create_signing_key,
)

LEDGER_KEY_FILE = "ledger_signing.key"
DB_FILE = "aegis.db"


@dataclass
class AegisSystem:
    keyring: KeyRing
    ledger: DecisionLedger
    orchestrator: Orchestrator
    settlement: SimulatorAdapter
    velocity: object            # VelocityStore | SqliteVelocityStore
    stepup: StepUpStore
    scope_store: object         # MemoryScopeStore | SqliteScopeStore
    data_dir: Optional[Path] = None

    def close(self) -> None:
        """Release durable-store handles (SQLite files stay locked on Windows
        until closed). Safe to call in demo mode — memory stores no-op."""
        for obj in (self.ledger, self.velocity, self.scope_store, self.keyring):
            close = getattr(obj, "close", None)
            if callable(close):
                close()


def build_system(data_dir: Optional[Path | str] = None,
                 screening: Optional[ScreeningProvider] = None) -> AegisSystem:
    if data_dir is None:
        keyring = KeyRing()
        signing_key, signing_pub = generate_keypair()
        ledger = DecisionLedger(signing_key, signing_pub)
        velocity: object = VelocityStore()
        scope_store: object = MemoryScopeStore()
        root: Optional[Path] = None
    else:
        root = Path(data_dir)
        db = root / DB_FILE
        signing_key, signing_pub = load_or_create_signing_key(root / LEDGER_KEY_FILE)
        # Opening the durable backend re-verifies the full hash chain and
        # raises LedgerCorruptionError (fail closed) if it does not verify.
        ledger = DecisionLedger(signing_key, signing_pub,
                                backend=SqliteLedgerBackend(db))
        keyring = PersistentKeyRing(db)
        velocity = SqliteVelocityStore(db)
        scope_store = SqliteScopeStore(db)

    stepup = StepUpStore()
    orchestrator = Orchestrator(
        ledger=ledger,
        keyring=keyring,
        velocity_store=velocity,
        stepup_store=stepup,
        screening=screening,
    )
    return AegisSystem(
        keyring=keyring,
        ledger=ledger,
        orchestrator=orchestrator,
        settlement=SimulatorAdapter(),
        velocity=velocity,
        stepup=stepup,
        scope_store=scope_store,
        data_dir=root,
    )
