"""Durable storage backends (WS3).

Everything here is deliberately boring and embeddable: SQLite via the standard
library, no external infrastructure, so the zero-infrastructure promise holds
while state survives process restarts. Server-grade backends (PostgreSQL,
Redis) implement the same interfaces as configuration for adopters.

Backends:
  * ``SqliteLedgerBackend``  — append-only WORM decision ledger (INSERT-only
    DAL + UPDATE/DELETE-rejecting triggers; chain verified on startup).
  * ``SqliteVelocityStore``  — durable sliding-window counters.
  * ``SqliteScopeStore``     — durable open-mandate scope state (AP2 track).
  * ``PersistentKeyRing``    — DID public-key directory that survives restarts.
"""

from .ledger_backend import (
    LedgerBackend,
    LedgerCorruptionError,
    MemoryLedgerBackend,
    SqliteLedgerBackend,
)
from .velocity_sqlite import SqliteVelocityStore
from .scope_sqlite import SqliteScopeStore
from .keys import PersistentKeyRing, load_or_create_signing_key

__all__ = [
    "LedgerBackend",
    "LedgerCorruptionError",
    "MemoryLedgerBackend",
    "SqliteLedgerBackend",
    "SqliteVelocityStore",
    "SqliteScopeStore",
    "PersistentKeyRing",
    "load_or_create_signing_key",
]
