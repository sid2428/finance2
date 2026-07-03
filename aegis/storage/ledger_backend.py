"""Ledger storage backends: the persistence seam under ``DecisionLedger``.

WORM semantics (the design note, made precise):

  * **Append-only.** The data-access layer exposes INSERT and SELECT only —
    there is no update or delete method to call.
  * **Defense in depth.** The SQLite schema installs BEFORE UPDATE / BEFORE
    DELETE triggers that ABORT, so even raw SQL against the file cannot mutate
    history without first dropping the triggers (which startup verification
    then catches, because the hash chain no longer verifies).
  * **Chain verified on startup.** ``DecisionLedger`` re-verifies the full
    hash chain from genesis when it opens a durable backend and REFUSES TO
    SERVE (raises ``LedgerCorruptionError``) if verification fails — fail
    closed, never serve from a corrupt evidence store.
  * **Key continuity.** The ledger's signing public key is recorded in the
    store's metadata on first use; reopening with a different key is refused
    (prevents silent key swaps under an existing chain).
"""

from __future__ import annotations

import json
from typing import Optional, Protocol

from .sqlite_util import SqliteBase


class LedgerCorruptionError(RuntimeError):
    """The durable ledger failed integrity verification — refuse to serve."""


class LedgerBackend(Protocol):
    """Insert-only persistence contract for the decision ledger."""

    def append(self, decision_id: str, envelope: dict,
               archive: Optional[dict]) -> None: ...
    def entries(self) -> list[dict]: ...
    def archive_for(self, decision_id: str) -> Optional[dict]: ...
    def get_meta(self, key: str) -> Optional[str]: ...
    def init_meta(self, key: str, value: str) -> str: ...


class MemoryLedgerBackend:
    """Default demo backend — nothing survives the process (by design)."""

    def __init__(self) -> None:
        self._rows: list[dict] = []
        self._archives: dict[str, dict] = {}
        self._meta: dict[str, str] = {}

    def append(self, decision_id: str, envelope: dict, archive: Optional[dict]) -> None:
        self._rows.append(envelope)
        if archive is not None:
            self._archives[decision_id] = archive

    def entries(self) -> list[dict]:
        return list(self._rows)

    def archive_for(self, decision_id: str) -> Optional[dict]:
        return self._archives.get(decision_id)

    def get_meta(self, key: str) -> Optional[str]:
        return self._meta.get(key)

    def init_meta(self, key: str, value: str) -> str:
        return self._meta.setdefault(key, value)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS decision_ledger (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id TEXT NOT NULL UNIQUE,
    envelope    TEXT NOT NULL,          -- canonical envelope JSON
    archive     TEXT,                   -- replay inputs (EvaluationArchive JSON)
    this_hash   TEXT NOT NULL,
    prev_hash   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- WORM: history is immutable. Mutation attempts abort at the engine level.
CREATE TRIGGER IF NOT EXISTS worm_no_update
    BEFORE UPDATE ON decision_ledger
    BEGIN SELECT RAISE(ABORT, 'WORM ledger: updates are forbidden'); END;
CREATE TRIGGER IF NOT EXISTS worm_no_delete
    BEFORE DELETE ON decision_ledger
    BEGIN SELECT RAISE(ABORT, 'WORM ledger: deletes are forbidden'); END;
CREATE TRIGGER IF NOT EXISTS meta_no_update
    BEFORE UPDATE ON ledger_meta
    BEGIN SELECT RAISE(ABORT, 'ledger_meta: updates are forbidden'); END;
CREATE TRIGGER IF NOT EXISTS meta_no_delete
    BEFORE DELETE ON ledger_meta
    BEGIN SELECT RAISE(ABORT, 'ledger_meta: deletes are forbidden'); END;
"""


class SqliteLedgerBackend(SqliteBase):
    """Durable append-only ledger store (embedded SQLite, WAL, synchronous=FULL)."""

    def __init__(self, path):
        super().__init__(path)
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def append(self, decision_id: str, envelope: dict, archive: Optional[dict]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO decision_ledger "
                "(decision_id, envelope, archive, this_hash, prev_hash) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    decision_id,
                    json.dumps(envelope, default=str),
                    json.dumps(archive, default=str) if archive is not None else None,
                    envelope.get("this_hash", ""),
                    envelope.get("prev_envelope_hash", ""),
                ),
            )
            self._conn.commit()

    def entries(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT envelope FROM decision_ledger ORDER BY seq"
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def archive_for(self, decision_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT archive FROM decision_ledger WHERE decision_id = ?",
                (decision_id,),
            ).fetchone()
        if row is None or row[0] is None:
            return None
        return json.loads(row[0])

    def get_meta(self, key: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM ledger_meta WHERE key = ?", (key,)
            ).fetchone()
        return row[0] if row else None

    def init_meta(self, key: str, value: str) -> str:
        """Set ``key`` if absent; return the stored value either way."""
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO ledger_meta (key, value) VALUES (?, ?)",
                (key, value),
            )
            self._conn.commit()
            return self._conn.execute(
                "SELECT value FROM ledger_meta WHERE key = ?", (key,)
            ).fetchone()[0]
