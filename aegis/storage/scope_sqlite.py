"""Durable open-mandate scope state (AP2 Feature 3 — scope ledger).

Scope state is mutable by design (authority is consumed over time), so unlike
the WORM decision ledger it updates in place — but only through the typed
``ScopeLedger`` state machine; receipts remain the sole path that reduces
authority.
"""

from __future__ import annotations

import json
from typing import Optional

from ..ap2.scope_ledger import OpenMandateScope
from .sqlite_util import SqliteBase

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mandate_scopes (
    mandate_id          TEXT PRIMARY KEY,
    remaining_count     INTEGER NOT NULL,
    remaining_value_usd REAL NOT NULL,
    consumed_hashes     TEXT NOT NULL,   -- JSON array
    outstanding         TEXT NOT NULL    -- JSON array
);
"""


class SqliteScopeStore(SqliteBase):
    def __init__(self, path):
        super().__init__(path)
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def get(self, mandate_id: str) -> Optional[OpenMandateScope]:
        with self._lock:
            row = self._conn.execute(
                "SELECT remaining_count, remaining_value_usd, consumed_hashes, "
                "outstanding FROM mandate_scopes WHERE mandate_id = ?",
                (mandate_id,),
            ).fetchone()
        if row is None:
            return None
        return OpenMandateScope(
            mandate_id=mandate_id,
            remaining_count=int(row[0]),
            remaining_value_usd=float(row[1]),
            consumed_hashes=set(json.loads(row[2])),
            outstanding=set(json.loads(row[3])),
        )

    def put(self, scope: OpenMandateScope) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO mandate_scopes "
                "(mandate_id, remaining_count, remaining_value_usd, "
                " consumed_hashes, outstanding) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(mandate_id) DO UPDATE SET "
                "  remaining_count = excluded.remaining_count, "
                "  remaining_value_usd = excluded.remaining_value_usd, "
                "  consumed_hashes = excluded.consumed_hashes, "
                "  outstanding = excluded.outstanding",
                (
                    scope.mandate_id,
                    scope.remaining_count,
                    scope.remaining_value_usd,
                    json.dumps(sorted(scope.consumed_hashes)),
                    json.dumps(sorted(scope.outstanding)),
                ),
            )
            self._conn.commit()


class MemoryScopeStore:
    """Default demo store."""

    def __init__(self) -> None:
        self._scopes: dict[str, OpenMandateScope] = {}

    def get(self, mandate_id: str) -> Optional[OpenMandateScope]:
        return self._scopes.get(mandate_id)

    def put(self, scope: OpenMandateScope) -> None:
        self._scopes[scope.mandate_id] = scope
