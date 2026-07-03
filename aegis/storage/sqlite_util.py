"""Shared SQLite plumbing: WAL-mode connections safe for the threaded gateway."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path


def connect(path: Path | str) -> sqlite3.Connection:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")   # durability over speed: this is evidence
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


class SqliteBase:
    """Connection + lock holder. Subclasses do all access under ``self._lock``."""

    def __init__(self, path: Path | str):
        self._path = Path(path)
        self._conn = connect(self._path)
        self._lock = threading.Lock()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
