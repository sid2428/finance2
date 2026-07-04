"""Pluggable sanctions/PEP screening data plane (WS2).

The pipeline consumes the ``ScreeningProvider`` contract; which data answers
is configuration:

  * ``offline`` (default) — built-in matcher over bundled demo fixtures;
    zero infrastructure, static data (exempt from the freshness bound).
  * ``yente``    — self-hosted OpenSanctions entity-matching API
    (mind OpenSanctions' commercial licensing; see ``yente.py``).
  * ``watchman`` — Moov Watchman OFAC/watchlist screening (Apache-2.0).

Freshness contract: every verdict records the list provenance (provider,
dataset, version, generated_at) in its signed envelope; a dataset older than
``config.SCREENING_MAX_LIST_AGE_SECONDS`` FAILS CLOSED with reason code
``AGENT.SANC.STALE_LIST`` — AEGIS never silently screens against old data.
Provider outage fails closed with ``AGENT.SANC.PROVIDER_UNAVAILABLE``.
"""

from __future__ import annotations

import os
from typing import Mapping, Optional

from .offline import OfflineFixtureProvider
from .provider import (
    ListProvenance,
    RecordedScreeningProvider,
    ScreeningCandidate,
    ScreeningProvider,
    ScreeningUnavailable,
)
from .watchman import WatchmanProvider
from .yente import YenteProvider

__all__ = [
    "ListProvenance",
    "OfflineFixtureProvider",
    "RecordedScreeningProvider",
    "ScreeningCandidate",
    "ScreeningProvider",
    "ScreeningUnavailable",
    "WatchmanProvider",
    "YenteProvider",
    "provider_from_env",
]


def provider_from_env(env: Optional[Mapping[str, str]] = None) -> ScreeningProvider:
    """Build the configured provider. ``AEGIS_SCREENING_PROVIDER`` selects
    offline (default) / yente / watchman; URL env vars point at deployments."""
    env = env if env is not None else os.environ
    kind = env.get("AEGIS_SCREENING_PROVIDER", "offline").strip().lower()
    if kind in ("offline", "fixture", ""):
        return OfflineFixtureProvider()
    if kind == "yente":
        return YenteProvider(
            env.get("AEGIS_YENTE_URL", "http://localhost:8000"),
            dataset=env.get("AEGIS_YENTE_DATASET", "default"),
        )
    if kind == "watchman":
        return WatchmanProvider(
            env.get("AEGIS_WATCHMAN_URL", "http://localhost:8084")
        )
    raise ValueError(f"unknown screening provider {kind!r}")
