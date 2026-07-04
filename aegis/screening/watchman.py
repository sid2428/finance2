"""Moov Watchman provider (WS2).

Calls a `moov-io/watchman <https://github.com/moov-io/watchman>`_ deployment —
Apache-licensed, production-hardened OFAC/global watchlist screening.
Provenance comes from Watchman's ``/downloads`` endpoint (when its lists were
last refreshed); the pipeline enforces the freshness bound against it.
"""

from __future__ import annotations

import urllib.parse
from typing import Callable, Optional

from .provider import (
    ListProvenance,
    ScreeningCandidate,
    ScreeningUnavailable,
    default_http,
)
from .yente import _parse_ts


class WatchmanProvider:
    name = "watchman"

    def __init__(self, base_url: str, timeout: float = 5.0, limit: int = 10,
                 http: Optional[Callable] = None):
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._limit = limit
        self._http = http or default_http

    def provenance(self) -> ListProvenance:
        status, body = self._call("GET", f"{self._base}/downloads?limit=1")
        downloads = body if isinstance(body, list) else body.get("downloads", [])
        if not downloads:
            raise ScreeningUnavailable(
                "watchman reports no completed list downloads"
            )
        latest = downloads[0]
        ts = _parse_ts(latest.get("timestamp") or latest.get("downloadedAt"))
        return ListProvenance(
            provider=self.name,
            dataset="ofac-and-friends",
            dataset_version=str(latest.get("timestamp")
                                or latest.get("downloadedAt") or "unknown"),
            generated_at=ts,
        )

    def screen(self, name: str) -> list[ScreeningCandidate]:
        if not name:
            return []
        q = urllib.parse.quote(name)
        status, body = self._call(
            "GET", f"{self._base}/search?name={q}&limit={self._limit}"
        )
        out: list[ScreeningCandidate] = []
        for sdn in body.get("SDNs") or []:
            out.append(ScreeningCandidate(
                entity_id=str(sdn.get("entityID", "")),
                name=str(sdn.get("sdnName", "")),
                score=float(sdn.get("match", 0.0)),
                list_name="OFAC-SDN",
                is_pep=False,
                kind=str(sdn.get("sdnType") or "entity").lower(),
            ))
        for alt in body.get("altNames") or []:
            out.append(ScreeningCandidate(
                entity_id=str(alt.get("entityID", "")),
                name=str(alt.get("alternateName", "")),
                score=float(alt.get("match", 0.0)),
                list_name="OFAC-SDN-ALT",
                is_pep=False,
                kind="alias",
            ))
        return sorted(out, key=lambda c: c.score, reverse=True)

    def _call(self, method: str, url: str, payload: Optional[dict] = None):
        status, body = self._http(method, url, payload, self._timeout)
        if status != 200:
            raise ScreeningUnavailable(f"{method} {url} -> HTTP {status}")
        return status, body
