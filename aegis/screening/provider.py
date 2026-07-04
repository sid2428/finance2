"""The screening-provider contract (WS2).

Exactly the semantics the pipeline needs: an entity name in; scored candidate
matches with list provenance out. Everything else (transport, matching
algorithm, dataset) is the provider's business, so the pipeline runs
unmodified against the offline fixtures, a self-hosted yente instance, or a
Moov Watchman deployment — selected by configuration.

Determinism invariant: the pipeline records every provider response (and the
list provenance) into the decision's replay archive at decision time.
``RecordedScreeningProvider`` serves those recorded values back during audit
replay, so replay NEVER makes a live provider call.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Optional, Protocol, runtime_checkable


class ScreeningUnavailable(RuntimeError):
    """The screening provider cannot answer. The pipeline fails CLOSED on
    this — a decision is never produced without a completed screen."""


@dataclass(frozen=True)
class ScreeningCandidate:
    """One scored watchlist match. ``score`` is 0..1; the pipeline applies its
    own acceptance threshold uniformly across providers."""

    entity_id: str
    name: str
    score: float
    list_name: str              # e.g. "OFAC-SDN", "eu_fsf", "PEP"
    is_pep: bool = False
    kind: str = "entity"

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ListProvenance:
    """Which list data produced a screen — recorded in every verdict.

    ``generated_at`` (epoch seconds) is when the dataset was generated or last
    refreshed; the pipeline enforces the freshness bound against it. ``None``
    means static fixture data with no refresh cycle — permitted only for the
    offline demo provider and exempt from the freshness bound (documented
    demo-mode caveat, not a production posture).
    """

    provider: str
    dataset: str
    dataset_version: str
    generated_at: Optional[float] = None

    def as_dict(self) -> dict:
        return asdict(self)


@runtime_checkable
class ScreeningProvider(Protocol):
    name: str

    def screen(self, name: str) -> list[ScreeningCandidate]: ...
    def provenance(self) -> ListProvenance: ...


class RecordedScreeningProvider:
    """Replays the provider responses captured in a decision's archive.

    Missing recordings raise ``ScreeningUnavailable`` (fail closed) rather
    than silently returning "no match" — an absent recording reproduces the
    original unavailable outcome, never a cleaner one.
    """

    name = "recorded"

    def __init__(self, snapshot: Optional[dict]):
        snapshot = snapshot or {}
        self._provenance = snapshot.get("provenance")
        self._queries: dict = snapshot.get("queries") or {}
        self._error: Optional[str] = snapshot.get("error")

    def provenance(self) -> ListProvenance:
        if self._provenance is None:
            raise ScreeningUnavailable(
                self._error or "no screening provenance recorded for this decision"
            )
        return ListProvenance(**self._provenance)

    def screen(self, name: str) -> list[ScreeningCandidate]:
        if name in self._queries:
            return [ScreeningCandidate(**c) for c in self._queries[name]]
        raise ScreeningUnavailable(
            self._error or f"no recorded screening responses for {name!r}"
        )


def default_http(method: str, url: str, payload: Optional[dict] = None,
                 timeout: float = 5.0) -> tuple[int, dict]:
    """Minimal JSON-over-HTTP transport (stdlib only). Providers accept an
    ``http`` callable with this signature so tests inject fakes."""
    req = urllib.request.Request(
        url,
        method=method,
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise ScreeningUnavailable(f"{method} {url}: {exc}") from exc
