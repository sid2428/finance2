"""OpenSanctions/yente provider (WS2).

Calls a self-hosted `yente <https://github.com/opensanctions/yente>`_ instance
(the OpenSanctions entity-matching API). Provenance comes from the yente
catalog: dataset version plus its last-export timestamp, which the pipeline
enforces the freshness bound against.

LICENSING — read before deploying: the OpenSanctions dataset is free for
non-commercial use; **commercial use requires a license from OpenSanctions**
(https://www.opensanctions.org/licensing/). AEGIS integrates via the provider
seam precisely so adopters can choose yente, Moov Watchman (Apache-2.0 data
pipeline), or their own vendor feed per their licensing situation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional

from .provider import (
    ListProvenance,
    ScreeningCandidate,
    ScreeningUnavailable,
    default_http,
)


def _parse_ts(value) -> Optional[float]:
    if value is None:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


class YenteProvider:
    name = "yente"

    def __init__(self, base_url: str, dataset: str = "default",
                 timeout: float = 5.0, http: Optional[Callable] = None):
        self._base = base_url.rstrip("/")
        self._dataset = dataset
        self._timeout = timeout
        self._http = http or default_http

    def provenance(self) -> ListProvenance:
        status, body = self._call("GET", f"{self._base}/catalog")
        for ds in body.get("datasets", []):
            if ds.get("name") == self._dataset:
                return ListProvenance(
                    provider=self.name,
                    dataset=self._dataset,
                    dataset_version=str(ds.get("version", "unknown")),
                    generated_at=_parse_ts(
                        ds.get("last_export") or ds.get("last_change")
                        or ds.get("updated_at")
                    ),
                )
        raise ScreeningUnavailable(
            f"dataset {self._dataset!r} not present in yente catalog"
        )

    def screen(self, name: str) -> list[ScreeningCandidate]:
        if not name:
            return []
        payload = {
            "queries": {
                "q": {"schema": "Thing", "properties": {"name": [name]}}
            }
        }
        status, body = self._call(
            "POST", f"{self._base}/match/{self._dataset}", payload
        )
        results = (
            body.get("responses", {}).get("q", {}).get("results", []) or []
        )
        out: list[ScreeningCandidate] = []
        for r in results:
            props = r.get("properties") or {}
            topics = [str(t) for t in (props.get("topics") or [])]
            datasets = r.get("datasets") or []
            out.append(ScreeningCandidate(
                entity_id=str(r.get("id", "")),
                name=str(r.get("caption", "")),
                score=float(r.get("score", 0.0)),
                list_name=str(datasets[0]) if datasets else "opensanctions",
                is_pep=any(t.startswith("role.pep") for t in topics),
                kind=str(r.get("schema", "entity")).lower(),
            ))
        return sorted(out, key=lambda c: c.score, reverse=True)

    def _call(self, method: str, url: str, payload: Optional[dict] = None):
        status, body = self._http(method, url, payload, self._timeout)
        if status != 200:
            raise ScreeningUnavailable(f"{method} {url} -> HTTP {status}")
        return status, body
