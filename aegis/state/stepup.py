"""Step-up challenge store (Redis analogue with TTL). Holds open m-of-n quorum
challenges between the initial STEP_UP verdict and quorum satisfaction."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from ..models import StepUpChallenge


@dataclass
class StepUpStore:
    _data: dict[str, StepUpChallenge] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def put(self, challenge: StepUpChallenge) -> None:
        with self._lock:
            self._data[challenge.challenge_id] = challenge

    def get(self, challenge_id: str) -> StepUpChallenge | None:
        with self._lock:
            return self._data.get(challenge_id)

    def delete(self, challenge_id: str) -> None:
        with self._lock:
            self._data.pop(challenge_id, None)

    def reset(self) -> None:
        with self._lock:
            self._data.clear()


_DEFAULT = StepUpStore()


def default_stepup_store() -> StepUpStore:
    return _DEFAULT
