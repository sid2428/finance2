"""Provider-neutral settlement adapters. Money can only move through
``settle()``, which physically refuses any envelope that is not a
signature-valid ALLOW (or a STEP_UP whose quorum has been satisfied)."""

from .settlement import (
    SettlementAdapter,
    SettlementResult,
    SimulatorAdapter,
    SettlementRefused,
    settle,
)

__all__ = [
    "SettlementAdapter",
    "SettlementResult",
    "SimulatorAdapter",
    "SettlementRefused",
    "settle",
]
