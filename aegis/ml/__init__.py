"""Peripheral ML: intent-drift embedder and the dynamic risk scorer.

Per the design invariant, ML lives on the *periphery* — it may only raise risk
or add evidence, never lift a deterministic hard block. Each model carries a
version string so its contribution is logged for SR 11-7 model-risk audit.

These are deterministic stand-ins for the ONNX-served production models; being
deterministic actually strengthens audit replay.
"""

from .embedder import DriftEmbedder, default_embedder
from .risk_model import RiskModel, default_risk_model

__all__ = ["DriftEmbedder", "default_embedder", "RiskModel", "default_risk_model"]
