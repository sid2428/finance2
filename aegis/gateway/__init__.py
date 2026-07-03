"""AEGIS gateway: FastAPI app + AP2 mandate signature verification."""

from .verify import verify_bundle, sign_mandate

__all__ = ["verify_bundle", "sign_mandate"]
