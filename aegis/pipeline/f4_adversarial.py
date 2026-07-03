"""Feature 4 — Adversarial Mandate Detector (prompt-injection firewall for
mandate construction).

Detects semantic drift between the signed Intent Mandate (the user's true goal)
and the Cart Mandate (what the agent actually selected), scans the intent's
natural-language field for injection signatures, and checks the cart total /
refund terms against the signed intent constraints.

HIGH severity (injection match or price breach) is a hard block; plain semantic
drift is MEDIUM and only raises risk.
"""

from __future__ import annotations

import re
import unicodedata

from ..config import INTENT_DRIFT_THRESHOLD
from ..ml import DriftEmbedder, default_embedder
from ..models import Severity, Signal
from .context import DecisionContext

STAGE = "f4_adversarial"

# Known prompt-injection signatures. A mandate field is *data*, never
# *instructions* — any of these appearing in it is adversarial.
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous", re.I),
    re.compile(r"disregard\s+(the\s+)?(above|prior)", re.I),
    re.compile(r"system\s*prompt", re.I),
    re.compile(r"you\s+are\s+now", re.I),
    re.compile(r"</?(system|tool|assistant)\b", re.I),
    re.compile(r"\bexecute\b.*\btool\b", re.I),
    re.compile(r"reveal\s+(your\s+)?(instructions|secret|key)", re.I),
]


def _has_hidden_unicode(text: str) -> bool:
    for ch in text:
        cat = unicodedata.category(ch)
        # Format/control chars (zero-width, bidi overrides, etc.).
        if cat in ("Cf", "Cc") and ch not in ("\n", "\r", "\t"):
            return True
    return False


def scan_injection(text: str) -> tuple[bool, list[str]]:
    matched = [p.pattern for p in _INJECTION_PATTERNS if p.search(text)]
    if _has_hidden_unicode(text):
        matched.append("<hidden-unicode>")
    return (len(matched) > 0, matched)


def run(ctx: DecisionContext, embedder: DriftEmbedder | None = None) -> None:
    embedder = embedder or default_embedder()
    ctx.record_model(embedder.name, embedder.version)

    intent = ctx.bundle.intent
    cart = ctx.bundle.cart

    sim = embedder.cosine_similarity(
        intent.natural_language_description, cart.summary_text()
    )
    drift = 1.0 - sim

    injected, patterns = scan_injection(intent.natural_language_description)
    price_breach = (
        intent.max_value_usd is not None and cart.total_usd > intent.max_value_usd
    )

    if injected or price_breach:
        detail_bits = []
        if injected:
            detail_bits.append(f"injection signatures={patterns}")
        if price_breach:
            detail_bits.append(
                f"cart {cart.total_usd:.2f} > intent cap {intent.max_value_usd:.2f}"
            )
        ctx.add_signal(Signal(
            code="AGENT.SEC.INTENT_DRIFT",
            detail=f"HIGH: {'; '.join(detail_bits)} (drift={drift:.2f})",
            severity=Severity.HIGH,
            hard_block=True,
            stage=STAGE,
        ))
        return

    if drift > INTENT_DRIFT_THRESHOLD:
        ctx.add_signal(Signal(
            code="AGENT.SEC.INTENT_DRIFT",
            detail=(
                f"MEDIUM: cart drifted from signed intent "
                f"(cosine drift={drift:.2f} > {INTENT_DRIFT_THRESHOLD})"
            ),
            severity=Severity.MEDIUM,
            hard_block=False,
            risk_delta=30.0,
            stage=STAGE,
        ))
