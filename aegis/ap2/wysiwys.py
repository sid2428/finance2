"""Feature 5 — WYSIWYS Intent Integrity Oracle ("What You See Is What You Sign").

AP2 proves a mandate is cryptographically valid, but nothing structurally proves
that what *settles* equals what the user *saw and approved* on the Trusted
Surface. This oracle hashes the exact confirmation payload shown to the user
(amount, merchant name, line-item table) at delegation time, then re-derives it
from the closed mandate at settlement. Any drift is a manipulated-checkout attack
— caught deterministically, even when Feature 4 passes.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import sdjwt as S


@dataclass
class IntegrityResult:
    ok: bool
    code: str = ""
    detail: str = ""

    @staticmethod
    def passed() -> "IntegrityResult":
        return IntegrityResult(ok=True, code="ok")

    @staticmethod
    def fail(code: str, detail: str) -> "IntegrityResult":
        return IntegrityResult(ok=False, code=code, detail=detail)


def _canon_amount(currency: str, value: float) -> dict:
    return {"currency": currency, "value": f"{float(value):.2f}"}


def _canon_line_items(items: list[dict]) -> list[dict]:
    return [
        {"title": li["title"], "qty": int(li["quantity"]), "price": f"{float(li['price']):.2f}"}
        for li in items
    ]


def bind_shown_confirmation(transaction_data: dict) -> str:
    """Hash exactly what the user saw on the Trusted Surface (the WYSIWYS anchor).

    ``transaction_data`` mirrors AP2's ``PaymentDetailsInit`` confirmation:
      { "amount": {"currency","value_usd"}, "merchant_name", "line_items":[...] }
    """
    shown = {
        "amount": _canon_amount(transaction_data["amount"]["currency"],
                                transaction_data["amount"]["value_usd"]),
        "merchant_name": transaction_data["merchant_name"],
        "line_items": _canon_line_items(transaction_data["line_items"]),
    }
    return S.sha256_b64u(S._json_bytes(shown))


def verify_wysiwys(closed_mandate: dict, shown_digest: str) -> IntegrityResult:
    rederived = {
        "amount": _canon_amount(closed_mandate["payment_amount"]["currency"],
                                closed_mandate["payment_amount"]["value_usd"]),
        "merchant_name": closed_mandate["payee"]["name"],
        "line_items": _canon_line_items(closed_mandate["line_items"]),
    }
    if S.sha256_b64u(S._json_bytes(rederived)) != shown_digest:
        return IntegrityResult.fail(
            "AGENT.WYSIWYS.DRIFT",
            "settled cart differs from the confirmation the user approved")
    return IntegrityResult.passed()
