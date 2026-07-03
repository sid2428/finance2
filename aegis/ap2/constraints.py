"""Feature 1 — Financial Constraint Compiler.

A small DSL for authoring custom AP2 payment constraint types. Each constraint
compiles to (a) a canonical object embedded in the open mandate's
``constraints[]`` and (b) a pure, deterministic verifier the fail-closed engine
runs. Novel types (none exist in base AP2):

  * ``com.aegis.spend_curve``       — time-decaying budget (authority isn't indefinite)
  * ``com.aegis.mcc_allowlist``     — ISO 18245 Merchant Category Code restriction
  * ``com.aegis.fx_slippage_bound`` — reject if executed FX deviates > N bps from quote
  * ``com.aegis.velocity_envelope`` — count + value caps carried in the mandate itself

AP2 rule enforced by the registry: *any unknown constraint type MUST fail*.
Verifiers read their parameters from the constraint object itself, so one
registered verifier serves every instance of its type.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

Verifier = Callable[[dict, dict, dict], "ConstraintResult"]  # (constraint, closed, ctx)


@dataclass(frozen=True)
class ConstraintResult:
    ok: bool
    type: str = ""
    detail: str = ""

    @staticmethod
    def passed(type_: str = "") -> "ConstraintResult":
        return ConstraintResult(ok=True, type=type_)

    @staticmethod
    def fail(type_: str, detail: str) -> "ConstraintResult":
        return ConstraintResult(ok=False, type=type_, detail=detail)


@dataclass(frozen=True)
class CompiledConstraint:
    type: str
    canonical: dict                       # goes into the open mandate constraints[]
    verify: Callable[[dict, dict], ConstraintResult]   # (closed, ctx) authoring form


# --- verifier implementations (parameters read from the constraint object) --

def verify_spend_curve(c: dict, closed: dict, ctx: dict) -> ConstraintResult:
    t = c["type"]
    open_iat = closed.get("open_iat")
    if open_iat is None:
        return ConstraintResult.fail(t, "closed mandate missing open_iat")
    age_h = (ctx["now"] - open_iat) / 3600.0
    if age_h < 0:
        return ConstraintResult.fail(t, "negative mandate age")
    allowed = c["initial_usd"] * (0.5 ** (age_h / c["half_life_hours"]))
    amt = closed["payment_amount"]["value_usd"]
    if amt > allowed + 1e-9:
        return ConstraintResult.fail(
            t, f"amount {amt:.2f} exceeds decayed budget {allowed:.2f} at age {age_h:.1f}h")
    return ConstraintResult.passed(t)


def verify_mcc_allowlist(c: dict, closed: dict, ctx: dict) -> ConstraintResult:
    t = c["type"]
    mcc = (closed.get("payee") or {}).get("mcc")
    if mcc is None:
        return ConstraintResult.fail(t, "payee MCC absent")
    allowed = set(c["allowed_mcc"])
    if mcc not in allowed:
        return ConstraintResult.fail(t, f"merchant category {mcc} not in allowlist")
    return ConstraintResult.passed(t)


def verify_fx_slippage_bound(c: dict, closed: dict, ctx: dict) -> ConstraintResult:
    t = c["type"]
    executed = ctx.get("executed_fx_rate")
    if executed is None:
        # No FX leg observed. If the cart is single-currency, the bound is moot.
        if closed["payment_amount"].get("currency") == c.get("quote_currency"):
            return ConstraintResult.passed(t)
        return ConstraintResult.fail(t, "cross-currency cart with no executed FX rate")
    quoted = c["quoted_rate"]
    bps = abs(executed - quoted) / quoted * 10_000
    if bps > c["max_bps"]:
        return ConstraintResult.fail(
            t, f"FX slippage {bps:.1f}bps exceeds bound {c['max_bps']}bps")
    return ConstraintResult.passed(t)


def verify_merchant_allowlist(c: dict, closed: dict, ctx: dict) -> ConstraintResult:
    """Base AP2 ``checkout.allowed_merchants``. The allowed set lives in the open
    mandate as selectively-disclosable claims; the verifier only sees what the
    agent chose to disclose (``ctx['disclosed_merchants']``)."""
    t = c["type"]
    payee_id = (closed.get("payee") or {}).get("id")
    disclosed = set(ctx.get("disclosed_merchants") or [])
    if payee_id not in disclosed:
        return ConstraintResult.fail(
            t, f"payee {payee_id} not among disclosed allowed merchants")
    return ConstraintResult.passed(t)


def verify_velocity_envelope(c: dict, closed: dict, ctx: dict) -> ConstraintResult:
    t = c["type"]
    amt = closed["payment_amount"]["value_usd"]
    observed = ctx.get("velocity_observed") or {"count": 0, "value_usd": 0.0}
    new_count = observed["count"] + 1
    new_value = observed["value_usd"] + amt
    if new_count > c["max_count"]:
        return ConstraintResult.fail(
            t, f"count {new_count} exceeds envelope max {c['max_count']} in window")
    if new_value > c["max_value_usd"] + 1e-9:
        return ConstraintResult.fail(
            t, f"aggregate {new_value:.2f} exceeds envelope max {c['max_value_usd']:.2f}")
    return ConstraintResult.passed(t)


# --- compilers (authoring side) -------------------------------------------

def _compile(type_: str, canonical: dict, verifier: Verifier) -> CompiledConstraint:
    return CompiledConstraint(
        type=type_,
        canonical=canonical,
        verify=lambda closed, ctx: verifier(canonical, closed, ctx),
    )


def compile_spend_curve(initial_usd: float, half_life_hours: float) -> CompiledConstraint:
    return _compile(
        "com.aegis.spend_curve",
        {"type": "com.aegis.spend_curve",
         "initial_usd": initial_usd, "half_life_hours": half_life_hours},
        verify_spend_curve,
    )


def compile_mcc_allowlist(allowed_mcc: list[str]) -> CompiledConstraint:
    return _compile(
        "com.aegis.mcc_allowlist",
        {"type": "com.aegis.mcc_allowlist", "allowed_mcc": list(allowed_mcc)},
        verify_mcc_allowlist,
    )


def compile_fx_slippage_bound(quoted_rate: float, max_bps: float,
                              quote_currency: str) -> CompiledConstraint:
    return _compile(
        "com.aegis.fx_slippage_bound",
        {"type": "com.aegis.fx_slippage_bound", "quoted_rate": quoted_rate,
         "max_bps": max_bps, "quote_currency": quote_currency},
        verify_fx_slippage_bound,
    )


def compile_merchant_allowlist() -> CompiledConstraint:
    return _compile(
        "checkout.allowed_merchants",
        {"type": "checkout.allowed_merchants"},
        verify_merchant_allowlist,
    )


def compile_velocity_envelope(max_count: int, max_value_usd: float,
                              window_seconds: int) -> CompiledConstraint:
    return _compile(
        "com.aegis.velocity_envelope",
        {"type": "com.aegis.velocity_envelope", "max_count": max_count,
         "max_value_usd": max_value_usd, "window_seconds": window_seconds},
        verify_velocity_envelope,
    )


# --- registry -------------------------------------------------------------

class ConstraintRegistry:
    """Maps constraint type -> verifier. Unknown types fail closed (AP2 rule)."""

    def __init__(self) -> None:
        self._v: dict[str, Verifier] = {}

    def register(self, type_: str, verifier: Verifier) -> None:
        self._v[type_] = verifier

    def register_compiled(self, c: CompiledConstraint, verifier: Verifier) -> None:
        self._v[c.type] = verifier

    def verifier_for(self, type_: str) -> Verifier | None:
        return self._v.get(type_)

    def evaluate(self, closed: dict, ctx: dict) -> list[ConstraintResult]:
        results: list[ConstraintResult] = []
        for c in closed.get("constraints", []):
            verifier = self._v.get(c.get("type"))
            if verifier is None:
                results.append(ConstraintResult.fail(
                    c.get("type", "<none>"), "unknown constraint type — fail closed"))
            else:
                results.append(verifier(c, closed, ctx))
        return results


def default_registry() -> ConstraintRegistry:
    reg = ConstraintRegistry()
    reg.register("com.aegis.spend_curve", verify_spend_curve)
    reg.register("com.aegis.mcc_allowlist", verify_mcc_allowlist)
    reg.register("com.aegis.fx_slippage_bound", verify_fx_slippage_bound)
    reg.register("com.aegis.velocity_envelope", verify_velocity_envelope)
    reg.register("checkout.allowed_merchants", verify_merchant_allowlist)
    return reg
