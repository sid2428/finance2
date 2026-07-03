"""Feature 1 — constraint compiler + registry (unknown-type fails closed)."""

from __future__ import annotations

from aegis.ap2.constraints import (
    ConstraintRegistry,
    compile_fx_slippage_bound,
    compile_mcc_allowlist,
    compile_spend_curve,
    compile_velocity_envelope,
    default_registry,
    verify_fx_slippage_bound,
    verify_mcc_allowlist,
    verify_spend_curve,
    verify_velocity_envelope,
)


def _closed(**over):
    base = {
        "open_iat": 1_000_000,
        "payment_amount": {"value_usd": 180.0, "currency": "USD"},
        "payee": {"id": "m1", "name": "Shop", "mcc": "5734"},
        "constraints": [],
    }
    base.update(over)
    return base


def test_spend_curve_passes_at_hour_zero():
    c = compile_spend_curve(200.0, 24.0)
    r = c.verify(_closed(), {"now": 1_000_000})
    assert r.ok


def test_spend_curve_fails_after_decay():
    c = compile_spend_curve(200.0, 24.0)
    # 48h -> two half-lives -> budget 50; £180 must fail.
    r = c.verify(_closed(), {"now": 1_000_000 + 48 * 3600})
    assert not r.ok and "decayed budget" in r.detail


def test_mcc_allowlist():
    c = compile_mcc_allowlist(["5734"])
    assert c.verify(_closed(), {}).ok
    assert not c.verify(_closed(payee={"id": "x", "mcc": "7995"}), {}).ok


def test_fx_slippage_bound():
    c = compile_fx_slippage_bound(quoted_rate=1.25, max_bps=50, quote_currency="USD")
    closed = _closed(payment_amount={"value_usd": 100.0, "currency": "EUR"})
    assert c.verify(closed, {"executed_fx_rate": 1.2505}).ok        # 4 bps
    assert not c.verify(closed, {"executed_fx_rate": 1.30}).ok      # 400 bps


def test_velocity_envelope():
    c = compile_velocity_envelope(max_count=3, max_value_usd=500.0, window_seconds=86400)
    closed = _closed(payment_amount={"value_usd": 200.0, "currency": "USD"})
    assert c.verify(closed, {"velocity_observed": {"count": 1, "value_usd": 200.0}}).ok
    assert not c.verify(closed, {"velocity_observed": {"count": 3, "value_usd": 200.0}}).ok  # count
    assert not c.verify(closed, {"velocity_observed": {"count": 1, "value_usd": 400.0}}).ok  # value


def test_unknown_constraint_type_fails_closed():
    reg = default_registry()
    closed = _closed(constraints=[{"type": "com.aegis.unknown_v9"}])
    results = reg.evaluate(closed, {"now": 1_000_000})
    assert len(results) == 1 and not results[0].ok
    assert "unknown constraint type" in results[0].detail


def test_empty_registry_fails_all():
    reg = ConstraintRegistry()
    closed = _closed(constraints=[{"type": "com.aegis.spend_curve"}])
    assert not reg.evaluate(closed, {"now": 1})[0].ok
