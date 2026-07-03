"""AEGIS·CORE advanced-track milestone demo (AEGIS-ADVANCED.md).

One run demonstrates: real SD-JWT crypto, protocol-native constraint design,
double-spend safety, human-intent integrity, adversarial assurance, and
automated dispute logic.

  open mandate (spend_curve + mcc_allowlist + allowed_merchants, w/ decoys)
    -> agent binds a valid closed mandate
    -> F4 verifies the delegation chain (real EdDSA / sd_hash / checkout_hash / KB)
    -> F2 discloses the minimal merchant set
    -> F3 reserves scope   -> F5 confirms the cart the user saw
    -> settlement issues a Mandate Receipt -> F3 reduces scope
    -> F7 fuzzes: all 8 attack variants bounce
    -> F6 auto-adjudicates a refund and a 'not authorized' dispute

Run:  python -m demo.advanced_demo
"""

from __future__ import annotations

import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

from aegis.crypto import generate_keypair
from aegis.ap2 import sdjwt as S
from aegis.ap2.constraints import (
    compile_mcc_allowlist,
    compile_merchant_allowlist,
    compile_spend_curve,
    default_registry,
)
from aegis.ap2.disclosure import minimal_disclosure_set, observable_slots
from aegis.ap2.disputes import (
    CheckoutRecord,
    DisputeClaim,
    DisputeStore,
    PaymentRecord,
    adjudicate_dispute,
)
from aegis.ap2.mandates import build_chain
from aegis.ap2.sandbox import MandateFuzzer
from aegis.ap2.scope_ledger import MandateReceipt, ScopeLedger
from aegis.ap2.verifier import VerifyContext, verify_delegation_chain
from aegis.ap2.wysiwys import bind_shown_confirmation, verify_wysiwys

LINE = "=" * 78


def hdr(t): print(f"\n{LINE}\n  {t}\n{LINE}")


def main() -> None:
    reg = default_registry()
    verifier_key, verifier_pub = generate_keypair()

    open_iat, now = 1_000_000, 1_000_000 + 3600   # settle 1h after issuance
    amount = {"value_usd": 180.0, "currency": "USD", "value": 180.0}
    line_items = [{"title": "espresso machine", "quantity": 1, "price": 180.0}]
    merchant = {"id": "m3", "name": "Bright Beans Coffee", "mcc": "5734"}

    # --- Delegation: build open + closed mandate chain -------------------
    hdr("SETUP — sign open mandate (spend_curve + mcc_allowlist + allowlist)")
    constraints = [
        compile_spend_curve(initial_usd=500.0, half_life_hours=24.0),
        compile_mcc_allowlist(allowed_mcc=["5734"]),
        compile_merchant_allowlist(),
    ]
    chain = build_chain(
        constraints=constraints,
        allowed_merchants=[f"merchant-{i}" for i in range(11)] + ["m3"],
        cart_merchant=merchant, payment_amount=amount, line_items=line_items,
        open_iat=open_iat, closed_iat=open_iat + 60, merchant_decoys=6,
    )
    print(f"  open mandate:   12 allowed merchants + 6 decoys "
          f"-> {observable_slots(chain.open_m)} observable slots")
    print(f"  constraints:    {[c['type'] for c in chain.open_m.payload['constraints']]}")
    print(f"  cnf key bound:  {chain.agent_jwk['x'][:16]}…  (agent proof-of-possession)")

    ctx = VerifyContext(now=now, nonce=chain.nonce, registry=reg,
                        issuer_resolver=lambda i: chain.issuer_pub)

    # --- F2: minimal disclosure -----------------------------------------
    hdr("F2 — minimal-disclosure solver")
    mds = minimal_disclosure_set(chain.open_m, chain.closed_m.payload, reg, {"now": now})
    revealed = [S.parse_disclosure(r).value for r in chain.open_m.disclosures
                if S.parse_disclosure(r).digest in mds]
    print(f"  cart matches merchant m3 -> discloses exactly {len(mds)} of 12: {revealed}")
    presented_open = S.present(chain.open_m, mds)

    # --- F4: delegation-chain verification ------------------------------
    hdr("F4 — delegation-chain verifier (the single gate)")
    result = verify_delegation_chain(
        [presented_open.serialize(), chain.closed_m.serialize()], chain.checkout_jwt, ctx)
    print(f"  verify: ok={result.ok} code={result.code}")
    for r in result.constraint_results:
        print(f"    constraint {r.type}: {'PASS' if r.ok else 'FAIL'}")
    assert result.ok

    # --- F3: reserve scope ----------------------------------------------
    hdr("F3 — scope ledger reserves authority (double-spend guard)")
    ledger = ScopeLedger(verifier_pub)
    scope = ledger.open_scope("open-mandate-1", count=3, value_usd=1000.0)
    closed_hash = chain.closed_m.issuer_hash()
    ledger.reserve(scope, closed_hash, amount["value_usd"])
    print(f"  reserved closed {closed_hash[:12]}…  outstanding={len(scope.outstanding)}")
    try:
        ledger.reserve(scope, "other-closed-hash", 50.0)
    except Exception as e:
        print(f"  second overlapping reserve -> blocked: {type(e).__name__}: {e}")

    # --- F5: WYSIWYS confirm --------------------------------------------
    hdr("F5 — WYSIWYS: settled cart == cart the user approved?")
    shown = {"amount": {"currency": "USD", "value_usd": 180.0},
             "merchant_name": merchant["name"], "line_items": line_items}
    shown_digest = bind_shown_confirmation(shown)
    integ = verify_wysiwys(chain.closed_m.payload, shown_digest)
    print(f"  WYSIWYS ok={integ.ok} (anchor {shown_digest[:12]}…)")
    assert integ.ok

    # --- Settlement + receipt -> F3 scope reduction ---------------------
    hdr("SETTLE — verifier issues Mandate Receipt -> F3 reduces scope")
    receipt = MandateReceipt.issue(
        verifier_key, reference=closed_hash, result="success",
        amount_usd=amount["value_usd"], issued_at=now, mandate_id="open-mandate-1")
    before = scope.remaining_value_usd
    ledger.apply_receipt(scope, receipt)
    print(f"  receipt applied. remaining_value {before:.0f} -> {scope.remaining_value_usd:.0f} USD, "
          f"count -> {scope.remaining_count}")

    # --- F7: adversarial fuzzer -----------------------------------------
    hdr("F7 — mandate sandbox fuzzes the closed mandate")
    report = MandateFuzzer().run(chain, ctx)
    print(f"  baseline_ok={report.baseline_ok}  attacks={report.attempted}  "
          f"rejected={report.rejected}  escaped={report.escaped}")
    assert report.clean

    # --- F6: dispute reconciliation -------------------------------------
    hdr("F6 — dispute reconciliation (join on checkout_hash)")
    store = DisputeStore(verifier_pub)
    checkout_hash = chain.closed_m.payload["checkout_hash"]
    store.record(
        CheckoutRecord(checkout_hash, requires_refundability=True, refund_period_days=30,
                       shown_digest=shown_digest, merchant_name=merchant["name"]),
        PaymentRecord("open-mandate-1", chain.closed_m.payload),
        receipt,
    )
    within = adjudicate_dispute(checkout_hash, DisputeClaim("REFUND_REQUEST", now + 1 * 86400), store)
    late = adjudicate_dispute(checkout_hash, DisputeClaim("REFUND_REQUEST", now + 45 * 86400), store)
    unauth = adjudicate_dispute(checkout_hash, DisputeClaim("NOT_AUTHORIZED", now), store)
    print(f"  refund @ +1d  (30d window) : {within.outcome:8s} — {within.rationale}")
    print(f"  refund @ +45d (30d window) : {late.outcome:8s} — {late.rationale}")
    print(f"  'not authorized' claim     : {unauth.outcome:8s} — {unauth.rationale}")

    print(f"\n{LINE}\n  ADVANCED DEMO COMPLETE — real SD-JWT crypto end to end\n{LINE}")


if __name__ == "__main__":
    main()
