# AP2 v0.2 Conformance

**Spec source:** ap2-protocol.org (Agentic Payment Protocol v0.2, FIDO Alliance
stewardship), retrieved 2026-07-04. This document is the conformance matrix the
production-uplift plan (WS1) calls for: every spec artifact mapped to how AEGIS
models it, marked **conformant / divergent / absent**. Honesty in the divergent
and absent rows is the point — this file exists so an adopter knows exactly
what translation their integration needs.

AEGIS has two tracks with different conformance postures:

* **Compliance track** (`aegis/models.py`, the 7-stage pipeline): models the
  *pre-v0.2* Intent/Cart/Payment trio as W3C-VC-style credentials. It is the
  policy plane; conformance lives in the adapter seam (see `ADAPTERS.md`).
* **Advanced track** (`aegis/ap2/`): speaks SD-JWT natively — EdDSA SD-JWTs,
  selective disclosure digests, KB-JWT proof-of-possession, `checkout_hash`
  binding, signed receipts. This is structurally the v0.2 vocabulary.

## Matrix

| # | AP2 v0.2 artifact / rule | Spec detail | AEGIS today | Status |
|---|---|---|---|---|
| 1 | Closed Checkout Mandate | SD-JWT, `vct: mandate.checkout.1`; carries merchant-signed `checkout_jwt` + `checkout_hash`; `iat`/`exp` | Advanced track: SD-JWT closed mandate with `checkout_hash` recomputed and enforced at the verifier gate. Compliance track: `CartMandate` (flat fields, VC-style proof) | **Divergent** — mechanism conformant in the advanced track; `vct` naming and envelope layout not yet aligned; compliance track needs the AP2-native adapter |
| 2 | Open Checkout Mandate | `vct: mandate.checkout.open.1`; constraints `checkout.allowed_merchants` (objects `{id, name, website}`), `checkout.line_items` (LineItemRequirements) | `IntentMandate.allowed_merchants` (DID strings, not merchant objects); constraint DSL (`aegis/ap2/constraints.py`) with `spend_curve`, `mcc_allowlist`, `fx_slippage_bound`, `velocity_envelope` | **Divergent** — AEGIS constraints are a *superset* in power but not the spec's constraint vocabulary; merchant identification shape differs |
| 3 | Closed Payment Mandate | `vct: mandate.payment.1`; `transaction_id`, `payee` (Merchant), `pisp`, `payment_amount` (minor units + ISO 4217), `payment_instrument` `{id, type, description}`, `execution_date`, `risk_data`, `iat`/`exp` | `PaymentMandate`: `mandate_id`, `cart_ref`, `instrument {kind, reference}`, `human_present`, `settlement_rail`, `initiator_agent` | **Divergent** — field names differ throughout; amounts are float USD not minor-unit + currency pairs; `risk_data`, `execution_date`, `pisp` **absent** |
| 4 | Open Payment Mandate | `vct: mandate.payment.open.1`; may carry any closed-mandate property as a constraint (budget, allowed instruments) | `IntentMandate.max_value_usd` + `velocity_envelope` constraint | **Partial** — value bound and velocity constraints exist; instrument-allowlist constraint absent |
| 5 | Signature suite | ES256 (P-256), `cnf` JWK key binding | Ed25519 throughout (both tracks) | **Divergent** — deliberate for the dependency-light reference build; the crypto seam (`aegis/crypto.py`, `aegis/ap2/sdjwt.py`) isolates the swap. ES256 support is the top item in the gap log |
| 6 | Closed→open binding (autonomous mode) | closed mandates signed with `agent_sk`; `kb-sd-jwt` binds to the user-signed open mandate whose `cnf` carries `agent_pk` | Advanced track: KB-JWT proof-of-possession against the endorsed `cnf` key, enforced at the single verifier gate | **Conformant (mechanism)** — same construction; alg/curve divergence per row 5 |
| 7 | Checkout Receipt | `status` (Success/Error), `iss`, `iat`, `reference` (hash binding), `order_id` | `MandateReceipt {reference, result, amount_usd, issued_at, mandate_id}`, verifier-signed; error receipts release (never consume) open-mandate authority | **Partial** — status/reference/issuer semantics present; `order_id` absent |
| 8 | Payment Receipt | adds `payment_id`, `psp_confirmation_id`, `network_confirmation_id`, `error`, `error_description` | single receipt type covers both roles | **Partial** — settlement-confirmation identifiers **absent** |
| 9 | Human Present ("direct") flow | user approves both closed mandates on a Trusted Surface | attended path: standard bands, no HNP signals; full flow test in `tests/test_conformance_ap2.py` | **Conformant** |
| 10 | Human Not Present ("autonomous") flow | user approves open mandates; agent assembles + signs closed mandates | Dedicated policy path (WS1): `AGENT.HNP.UNATTENDED` baseline risk, tightened verdict bands (25/65 vs 40/75), and **unbounded delegated authority refused** (`AGENT.HNP.UNBOUNDED_AUTHORITY` when no `max_value_usd`) | **Conformant (policy plane)** — HNP demonstrably exercises a different path, with tests |
| 11 | HNP mode detection | structural: *who signed* the closed mandate (`user_sk` vs `agent_sk`) | explicit `human_present` boolean on the payment mandate | **Divergent** — AEGIS trusts a declared flag; deriving HNP from the closed-mandate signer is a tracked gap (adapter responsibility, row 6 gives the mechanism) |
| 12 | `unresolved_constraint` fallback | merchant/CP returns this error to convert HNP → human-present approval | `STEP_UP` verdict: m-of-n guardian quorum bound to the exact cart hash | **Conformant (by analogy)** — same outcome (human back in the loop), different vocabulary; the AP2-native adapter should translate STEP_UP to `unresolved_constraint` |
| 13 | Roles (SA / CP / M / MPP / TS) | five defined roles; verification duties at CP and MPP | AEGIS is none of these — it is the policy decision point invoked by CP and/or MPP before token creation / settlement | **N/A (positioning)** — see `ADAPTERS.md` for insertion points |
| 14 | `vct` versioning discipline | numeric suffixes (`mandate.payment.1`) gate breaking change | reason-code registry + ruleset version pinned per decision | **Conformant in spirit** — AEGIS versions its own contract surfaces; `vct` passthrough belongs to the adapter |

## Tracked gaps (priority order)

1. **ES256/P-256 signature suite** alongside Ed25519 (rows 5, 6).
2. **Minor-unit + ISO 4217 amounts** in the canonical models (row 3) — also a
   prerequisite for the ISO 20022 alignment in WS4.
3. **HNP derivation from closed-mandate signer** instead of a declared flag
   (row 11).
4. **Spec constraint vocabulary** (`checkout.allowed_merchants`,
   `checkout.line_items`) compiled into the existing constraint DSL (row 2).
5. **Receipt field parity** (`order_id`, `payment_id`, confirmation ids)
   (rows 7, 8).
6. Replay of the FIDO reference implementation's sample SD-JWTs through the
   advanced-track verifier (currently: flow-level conformance tests only,
   `tests/test_conformance_ap2.py`).

## Spec changelog (WG tracking)

Log every observed spec change here so adopters can see the project tracks
the standard. Newest first.

| Date observed | Change | Impact on AEGIS |
|---|---|---|
| 2026-07-04 | Baseline: matrix built against ap2-protocol.org v0.2 (Checkout/Payment mandates, SD-JWT, HNP autonomous mode, `unresolved_constraint` fallback) | This document; HNP policy path implemented |
| 2026-04 (per public record) | AP2 donated to FIDO Alliance; v0.2 adds Human-Not-Present payments | HNP became a first-class policy path (WS1 task 2) |
