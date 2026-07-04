# The AEGIS Adapter Contract

**Status:** design document (WS1 task 3). The contract below is what a third
party needs to implement a new protocol adapter; the three adapter designs
that follow (AP2-native, ACP, x402) are specifications, with the AP2-native
one partially realized by the existing gateway.

## Why a seam

The protocol stack is young and moving (AP2 went to FIDO three months ago;
ACP ships date-versioned schemas; x402 V2 added batch settlement). AEGIS's
hedge is architectural: **conformance lives in adapters, the pipeline stays
stable.** An adapter's whole job is a lossless-enough translation in, and a
faithful translation out. Policy, evidence, and determinism never leave the
core.

## The contract

```
adapter: (AuthorizationArtifact, TransactionContext) -> VerdictEnvelope
```

**In — `AuthorizationArtifact`**: whatever the protocol calls authorization
(AP2 mandate SD-JWTs, an ACP checkout session + payment handler event, an
x402 challenge/commitment pair), untranslated, plus **`TransactionContext`**:
the routing facts the artifact itself does not carry — touched jurisdictions,
processing region, FX context for USD-equivalent amounts, guardian set.

**Out — `VerdictEnvelope`**: AEGIS's signed `DecisionEnvelope` (verdict,
versioned reason codes, rationale, risk score, screening provenance, model
provenance, liability split, replay hashes, Ed25519 signature), plus the
adapter's translation of the verdict into the protocol's native vocabulary.

Adapter obligations (normative):

1. **Fail closed on translation.** Any artifact field the adapter does not
   recognize as safe-to-ignore, any missing required field, any signature it
   cannot verify → submit nothing; return the protocol's rejection with
   reason `AGENT.SIG.INVALID` or `AGENT.SYS.FAILCLOSED`. Never "best-effort"
   a mandate into the pipeline.
2. **Preserve the money.** Amounts must arrive in the pipeline as
   USD-equivalent with the conversion source recorded in
   `TransactionContext` — the conversion is evidence, part of the replay
   archive.
3. **Derive, don't trust, mode flags.** `human_present` must be derived from
   the protocol's structure (who signed the closed mandate; whether a
   delegated token was used), not copied from an attacker-writable field.
4. **Translate verdicts completely.** ALLOW / BLOCK / STEP_UP must each map
   to a defined protocol behavior. Unmappable verdict → the protocol's
   rejection path (fail closed), never a silent ALLOW.
5. **Return the envelope.** The signed envelope rides with the protocol
   response (header, extension field, or detached reference) so the
   settlement layer can verify AEGIS's output was not tampered with in
   transit.

## Adapter 1 — AP2-native (v0.2)

Insertion points: the **Credential Provider** (before payment-token creation)
and/or the **Merchant Payment Processor** (before settlement) — the two
verification duties AP2 already assigns.

| AP2 artifact | Pipeline mapping |
|---|---|
| Closed Checkout Mandate (`mandate.checkout.1`): `checkout_jwt` payload (line items, `total_price`, `currency`, merchant `{id, name, website}`) | `CartMandate` (line items, total→USD per contract rule 2, merchant identity → screening inputs) |
| Open Checkout Mandate (`mandate.checkout.open.1`): `checkout.allowed_merchants`, `checkout.line_items` | `IntentMandate.allowed_merchants` + constraint DSL terms |
| Closed Payment Mandate (`mandate.payment.1`): `payment_amount`, `payment_instrument`, `payee`, `transaction_id` | `PaymentMandate` (instrument, rail, references) |
| Open Payment Mandate budget constraint | `IntentMandate.max_value_usd` — **required for HNP** (else `AGENT.HNP.UNBOUNDED_AUTHORITY`) |
| Closed-mandate signer: `user_sk` (direct) vs `agent_sk` bound by `kb-sd-jwt` to the open mandate's `cnf: agent_pk` | `human_present` derived per contract rule 3; the advanced track's verifier gate performs exactly this chain check |
| Receipts (status / `reference` / confirmation ids) | scope-ledger receipt (authority consumption on success, release on error) |

Verdict translation: ALLOW → proceed to token creation / settlement.
BLOCK → protocol rejection carrying the reason codes. STEP_UP →
**`unresolved_constraint`** — AP2's own fallback that brings the user back to
a Trusted Surface; the quorum challenge is the compliance-grade form of that
re-approval.

## Adapter 2 — ACP (checkout / payment-handler events)

ACP (OpenAI + Stripe + Meta; date-versioned spec, 2026-04-17 line) lets the
merchant "apply custom approval logic" during checkout — that hook is the
insertion point: AEGIS runs before `checkout_session.complete` is honored,
and again at the PSP when the delegated payment token is exercised.

| ACP artifact | Pipeline mapping |
|---|---|
| Checkout session (id, line items, totals, fulfillment, buyer) | `CartMandate` + `TransactionContext` (buyer/merchant jurisdictions) |
| Delegated payment token (`delegate_payment`: allowance `max_amount`, expiry, merchant binding) | `IntentMandate` (the allowance IS the bounded authority; `max_amount` → `max_value_usd`) |
| Payment-handler event exercising the token | `PaymentMandate`; `human_present=False` whenever a stored allowance is exercised without a fresh buyer confirmation (rule 3) |
| Buyer/merchant identity fields | screening inputs (f2) |

Verdict translation: ALLOW → session completes. BLOCK → session rejected
with `messages[]` carrying reason codes. STEP_UP → session parked in
`requires_action`; the quorum approval endpoint satisfies the action.
Design note: ACP has no mandate-grade signatures on the checkout objects —
the adapter records that as a control gap in `ControlEvidence`
(`agent_sdk_pinned_intent_constraints=False`), which shifts liability
weighting; it does not fabricate trust the protocol doesn't provide.

## Adapter 3 — x402 (challenge / commitment)

x402 authorizes machine-speed stablecoin payment per request; the Fireblocks
security extension (request integrity + spend governance) is the
architectural sibling: AEGIS slots in at the **facilitator** (or the payer's
policy proxy) between `verify` and `settle`.

| x402 artifact | Pipeline mapping |
|---|---|
| `PaymentRequirements` (402 challenge: `payTo`, `asset`, `maxAmountRequired`, `network`, `resource`) | `CartMandate` analogue (the resource is the line item; `payTo` wallet → screening input — the expected OFAC wallet-screening guidance makes this row load-bearing) |
| `X-PAYMENT` commitment (signed EIP-3009/permit payload, payer, amount, nonce, validity window) | `PaymentMandate` (rail `x402`; instrument = asset+network; nonce/validity into replay protection) |
| Fireblocks extension: request-hash binding, per-agent spend policy | request-hash → `checkout_hash`-style binding check (f4); spend policy → `IntentMandate.max_value_usd` / `velocity_envelope` |
| Agent wallet key | agent identity (KYA registry root once WS6 lands) |
| Settlement mode | x402 is **always HNP** — a human never confirms the individual request. The HNP policy path applies unconditionally: bounded authority required, tightened bands |

Verdict translation: ALLOW → facilitator settles (V2 batch included).
BLOCK → HTTP 402 re-issued with a `compliance` error object (reason codes).
STEP_UP → 402 with a challenge extension pointing at the quorum endpoint;
timeout resolves toward refusal, never silent settlement.

## Compatibility promise

Adapter contracts and the reason-code taxonomy are public surfaces: breaking
changes require a major version (see WS9/WS10 versioning policy). The
pipeline's own models may evolve freely — that is the point of the seam.
