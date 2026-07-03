# AEGIS·CORE — Advanced Build Track

**Seven distinctive features built directly on AP2's real authorization machinery.**

This track goes *below* the compliance layer and builds on the actual cryptographic primitives defined in the AP2 Agent Authorization Framework: **SD-JWT Verifiable Credentials**, **Open/Closed mandate chains**, **Key Binding proof-of-possession** (`cnf`), the `sd_hash` / `checkout_hash` binding claims, **selective disclosure**, **Mandate Receipts**, and **custom constraint types**.

The design premise comes straight from AP2's own threat model: *prompt injection is assumed unpreventable, so every LLM and Agent is treated as a potential attacker.* Security therefore cannot live in the agent's reasoning — it must live in the **cryptographic constraints on the mandate** and in **deterministic verification**. That is exactly what these seven features build.

> Focus of this document: **building now.** No deployment/ops. Every feature has a protocol anchor, the distinctive idea, concrete code, and a test that proves it.

---

## Protocol primitives we build on (quick reference)

| Primitive | What it is | Where it comes from |
|---|---|---|
| **Open Mandate** | Constraints + agent key (`cnf`), not yet bound to a transaction | Agent Authorization → Mandate Structure |
| **Closed Mandate** | Open mandate bound to a specific transaction via a Key-Binding JWT | Agent Authorization → Mandate Structure |
| **`cnf` claim** | The proof-of-possession key the agent must sign with (RFC 7800) | Mandate Content claims |
| **`sd_hash`** | Binds a closed mandate to the exact open mandate it derives from | Manipulated-Checkout mitigations |
| **`checkout_hash`** | Links a Payment Mandate to its Checkout Mandate; join key for disputes | Manipulated-Payment / Data Minimization |
| **`transaction_data`** | The confirmation UI + amount the user actually saw on the Trusted Surface | OpenID4VP delegation |
| **Constraints** | Typed rules the closed mandate MUST satisfy; *unknown types MUST fail* | Verification & Processing Rules |
| **Mandate Receipt** | Verifier-signed JWT proving an action was authorized; scopes down the open mandate | Action Authorization |

Every feature below cites which of these it stands on.

---

## The 7 Advanced Features

### Feature 1 — Financial Constraint Compiler (a DSL for custom AP2 constraint types)

**Protocol anchor:** Constraints array + the rule *"any unknown Constraints MUST be treated as failing evaluation"* + the guidance to name new constraint types with a collision-resistant rDNS/URN prefix.

**The distinctive idea.** AP2 ships only two payment constraint types (`checkout.line_items`, `checkout.allowed_merchants`). The protocol *invites* new ones — but a wrong constraint verifier is a security hole, because a closed mandate is only as safe as the constraints checked against it. So we build a **constraint compiler**: a small DSL where a financial constraint is authored once, compiles to (a) a canonical SD-JWT constraint object the Trusted Surface can embed, and (b) a **pure, deterministic verifier** that the fail-closed engine runs. This lets us ship genuinely novel finance constraints that AP2 doesn't have.

**Novel constraint types we author (none of these exist in base AP2):**

- `com.aegis.spend_curve` — a time-decaying budget: authorized spend shrinks as the open mandate ages (models "authority should not be indefinite").
- `com.aegis.mcc_allowlist` — restrict by ISO 18245 **Merchant Category Code**, not just merchant identity (block "gambling" / "crypto ATM" categories wholesale).
- `com.aegis.fx_slippage_bound` — for cross-currency carts, reject if the executed FX rate deviates > N bps from the rate quoted at intent time.
- `com.aegis.velocity_envelope` — max count *and* max aggregate value inside a rolling window, carried *in the mandate itself* so it's enforced even offline.

**Build it:**

```python
from dataclasses import dataclass
from typing import Callable, Any

@dataclass(frozen=True)
class CompiledConstraint:
    type: str                              # e.g. "com.aegis.spend_curve"
    canonical: dict                        # goes into the open mandate's constraints[]
    verify: Callable[[dict, dict], "ConstraintResult"]   # (closed_mandate, ctx) -> result

def compile_spend_curve(initial_usd: float, half_life_hours: float) -> CompiledConstraint:
    canonical = {"type": "com.aegis.spend_curve",
                 "initial_usd": initial_usd, "half_life_hours": half_life_hours}

    def verify(closed: dict, ctx: dict) -> ConstraintResult:
        age_h = (ctx["now"] - closed["open_iat"]) / 3600
        allowed = initial_usd * (0.5 ** (age_h / half_life_hours))   # exponential decay
        amt = closed["payment_amount"]["value_usd"]
        if amt > allowed:
            return ConstraintResult.fail(
                "com.aegis.spend_curve",
                f"amount {amt:.2f} exceeds decayed budget {allowed:.2f} at age {age_h:.1f}h")
        return ConstraintResult.ok()
    return CompiledConstraint("com.aegis.spend_curve", canonical, verify)

# The registry enforces AP2's rule: unknown type => automatic FAIL (never silently pass)
class ConstraintRegistry:
    def __init__(self): self._v: dict[str, Callable] = {}
    def register(self, c: CompiledConstraint): self._v[c.type] = c.verify
    def evaluate(self, closed: dict, ctx: dict) -> list["ConstraintResult"]:
        results = []
        for c in closed["constraints"]:
            verifier = self._v.get(c["type"])
            if verifier is None:                       # <-- AP2: unknown MUST fail
                results.append(ConstraintResult.fail(c["type"], "unknown constraint type"))
            else:
                results.append(verifier(closed, ctx))
        return results
```

**Prove it:** a closed mandate carrying `com.aegis.spend_curve` for £200 half-life 24h must pass at hour 0 for £180, and **fail** at hour 48 for the same £180 (budget decayed to £50). And a mandate carrying `com.aegis.unknown_v9` must fail closed.

---

### Feature 2 — Minimal-Disclosure Solver + Decoy-Digest Privacy Budget

**Protocol anchor:** Selective Disclosure — *"the Agent MUST choose which disclosures to include so as to maximize user privacy while still providing authorization"* + decoy digests (RFC 9901 §4.2.5) + rainbow-table salting (§9.1).

**The distinctive idea.** Everyone treats selective disclosure as "reveal what's asked." We treat it as a **constrained minimization problem**: given a verifier's constraint set, compute the *smallest* subset of SD-JWT disclosures that still satisfies every constraint, so the agent never over-reveals. Then add a **privacy budget** that pads the presentation with decoy digests so the *number* of hidden claims doesn't itself leak intent (an open mandate for "coffee maker under £200" shouldn't reveal that ten other allowed merchants exist).

**Build it:**

```python
def minimal_disclosure_set(open_mandate, closed_mandate, constraint_registry, ctx) -> set[str]:
    """Return the minimal set of disclosure digests required to satisfy all constraints."""
    all_disclosures = open_mandate.disclosures            # {digest: (salt, key, value)}
    required = set()

    for constraint in closed_mandate["constraints"]:
        verifier = constraint_registry.verifier_for(constraint["type"])
        # Greedy shrink: start from full set, drop each disclosure if constraint still passes
        working = set(all_disclosures)
        for d in list(working):
            trial = working - {d}
            if verifier(present(closed_mandate, trial), ctx).ok:
                working = trial                            # d was not needed
        required |= working
    return required                                        # minimal covering set

def add_decoys(presentation, privacy_budget: int, salt_bits: int = 128):
    """RFC9901 §4.2.5 decoy digests: hide the true count of undisclosed claims."""
    for _ in range(privacy_budget):
        presentation["_sd"].append(random_digest(salt_bits))   # indistinguishable from real
    return presentation
```

**Prove it:** for a mandate with 12 allowed merchants where the cart matches merchant #3, the solver discloses exactly **one** merchant disclosure (not all 12); and with a privacy budget of 5, an observer counting `_sd` entries cannot infer how many real merchants were authorized.

---

### Feature 3 — Open-Mandate Scope Ledger (receipt-driven double-spend prevention)

**Protocol anchor:** Double-Spend threat + *"the agent reduces the scope of the open mandate based on the receipt, often preventing future presentations entirely"* + *"these Receipts MUST be integrity protected from the Shopping Agent's LLM."*

**The distinctive idea.** An open mandate is *reusable* authority (that's the point — autonomous action). That makes it a double-spend risk: a prompt-injected agent can try to bind the same open mandate to several overlapping closed mandates before any receipt comes back. We build the **scope ledger**: an integrity-protected state machine, held *outside* the agent's LLM context, that tracks remaining authorization per open mandate and monotonically reduces it on each Mandate Receipt — so a second overlapping closed mandate is rejected before it can settle.

**Build it:**

```python
@dataclass
class OpenMandateScope:
    mandate_id: str
    remaining_count: int          # e.g. authority for N purchases
    remaining_value_usd: float
    consumed_hashes: set[str]     # sd_hash of every closed mandate already receipted
    outstanding: set[str]         # closed sd_hashes released but not yet receipted

class ScopeLedger:
    """Lives in tamper-evident storage the agent's LLM cannot write to."""

    def reserve(self, scope: OpenMandateScope, closed) -> Reservation:
        h = closed["sd_hash"]
        if h in scope.consumed_hashes:
            raise DoubleSpend("closed mandate already settled")
        if self._overlaps(closed, scope.outstanding):        # overlapping unreceipted spend
            raise DoubleSpend("overlapping closed mandate outstanding — await receipt")
        if closed["amount_usd"] > scope.remaining_value_usd or scope.remaining_count < 1:
            raise ScopeExceeded("beyond remaining authority")
        scope.outstanding.add(h)
        return Reservation(scope.mandate_id, h)

    def apply_receipt(self, scope: OpenMandateScope, receipt: MandateReceipt):
        verify_receipt_signature(receipt)                    # Verifier-signed JWT
        h = receipt.reference                                # hash of the final SD-JWT
        scope.outstanding.discard(h)
        if receipt.result == "success":
            scope.consumed_hashes.add(h)
            scope.remaining_count -= 1
            scope.remaining_value_usd -= receipt.amount_usd  # monotonic reduction
        # on "error": scope is released, authority restored — no silent leak
```

**Prove it:** release two overlapping closed mandates from one open mandate; the second `reserve()` raises `DoubleSpend`. After a `success` receipt, remaining value strictly decreases and can never increase. Tamper with a receipt's signature → `apply_receipt` rejects it.

---

### Feature 4 — Delegation-Chain Cryptographic Verifier (the part most projects stub)

**Protocol anchor:** Verification & Processing Rules (verify SD-JWT chain, carry open→closed values unchanged, evaluate every constraint) + Key Binding proof-of-possession via the `cnf` key + `sd_hash` binding + `checkout_hash` merchant check.

**The distinctive idea.** Most AP2 demos fake the crypto with a boolean `verified=True`. The distinctive move is to *actually* implement the full chain verification exactly as the spec's processing rules require, and make it the **single gate** every other feature depends on. This is the hard engineering: SD-JWT parsing, disclosure digest recomputation, KB-JWT proof-of-possession against the endorsed `cnf` key, and the three binding checks.

**Build it (verification pipeline, each step fail-closed):**

```python
def verify_delegation_chain(chain: list[str], expected_checkout_jwt: str, ctx) -> VerifyResult:
    # 1. Parse & verify each SD-JWT in the chain (issuer sig + disclosure digests match _sd)
    sdjwts = [parse_sdjwt(x) for x in chain]
    for sd in sdjwts:
        if not verify_issuer_signature(sd) or not digests_match_disclosures(sd):
            return VerifyResult.fail("invalid_credential")          # AP2 terminal error

    open_m, closed_m = sdjwts[0], sdjwts[-1]

    # 2. Open-mandate claims must appear UNCHANGED in the closed mandate
    for k, v in open_m.locked_claims().items():
        if closed_m.claim(k) != v:
            return VerifyResult.fail("invalid_mandate", f"claim {k} mutated open->closed")

    # 3. Key Binding: closed mandate must be signed by the key endorsed in open `cnf`
    cnf_jwk = open_m.claim("cnf")["jwk"]
    if not verify_kb_jwt(closed_m.kb_jwt, cnf_jwk, expected_nonce=ctx.nonce):
        return VerifyResult.fail("invalid_credential", "proof-of-possession failed")

    # 4. sd_hash binds closed -> exact open mandate presented
    if closed_m.claim("sd_hash") != sd_hash_of(open_m):
        return VerifyResult.fail("invalid_mandate", "sd_hash mismatch (rebind attack)")

    # 5. checkout_hash must match hash of the merchant's latest checkout_jwt
    if closed_m.claim("checkout_hash") != sha256_b64(expected_checkout_jwt):
        return VerifyResult.fail("invalid_mandate", "checkout_hash mismatch")

    # 6. Evaluate EVERY constraint (unknown => fail, from Feature 1's registry)
    for r in ctx.registry.evaluate(closed_m.payload, ctx):
        if not r.ok:
            return VerifyResult.fail("unresolved_constraint", r.detail)

    return VerifyResult.ok(mandate=closed_m)
```

**Prove it:** swap the KB-JWT signing key → step 3 fails. Mutate one line item in the closed mandate after signing → digest check (step 1) or constraint check (step 6) fails. Point the closed mandate at a different open mandate → step 4 (`sd_hash`) fails.

---

### Feature 5 — WYSIWYS Intent Integrity Oracle ("What You See Is What You Sign")

**Protocol anchor:** `transaction_data` confirmation UI (`amount`, `merchant_name`, `additional_info` table the user actually saw) + Manipulated-Checkout / Manipulated-Payment threats.

**The distinctive idea.** The gap AP2's threat model leaves open at the *human* boundary: the user approves what the Trusted Surface *displayed*, but nothing structurally proves the displayed confirmation equals what settles. We build an **intent-integrity oracle**: canonicalize and hash the exact confirmation payload shown to the user (`amount`, `merchant_name`, the line-item table in `additional_info`), embed that digest at delegation time, and at settlement re-derive it from the closed mandate. Any drift between "what was shown" and "what settles" is a manipulated-checkout attack — blocked deterministically.

**Build it:**

```python
def bind_shown_confirmation(transaction_data_payment_card: dict) -> str:
    """Hash exactly what the user saw on the Trusted Surface (WYSIWYS anchor)."""
    shown = {
        "amount": transaction_data_payment_card["amount"],            # "USD 150.00"
        "merchant_name": transaction_data_payment_card["merchant_name"],
        "line_items": parse_table(transaction_data_payment_card["additional_info"]),
    }
    return sha256_b64(canonical_json(shown))     # embedded into the delegate payload

def verify_wysiwys(closed_mandate: dict, shown_digest: str) -> IntegrityResult:
    rederived = {
        "amount": fmt_amount(closed_mandate["payment_amount"]),
        "merchant_name": closed_mandate["payee"]["name"],
        "line_items": [{"title": li["title"], "qty": li["quantity"], "price": li["price"]}
                       for li in closed_mandate["line_items"]],
    }
    if sha256_b64(canonical_json(rederived)) != shown_digest:
        return IntegrityResult.fail(
            "AGENT.WYSIWYS.DRIFT",
            "settled cart differs from the confirmation the user approved")
    return IntegrityResult.ok()
```

**Prove it:** user approves a £150 rabbit; a compromised shopping agent inflates the closed mandate to £1,500 or swaps the payee → `verify_wysiwys` fails even though the mandate is *cryptographically valid* (Feature 4 passes) — because the human never saw *this* cart.

---

### Feature 6 — `checkout_hash` Dispute Reconciliation & Programmable Refund Engine

**Protocol anchor:** *"The `checkout_hash` links these Mandates allowing them to be joined in the case of a Dispute"* + `requires_refundability` / `refund_period` fields + Mandate Receipts as evidence.

**The distinctive idea.** Disputes and chargebacks are the messiest, most manual part of payments. AP2 quietly hands us the join key (`checkout_hash`) to reconstruct the *entire* authorized truth of a transaction. We build an engine that, given a `checkout_hash`, reassembles the Checkout Mandate ↔ Payment Mandate ↔ Receipt tuple and **auto-adjudicates** the dispute: was it inside the refund window? did the settled cart match the signed cart? was there a valid receipt? This is automated **chargeback representment** — the evidence package builds itself from cryptographic artifacts, not screenshots.

**Build it:**

```python
def adjudicate_dispute(checkout_hash: str, claim: DisputeClaim, store) -> Adjudication:
    # 1. Reassemble the cryptographic truth via the join key
    checkout = store.checkout_by_hash(checkout_hash)
    payment  = store.payment_by_checkout_hash(checkout_hash)
    receipt  = store.receipt_for(payment.mandate_id)
    if not (checkout and payment and receipt):
        return Adjudication.escalate("incomplete mandate chain — manual review")

    evidence = []

    # 2. Refundability & window (from the signed checkout mandate itself)
    if claim.type == "REFUND_REQUEST":
        if not checkout.requires_refundability:
            evidence.append(("merchant_favored", "cart was signed non-refundable"))
        days_elapsed = (claim.filed_at - receipt.issued_at).days
        if days_elapsed > checkout.refund_period_days:
            return Adjudication.deny("outside signed refund window", evidence)
        return Adjudication.grant("within refund window; refundable cart", evidence)

    # 3. "Item not as described / not authorized" -> compare against WYSIWYS anchor
    if claim.type == "NOT_AUTHORIZED":
        if not verify_receipt_signature(receipt) or receipt.result != "success":
            return Adjudication.grant("no valid authorization receipt", evidence)  # consumer wins
        if not verify_wysiwys(payment.closed, checkout.shown_digest).ok:
            return Adjudication.grant("settled cart != approved cart", evidence)   # consumer wins
        evidence.append(("merchant_favored", "valid receipt + WYSIWYS match"))
        return Adjudication.deny("authorized & matches approved cart", evidence)
```

**Prove it:** file a refund one day after purchase on a 30-day refundable cart → auto-granted with the signed cart as evidence. File "not authorized" on a transaction with a valid receipt and matching WYSIWYS anchor → auto-denied with a machine-built evidence package. Break the chain (missing receipt) → escalated, never silently resolved.

---

### Feature 7 — Mandate Sandbox: Replay Simulator + Adversarial Constraint Fuzzer

**Protocol anchor:** The whole threat model (*all agents are potential attackers*) + Verification & Processing Rules + Double-Spend / rebind attacks.

**The distinctive idea.** Before a user ever signs an open mandate, you should be able to *prove* what an adversarial agent can and cannot do with it. We build a **sandbox** that (a) replays any mandate chain deterministically through Feature 4's verifier, and (b) **fuzzes** the closed mandate — mutating amounts, swapping payees, rebinding to other open mandates, replaying receipts, padding disclosures — and asserts that every malicious variant is rejected. It turns "we think the constraints are safe" into a machine-checked guarantee, and doubles as your regression harness.

**Build it:**

```python
class MandateFuzzer:
    def attacks(self, valid_closed: dict) -> list[Attack]:
        return [
            Attack("amount_inflate", mutate(valid_closed, "payment_amount.value_usd", x10)),
            Attack("payee_swap",     mutate(valid_closed, "payee.id", "attacker_merchant")),
            Attack("rebind_open",    set_field(valid_closed, "sd_hash", other_open_sd_hash())),
            Attack("checkout_swap",  set_field(valid_closed, "checkout_hash", foreign_hash())),
            Attack("kb_key_swap",    resign_with_wrong_key(valid_closed)),
            Attack("constraint_drop",drop_constraint(valid_closed, "com.aegis.spend_curve")),
            Attack("receipt_replay", replay_prior_receipt(valid_closed)),
            Attack("disclosure_flood", pad_disclosures(valid_closed, n=1000)),  # DoS / leak
        ]

    def run(self, valid_closed, ctx) -> FuzzReport:
        assert verify_delegation_chain(as_chain(valid_closed), ctx.checkout_jwt, ctx).ok, \
            "baseline valid mandate must pass"
        failures = []
        for atk in self.attacks(valid_closed):
            res = verify_delegation_chain(as_chain(atk.mandate), ctx.checkout_jwt, ctx)
            if res.ok:                                   # an attack that SUCCEEDED = a bug
                failures.append(atk.name)
        return FuzzReport(rejected=len(self.attacks(valid_closed)) - len(failures),
                          escaped=failures)              # escaped MUST be empty
```

**Prove it:** the baseline mandate verifies; all eight attack variants are rejected; `escaped == []`. Wire this into CI so any future constraint or verifier change that opens a hole fails the build.

---

## How the seven fit together

```
                     ┌─────────────────────────────────────────────┐
   Trusted Surface   │ F5  WYSIWYS: hash what the user actually saw │
   (user approves) ──┤     -> shown_digest embedded at delegation    │
                     └─────────────────────────────────────────────┘
                                        │ open mandate (SD-JWT VC, cnf key, constraints)
                                        ▼
   Agent binds ──►  F4  Delegation-Chain Verifier  ◄── F1 Constraint Compiler (typed rules)
   closed mandate        │  sig · sd_hash · checkout_hash · KB-JWT · constraints
                         ▼
                   F3  Scope Ledger (double-spend / receipt-driven scope reduction)
                         │
                         ▼
                   F5  WYSIWYS check (settled cart == approved cart?)
                         │  ALLOW
                         ▼
                   Settlement ── Verifier issues Mandate Receipt ──► F3 reduces scope
                         │
                         ▼
   Later:            F6  Dispute Reconciliation (join on checkout_hash, auto-adjudicate)

   Throughout dev:   F2  Minimal-Disclosure Solver (privacy)   F7  Sandbox/Fuzzer (assurance)
```

- **F4 is the spine** — nothing settles without a passing chain verification.
- **F1 feeds F4** — the constraint registry is what F4 evaluates in its final step.
- **F3 wraps F4** — reservation before, receipt-driven scope reduction after.
- **F5 guards the human boundary** F4 can't see (crypto-valid ≠ human-approved).
- **F6 consumes the receipts + `checkout_hash`** F3 and settlement produce.
- **F2 and F7 are cross-cutting** — privacy and adversarial assurance for everything.

---

## Recommended build order

1. **F4 — Delegation-Chain Verifier** first. Everything depends on it; without real verification the rest is theatre. Use the `sd-jwt` reference library + `cryptography` (ES256/EdDSA) and the AP2 sample mandates from `google-agentic-commerce/AP2/code/samples/python/`.
2. **F1 — Constraint Compiler**, so F4 has real constraints to evaluate (start with `spend_curve` and `mcc_allowlist`).
3. **F7 — Sandbox/Fuzzer** immediately after F4+F1, so every later change is regression-guarded.
4. **F3 — Scope Ledger** to make open mandates safely reusable (double-spend).
5. **F5 — WYSIWYS Oracle** to close the human-boundary gap.
6. **F6 — Dispute Engine** once receipts and `checkout_hash` linkage exist.
7. **F2 — Minimal-Disclosure Solver** last; it's an optimization/privacy refinement, not a gate.

**Milestone demo:** sign an open mandate with a `spend_curve` + `mcc_allowlist` constraint → agent binds a valid closed mandate → F4 verifies, F3 reserves, F5 confirms the cart the user saw, settlement issues a receipt, F3 reduces scope. Then run F7 and watch all eight attack variants bounce, and file a late refund through F6 and watch it auto-adjudicate from the signed cart. That single run demonstrates real SD-JWT crypto, protocol-native constraint design, double-spend safety, human-intent integrity, automated dispute logic, and adversarial assurance.

---

## Sources this track is built on

- AP2 — **Agent Authorization Framework** (Open/Closed mandates, SD-JWT VCs, Key Binding, `cnf`, OpenID4VP `transaction_data`, constraint verification rules, Mandate Receipts): `ap2-protocol.org/ap2/agent_authorization/`
- AP2 — **Security & Privacy Considerations** (manipulated checkout/payment, credential theft, double-spend, decoy digests, rainbow-table salting): `ap2-protocol.org/ap2/security_and_privacy_considerations/`
- AP2 reference implementation & runnable samples (human-present/not-present, cards/x402): `github.com/google-agentic-commerce/AP2`
- Standards referenced by AP2: SD-JWT (RFC 9901), Proof-of-Possession (RFC 7800), OpenID4VP/OpenID4VCI, ISO 18013-5/-7 mDocs, ISO 18245 MCC (for F1).

---

*Reference design. The cryptographic verification (F4) and dispute logic (F6) must be reviewed against the live AP2 spec version you target and by qualified security/compliance reviewers before any real-money use.*
