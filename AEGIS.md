# AEGIS

**Agentic Enforcement, Governance & Interdiction of Settlement**

A production-grade compliance and regulation layer for agent-to-agent (A2A) payments. AEGIS sits between an AI agent's payment authorization (Google AP2 mandates) and the settlement rail (card networks, stablecoins/x402, bank transfers), and enforces jurisdiction-aware regulatory policy, financial-crime controls, and non-repudiable liability attribution *before money moves* — fail-closed.

> **The gap this closes.** AP2 proves *what* was authorized and *who* signed it. It does **not** decide whether that authorization is *lawful in the relevant jurisdictions*, whether it looks like *structuring/laundering*, or *who is liable* when it goes wrong. AEGIS is the missing regulatory control plane.

---

## Table of Contents

1. [Why AEGIS](#1-why-aegis)
2. [System Architecture](#2-system-architecture)
3. [The 7 Flagship Features](#3-the-7-flagship-features)
4. [Data Models](#4-data-models)
5. [The Decision Pipeline](#5-the-decision-pipeline)
6. [API Contract](#6-api-contract)
7. [Regulatory Mapping](#7-regulatory-mapping)
8. [Tech Stack & Production Deployment](#8-tech-stack--production-deployment)
9. [Testing & Assurance](#9-testing--assurance)
10. [Repository Layout](#10-repository-layout)
11. [Build Roadmap](#11-build-roadmap)
12. [References](#12-references)

---

## 1. Why AEGIS

Agentic commerce breaks the core assumption of every payment system built to date: that a human is present, clicking "buy" on a trusted surface. When an autonomous agent initiates a payment on a user's behalf, three regulatory questions have no answer in the base protocol:

- **Lawfulness** — Is this transaction permitted given the buyer's domicile, the merchant's domicile, the settlement rail's domicile, and the sanctions/AML regimes that apply to all three?
- **Financial crime** — Does the *stream* of mandates from this agent look like structuring, layering, or scam-driven coercion — even if each individual mandate is validly signed?
- **Accountability** — When a mandate turns out to be mistaken, fraudulent, or injected, **who eats the loss** — the user, the agent developer, the merchant, or the PSP?

AEGIS answers all three deterministically, emits an auditable reason for every decision, and shifts liability with cryptographic evidence. It is designed to the operational bar a Tier-1 bank would demand: fail-closed, fully traceable, model-risk-governed, and regulator-inspectable.

---

## 2. System Architecture

```
        AI AGENT (buyer)                         AI AGENT (merchant / seller)
              │  AP2 Intent / Cart / Payment Mandate (W3C Verifiable Credential)
              ▼
    ┌───────────────────────────────────────────────────────────────────┐
    │                          AEGIS GATEWAY (mTLS)                        │
    │  ─ Mandate ingestion & signature verification (Ed25519 / VC proof)  │
    └───────────────────────────────────────────────────────────────────┘
              │
              ▼
    ┌───────────────────────────────────────────────────────────────────┐
    │                   PRE-SETTLEMENT DECISION PIPELINE                   │
    │  (deterministic, ordered, fail-closed — any hook failure = BLOCK)   │
    │                                                                     │
    │   1. Jurisdiction-Aware Mandate Firewall     (Feature 1)            │
    │   2. Sanctions / PEP Interdiction Engine      (Feature 2)           │
    │   3. Structuring & Velocity Analyzer          (Feature 3)           │
    │   4. Adversarial Mandate Detector             (Feature 4)           │
    │   5. Dynamic Risk Scorer + Step-Up Quorum     (Feature 5)           │
    │   6. Liability Attribution Engine             (Feature 6)           │
    │   7. Explainable Reason-Code Emitter          (Feature 7)           │
    └───────────────────────────────────────────────────────────────────┘
              │  ALLOW / STEP_UP / BLOCK  + signed decision envelope
              ▼
    ┌───────────────────────────────────────────────────────────────────┐
    │              SETTLEMENT ADAPTERS (provider-neutral)                  │
    │   Card networks · x402/stablecoin · SEPA/FedNow/UPI · simulator     │
    └───────────────────────────────────────────────────────────────────┘
              │
              ▼
    ┌───────────────────────────────────────────────────────────────────┐
    │        APPEND-ONLY HASH-CHAINED AUDIT LEDGER (Ed25519-signed)       │
    │            every decision reconstructable & tamper-evident          │
    └───────────────────────────────────────────────────────────────────┘
```

**Design invariants**

- **Single authority path.** There is no code path to settlement that bypasses the pipeline. A settlement adapter physically cannot be invoked without a valid signed decision envelope.
- **Fail-closed.** If any stage errors, times out, or a dependency (sanctions list, Redis counter) is unavailable, the transaction is `BLOCK`ed, not allowed through.
- **Deterministic core.** The policy decision is a pure function of `(mandate, world_state_snapshot, ruleset_version)`. Same inputs → same decision → replayable for audit and dispute.
- **ML on the periphery.** Machine-learning models (risk score, injection detector) only ever *raise* risk or *add* evidence; a model can never *override* a hard deterministic block. This keeps the system SR 11-7 governable.

---

## 3. The 7 Flagship Features

Each feature below encodes real-world finance logic that goes beyond generic "policy engine" plumbing.

### Feature 1 — Jurisdiction-Aware Mandate Firewall (Conflict-of-Laws Resolver)

**The out-of-the-box idea:** a single agent transaction can touch four jurisdictions at once — the buyer's domicile, the merchant's domicile, the settlement rail's incorporation, and the data-residency zone. Most systems check one. AEGIS resolves all four and applies the *strictest binding* rule (a real conflict-of-laws principle).

**Real finance logic it encodes:**
- **FATF Recommendation 16 (Travel Rule)** — originator/beneficiary information must accompany transfers above the local threshold (USD/EUR 1,000 in most regimes; USD 3,000 legacy US). AEGIS computes the applicable threshold from the *most conservative* touched jurisdiction and demands the required attestation fields on the mandate, else `BLOCK`.
- **Data residency** — if the buyer is EU-domiciled, PII in the mandate must be processed in-region (GDPR Art. 44–49). AEGIS routes such mandates to the EU processing enclave and blocks cross-border evaluation.
- **Rail eligibility** — e.g., a stablecoin rail may be lawful for a US↔SG transfer but not for a corridor touching a restricted jurisdiction.

**Decision logic (Rego):**

```rego
package aegis.jurisdiction

import future.keywords.if

# Strictest-binding threshold across all touched jurisdictions
applicable_travel_rule_threshold := min([t |
    some j in input.touched_jurisdictions
    t := data.fatf.travel_rule_threshold[j.iso]
])

deny[reason] if {
    input.amount.value_usd >= applicable_travel_rule_threshold
    not travel_rule_fields_present
    reason := {
        "code": "AGENT.JUR.TRAVELRULE_MISSING",
        "detail": sprintf("Transfer of %.2f USD >= threshold %.2f; originator/beneficiary attestation absent",
                          [input.amount.value_usd, applicable_travel_rule_threshold])
    }
}

deny[reason] if {
    input.buyer.residency == "EU"
    input.processing_region != "EU"
    reason := {"code": "AGENT.JUR.DATA_RESIDENCY", "detail": "EU PII processed outside EU enclave"}
}

travel_rule_fields_present if {
    input.mandate.originator.legal_name
    input.mandate.originator.account_ref
    input.mandate.beneficiary.legal_name
}
```

---

### Feature 2 — Sanctions & PEP Interdiction Engine (with the OFAC 50% Rule + fuzzy matching)

**The out-of-the-box idea:** agents present *identities* (agent DIDs, merchant legal names, beneficiary wallets) that are transliterated, abbreviated, or deliberately obfuscated. A naïve exact-match sanctions screen is trivially evaded. AEGIS screens with phonetic + edit-distance matching and — crucially — implements the **OFAC 50% Rule**: an entity is blocked if it is 50%-or-more owned, in aggregate, by sanctioned parties, even if the entity itself is not listed.

**Real finance logic it encodes:**
- Screening against **OFAC SDN**, **EU Consolidated**, and **UN Security Council** lists.
- **Fuzzy name matching**: Jaro-Winkler for typos/transliteration + Double Metaphone for phonetic equivalence, with a tunable score threshold to manage the false-positive/false-negative tradeoff (a genuine compliance-ops concern — over-blocking is a real business cost).
- **PEP screening**: politically-exposed-person flags trigger enhanced due diligence (EDD), not an automatic block.
- **Aggregated beneficial-ownership** graph traversal for the 50% rule.

**Matching core (Python):**

```python
from jellyfish import jaro_winkler_similarity, metaphone

def screen_name(candidate: str, watchlist: list[WatchlistEntry]) -> ScreenResult:
    cand_phon = metaphone(candidate)
    hits = []
    for entry in watchlist:
        jw = jaro_winkler_similarity(candidate.lower(), entry.name.lower())
        phon = entry.phonetic == cand_phon
        # Weighted: a phonetic match tightens the acceptance band
        score = jw + (0.06 if phon else 0.0)
        if score >= SANCTIONS_MATCH_THRESHOLD:      # e.g. 0.92, tuned per audit
            hits.append(Hit(entry, score, is_pep=entry.is_pep))
    return ScreenResult(hits=hits)

def ofac_50_percent(entity_id: str, graph: OwnershipGraph) -> bool:
    """Blocked if aggregate sanctioned ownership >= 50%."""
    sanctioned_share = sum(
        edge.pct for edge in graph.owners_of(entity_id)
        if graph.is_sanctioned(edge.owner_id)
    )
    return sanctioned_share >= 0.50
```

A sanctions hit is a **hard block** (regulatory strict liability) — no ML model or risk score can lift it.

---

### Feature 3 — Structuring & Velocity Analyzer (Financial-Crime Detection at the *Intent* Layer)

**The out-of-the-box idea:** everyone runs fraud detection *after* settlement, on completed transactions. An agent that programmatically slices a large payment into many sub-threshold transfers ("smurfing"/structuring) is caught too late. AEGIS analyzes the **intent-mandate stream** — the agent's *stated future spending plans* — and detects structuring *before the first transfer settles*.

**Real finance logic it encodes:**
- **Structuring detection** against reporting thresholds: US CTR (Currency Transaction Report) at USD 10,000; deliberate slicing to stay under it is itself a federal offense (31 U.S.C. §5324). AEGIS flags N-transfer clusters that (a) share a beneficiary, (b) fall in a short window, and (c) sum above threshold while each sits below it.
- **Velocity limits**: sliding-window counters (per-agent, per-beneficiary, per-corridor) for count and value — daily/monthly caps enforced fail-closed.
- **Layering signal**: rapid A→B→C→… hops through intermediary agents with near-zero holding time (classic placement/layering).

**Sliding-window structuring detector (Redis + Python):**

```python
def detect_structuring(agent_id: str, beneficiary: str, amount_usd: float,
                       redis: Redis) -> StructuringSignal:
    key = f"struct:{agent_id}:{beneficiary}"
    now = time.time()
    # Sorted set scored by timestamp; each member is "ts:amount"
    redis.zadd(key, {f"{now}:{amount_usd}": now})
    redis.zremrangebyscore(key, 0, now - STRUCTURING_WINDOW_SECONDS)  # e.g. 24h
    redis.expire(key, STRUCTURING_WINDOW_SECONDS)

    members = redis.zrange(key, 0, -1)
    total = sum(float(m.split(":")[1]) for m in members)
    each_below = all(float(m.split(":")[1]) < CTR_THRESHOLD for m in members)

    if len(members) >= MIN_CLUSTER and each_below and total >= CTR_THRESHOLD:
        return StructuringSignal(
            triggered=True,
            code="AGENT.AML.STRUCTURING_SUSPECTED",
            detail=f"{len(members)} sub-threshold transfers to {beneficiary} "
                   f"summing {total:.2f} USD in window (each < {CTR_THRESHOLD})",
            recommend="FILE_SAR",   # generate a Suspicious Activity Report draft
        )
    return StructuringSignal(triggered=False)
```

When triggered, AEGIS auto-drafts a **SAR (Suspicious Activity Report)** payload for the compliance team — turning detection into an actionable regulatory artifact.

---

### Feature 4 — Adversarial Mandate Detector (Prompt-Injection Firewall for Mandate Construction)

**The out-of-the-box idea:** AP2 cryptographically guarantees *what is executed* but not *how the decision was made*. A merchant agent (or a compromised tool) can inject instructions during mandate construction so the buyer agent builds a cart that doesn't match the user's true intent. AEGIS detects **semantic drift** between the signed **Intent Mandate** (the user's real goal) and the **Cart Mandate** (what the agent actually selected).

**Real finance logic + security logic it encodes:**
- **Intent↔Cart semantic consistency**: embed the user's natural-language intent and the resolved cart; if cosine distance exceeds a threshold, the cart has drifted from stated intent → step-up or block. (e.g. intent "espresso machine under £200", cart resolves to a £2,000 gift card → drift.)
- **Injection-signature scan**: the intent's natural-language field is scanned for known injection patterns ("ignore previous", tool-directive strings, hidden unicode) — a mandate field is *data*, never *instructions*.
- **Price/refundability tamper check**: cart total and refund terms are validated against the intent constraints that were signed *first*, so a post-hoc price inflation is caught.

```python
def detect_adversarial(intent: IntentMandate, cart: CartMandate,
                       embedder, injection_rules) -> AdversarialSignal:
    drift = 1 - cosine(embedder(intent.natural_language_description),
                       embedder(cart.summary_text()))
    inj = injection_rules.scan(intent.natural_language_description)
    price_breach = cart.total_usd > intent.max_value_usd if intent.max_value_usd else False

    if drift > INTENT_DRIFT_THRESHOLD or inj.matched or price_breach:
        return AdversarialSignal(
            triggered=True,
            code="AGENT.SEC.INTENT_DRIFT",
            detail=f"drift={drift:.2f} injection={inj.matched} price_breach={price_breach}",
            severity="HIGH" if (inj.matched or price_breach) else "MEDIUM",
        )
    return AdversarialSignal(triggered=False)
```

This directly operationalizes the gap identified in the *Whispers of Wealth* red-teaming research: constrain *how* the mandate was constructed, not only whether it was signed.

---

### Feature 5 — Dynamic Risk Scorer + Cryptographic Step-Up Quorum (Four-Eyes for Agents)

**The out-of-the-box idea:** not every transaction is allow/block — most real compliance is *graduated*. AEGIS computes a continuous risk score and, above configurable bands, escalates to **step-up authorization**: a high-value or high-risk mandate requires an **m-of-n cryptographic quorum** (maker-checker / four-eyes principle from bank operations), where approvers can be humans *or* designated guardian agents, each contributing an Ed25519 signature.

**Real finance logic it encodes:**
- **Strong Customer Authentication (PSD2 SCA)** — dynamic linking of the auth to the specific amount + payee; a step-up challenge is bound to the exact cart hash, so approval can't be replayed for a different transaction.
- **Segregation of duties / four-eyes** — the agent that *initiates* (maker) can never be an approver (checker). Enforced structurally.
- **Risk-based authentication** — low-risk, low-value flows pass frictionlessly; risk is a weighted blend of amount, corridor risk, counterparty novelty, velocity pressure, and the ML model's score.

```python
def decide_authorization(ctx: DecisionContext) -> AuthDecision:
    score = risk_model.score(ctx)              # 0..100, ML-assisted but bounded
    if score < LOW_BAND:
        return AuthDecision.ALLOW
    if score < STEPUP_BAND:
        # Bind challenge to this exact cart — SCA dynamic linking
        return AuthDecision.step_up(
            quorum=required_quorum(score),      # e.g. 2-of-3
            bound_to=ctx.cart_hash,
            eligible_approvers=ctx.guardians_excluding(ctx.initiator_agent),  # four-eyes
        )
    return AuthDecision.BLOCK

def verify_quorum(challenge: StepUpChallenge, sigs: list[Signature]) -> bool:
    valid = {s.signer for s in sigs
             if ed25519_verify(s.signer_pubkey, challenge.cart_hash, s.value)
             and s.signer != challenge.initiator}          # maker != checker
    return len(valid) >= challenge.required_m
```

---

### Feature 6 — Liability Attribution Engine (The "Who Pays When It Breaks" Ledger)

**The out-of-the-box idea — the crown jewel.** The single biggest unsolved regulatory question in agentic payments (flagged by Everest Group and others) is *liability*: when a transaction is fraudulent or mistaken, who bears the loss? AEGIS resolves this **at authorization time** by computing a **liability apportionment** across user / agent-developer / merchant / PSP from the mandate's signature chain and provenance — modeled on the **EMV liability shift** (whoever is the "least secure party" bears the loss).

**Real finance logic it encodes:**
- **EMV-style liability shift** — the party that failed to meet the security bar carries liability. If the merchant agent didn't verify the payment mandate challenge, liability shifts to the merchant; if the user's guardian skipped a required step-up, it shifts to the user.
- **Reg E / Reg Z consumer-protection floors** — a consumer's liability for unauthorized transfers is statutorily capped; AEGIS never apportions above the legal cap to the consumer.
- **Provenance weighting** — each mandate in the chain (Intent→Cart→Payment) carries a signer and an attestation of controls met; the engine walks the chain and assigns weights.

```python
def apportion_liability(chain: MandateChain, controls: ControlEvidence) -> LiabilityBreakdown:
    weights = {"user": 0.0, "agent_developer": 0.0, "merchant": 0.0, "psp": 0.0}

    # EMV-style: unmet control shifts weight to the responsible party
    if not controls.merchant_verified_payment_challenge:
        weights["merchant"] += 0.6
    if not controls.user_completed_required_stepup:
        weights["user"] += 0.3
    if not controls.agent_sdk_pinned_intent_constraints:
        weights["agent_developer"] += 0.4
    if not controls.psp_ran_sanctions_screen:
        weights["psp"] += 0.5

    weights = normalize(weights)
    # Reg E / Reg Z consumer floor: cap consumer exposure for unauthorized txns
    if chain.is_unauthorized and weights["user"] > REG_E_CONSUMER_CAP_RATIO:
        overflow = weights["user"] - REG_E_CONSUMER_CAP_RATIO
        weights["user"] = REG_E_CONSUMER_CAP_RATIO
        weights = redistribute(overflow, to=["merchant", "psp", "agent_developer"])

    return LiabilityBreakdown(weights=weights, basis="EMV_SHIFT+REG_E_FLOOR")
```

The result is written into the signed decision envelope, so if a dispute arises later, the liability split was **pre-agreed and cryptographically recorded** — not litigated after the fact.

---

### Feature 7 — Explainable Reason-Code Emitter (Regulator-Grade Audit Trail)

**The out-of-the-box idea:** regulators (and internal model-risk teams under **SR 11-7**) require that an automated decision be *explainable* — not just "blocked" but *why*, in standardized codes and human-readable rationale. Every AEGIS decision emits **ISO 20022-style external reason codes** plus a plain-language explanation, chained into a tamper-evident ledger.

**Real finance logic it encodes:**
- **ISO 20022 external reason codes** — machine-readable, network-portable rejection/hold codes so downstream systems and dispute processes speak a common language.
- **SR 11-7 model risk management** — every ML contribution to a decision is logged with the model version, feature inputs, and score, so the decision is reproducible and the model is auditable.
- **Hash-chained append-only ledger** — each decision envelope includes the hash of the previous one (like a blockchain block header), making after-the-fact tampering detectable.

```python
def emit_decision_envelope(ctx, verdict, signals, liability, prev_hash) -> DecisionEnvelope:
    env = DecisionEnvelope(
        decision_id=uuid4(),
        mandate_id=ctx.mandate_id,
        verdict=verdict,                          # ALLOW | STEP_UP | BLOCK
        reason_codes=[s.code for s in signals],   # e.g. ["AGENT.AML.STRUCTURING_SUSPECTED"]
        rationale=humanize(signals),              # plain-English narrative
        model_provenance={m.name: m.version for m in ctx.models_used},  # SR 11-7
        liability=liability.weights,
        ruleset_version=ctx.ruleset_version,
        world_snapshot_hash=ctx.snapshot_hash,    # replayability
        prev_envelope_hash=prev_hash,             # hash chaining
        ts=utcnow(),
    )
    env.signature = ed25519_sign(SIGNING_KEY, env.canonical_bytes())
    ledger.append(env)                            # append-only, WORM storage
    return env
```

Any auditor can take a decision, re-load the pinned `ruleset_version` and `world_snapshot_hash`, replay the pipeline, and get the identical verdict — the gold standard for regulatory defensibility.

---

## 4. Data Models

```python
# --- Inbound (AP2-aligned) ---
class IntentMandate(BaseModel):
    mandate_id: str
    natural_language_description: str
    max_value_usd: float | None
    allowed_merchants: list[str]
    requires_refundability: bool
    intent_expiry: datetime
    signer_did: str
    proof: VerifiableCredentialProof          # W3C VC / Ed25519

class CartMandate(BaseModel):
    mandate_id: str
    intent_ref: str
    line_items: list[LineItem]
    total_usd: float
    refund_period_days: int
    merchant_did: str
    proof: VerifiableCredentialProof

class PaymentMandate(BaseModel):
    mandate_id: str
    cart_ref: str
    instrument: PaymentInstrument             # card | x402/stablecoin | bank
    human_present: bool
    settlement_rail: str
    proof: VerifiableCredentialProof

# --- Outbound (AEGIS-native) ---
class DecisionEnvelope(BaseModel):
    decision_id: str
    mandate_id: str
    verdict: Literal["ALLOW", "STEP_UP", "BLOCK"]
    reason_codes: list[str]
    rationale: str
    model_provenance: dict[str, str]
    liability: dict[str, float]
    ruleset_version: str
    world_snapshot_hash: str
    prev_envelope_hash: str
    ts: datetime
    signature: str
```

**Audit ledger table (PostgreSQL, append-only):**

```sql
CREATE TABLE decision_ledger (
    seq             BIGSERIAL PRIMARY KEY,
    decision_id     UUID        NOT NULL UNIQUE,
    mandate_id      TEXT        NOT NULL,
    verdict         TEXT        NOT NULL CHECK (verdict IN ('ALLOW','STEP_UP','BLOCK')),
    reason_codes    TEXT[]      NOT NULL,
    liability       JSONB       NOT NULL,
    ruleset_version TEXT        NOT NULL,
    envelope        JSONB       NOT NULL,
    prev_hash       BYTEA       NOT NULL,
    this_hash       BYTEA       NOT NULL,
    signature       BYTEA       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Enforce immutability: revoke UPDATE/DELETE at the role level; WORM via
-- append-only trigger + periodic anchoring of this_hash to external notary.
REVOKE UPDATE, DELETE ON decision_ledger FROM aegis_app;
```

---

## 5. The Decision Pipeline

The pipeline is a strict, ordered sequence. Hard blocks short-circuit; graduated signals accumulate.

```
verify_signatures(mandate)                 → fail = BLOCK  [AGENT.SIG.INVALID]
  │
Feature 1: jurisdiction_firewall()         → deny = BLOCK  (hard)
  │
Feature 2: sanctions_interdiction()        → hit  = BLOCK  (hard, strict liability)
  │
Feature 3: structuring_velocity()          → signal accumulates (+ SAR draft)
  │
Feature 4: adversarial_detector()          → HIGH = BLOCK, MEDIUM = raise risk
  │
Feature 5: risk_score + step_up_quorum()   → band → ALLOW | STEP_UP | BLOCK
  │
Feature 6: apportion_liability()           → attach to envelope
  │
Feature 7: emit_decision_envelope()        → sign, hash-chain, append to ledger
  │
  ▼
return verdict  →  settlement adapter (only if ALLOW / quorum satisfied)
```

**Fail-closed guarantee (orchestrator):**

```python
async def evaluate(mandate) -> DecisionEnvelope:
    try:
        ctx = build_context(mandate)          # pins ruleset + world snapshot
        assert verify_signatures(mandate), "AGENT.SIG.INVALID"
        for stage in PIPELINE:                # ordered, hard blocks short-circuit
            verdict = await stage.run(ctx)
            if verdict.is_hard_block:
                return finalize(ctx, verdict)
        return finalize(ctx, resolve_graduated(ctx))
    except Exception as e:                     # ANY failure → BLOCK, never allow
        return finalize_block(mandate, code="AGENT.SYS.FAILCLOSED", detail=str(e))
```

---

## 6. API Contract

```
POST /v1/mandates/evaluate
  Body:   { intent, cart, payment }          # AP2 mandate chain
  Return: 200 DecisionEnvelope               # verdict + reason codes + liability
          422 { reason_codes }               # malformed / signature failure

POST /v1/stepup/{challenge_id}/approve
  Body:   { signer_did, signature }          # one quorum contribution
  Return: 200 { satisfied: bool, remaining: int }

GET  /v1/ledger/{decision_id}
  Return: 200 DecisionEnvelope               # full audit record, verifiable

POST /v1/ledger/{decision_id}/replay
  Return: 200 { reproduced_verdict, matches_original: bool }   # audit replay

GET  /v1/sar/drafts                          # queued Suspicious Activity Reports
GET  /healthz  /readyz  /metrics             # ops
```

All endpoints are mTLS-authenticated; agent identities are DIDs bound to Ed25519 keys.

---

## 7. Regulatory Mapping

| AEGIS Feature | Regulations / Standards Encoded |
|---|---|
| 1 · Jurisdiction Firewall | FATF Rec. 16 (Travel Rule), GDPR Art. 44–49 (data residency), conflict-of-laws |
| 2 · Sanctions Interdiction | OFAC SDN + 50% Rule, EU Consolidated List, UN SC List, PEP/EDD |
| 3 · Structuring Analyzer | BSA / 31 U.S.C. §5324, FinCEN CTR & SAR, EU AMLD6 |
| 4 · Adversarial Detector | (security) prompt-injection resistance; intent-authenticity per AP2 threat model |
| 5 · Risk + Step-Up Quorum | PSD2 SCA (dynamic linking), four-eyes / segregation of duties |
| 6 · Liability Engine | EMV liability shift, Reg E, Reg Z consumer-protection floors |
| 7 · Reason-Code Emitter | ISO 20022 external codes, SR 11-7 model risk management, WORM audit |

---

## 8. Tech Stack & Production Deployment

**Core service**
- **Language:** Python 3.12 + FastAPI (async), `uvicorn`/`gunicorn` workers
- **Policy engine:** Open Policy Agent (OPA) with Rego for deterministic hard rules; bundle-versioned so `ruleset_version` is pinnable
- **AP2:** `google-agentic-commerce/AP2` Pydantic models + VC verification
- **ML models:** risk scorer + intent-drift embedder served via ONNX runtime, versioned in a model registry (MLflow) for SR 11-7 traceability

**State**
- **PostgreSQL** — append-only decision ledger, ownership graph, ruleset registry
- **Redis** — sliding-window velocity/structuring counters, step-up challenge store
- **Kafka** — mandate-stream ingestion (structuring analysis needs the stream, not point events)
- **WORM object store** (S3 Object Lock) — periodic ledger hash anchoring / external notarization

**Crypto & identity**
- Ed25519 for decision-envelope signing and quorum signatures
- W3C Verifiable Credentials for AP2 mandate proofs
- mTLS between all agents and the gateway; DID-based agent identity

**Observability & ops**
- OpenTelemetry tracing end-to-end (each decision = one trace)
- Prometheus metrics (`aegis_decisions_total{verdict}`, block reasons, p99 latency)
- Grafana dashboards for compliance ops (SAR queue depth, sanctions-hit rate, false-positive rate)
- Structured JSON logs shipped to a SIEM

**Deployment**
- Containerized (Docker), orchestrated on **Kubernetes**
- HPA on decision throughput; PodDisruptionBudgets for the gateway
- Blue/green ruleset rollout — a new Rego bundle is canaried before promotion
- Secrets in Vault / KMS-backed; signing keys in an HSM or cloud KMS (keys never in app memory as raw bytes)
- Multi-region with the **EU processing enclave** for data-residency-bound mandates

**Latency budget:** target **p99 < 120 ms** for the full pipeline on the ALLOW path (sanctions + velocity are the hot spots — both are Redis/in-memory backed).

---

## 9. Testing & Assurance

- **Golden-file replay tests** — a corpus of mandates with expected verdicts; CI fails if a ruleset change silently alters a decision.
- **Property-based tests** (Hypothesis) — invariant: *no input ever yields settlement without a valid ALLOW/quorum envelope.*
- **Adversarial test suite** — injected mandates, transliterated sanctioned names, structuring clusters, replayed step-up challenges — each must be caught.
- **Fail-closed chaos tests** — kill Redis / OPA / the sanctions feed mid-request; assert every in-flight decision resolves to `BLOCK`.
- **Ledger integrity test** — tamper with any historical envelope; the hash chain must break and be detected on the next `replay`.
- **Model-risk tests** — assert an ML score can never lift a hard deterministic block (SR 11-7 guardrail).

---

## 10. Repository Layout

```
aegis/
├── gateway/                  # FastAPI app, mTLS, mandate ingestion
│   ├── main.py
│   └── verify.py             # VC / Ed25519 signature verification
├── pipeline/
│   ├── orchestrator.py       # fail-closed ordered pipeline
│   ├── f1_jurisdiction.py
│   ├── f2_sanctions.py
│   ├── f3_structuring.py
│   ├── f4_adversarial.py
│   ├── f5_risk_stepup.py
│   ├── f6_liability.py
│   └── f7_reasoncodes.py
├── policy/                   # Rego bundles, versioned
│   ├── jurisdiction.rego
│   ├── travel_rule.rego
│   └── bundle.manifest
├── models/                   # risk scorer, intent-drift embedder (ONNX + registry)
├── ledger/                   # append-only store, hash chaining, replay
├── adapters/                 # card / x402 / SEPA / simulator settlement
├── data/                     # sanctions lists loader, ownership graph, FATF thresholds
├── deploy/                   # Dockerfiles, k8s manifests, Helm chart
├── tests/                    # golden-file, property, adversarial, chaos
└── AEGIS.md                  # this document
```

---

## 11. Build Roadmap

**Phase 0 — Skeleton (week 1)**
Stand up the gateway, ingest an AP2 mandate chain from `google-agentic-commerce/AP2`, verify signatures, return a stubbed `ALLOW` envelope written to the ledger.

**Phase 1 — Hard controls (weeks 2–3)**
Feature 1 (jurisdiction/travel rule in Rego) + Feature 2 (sanctions with fuzzy matching + 50% rule). These are the deterministic, block-or-pass core. Ship the append-only hash-chained ledger (Feature 7 substrate).

**Phase 2 — Financial-crime intelligence (weeks 4–5)**
Feature 3 (structuring/velocity over a Kafka mandate stream) with SAR draft generation. Feature 4 (adversarial/intent-drift detector) with the embedding model.

**Phase 3 — Graduated authorization & liability (weeks 6–7)**
Feature 5 (risk scorer + step-up quorum with four-eyes) and Feature 6 (liability apportionment). Wire full reason-code emission (Feature 7) and audit replay.

**Phase 4 — Production hardening (week 8+)**
Chaos/fail-closed tests, observability dashboards, blue/green ruleset rollout, HSM-backed signing, EU enclave, load test to the p99 budget.

**Demo narrative for a portfolio/interview:** run one clean transaction (ALLOW), one structuring cluster (BLOCK + auto-SAR), one transliterated sanctioned beneficiary (interdicted by fuzzy match + 50% rule), and one prompt-injected cart that drifts from intent (caught by Feature 4) — then open the ledger and *replay* a decision to prove determinism. That end-to-end story demonstrates protocol fluency, financial-crime domain knowledge, and production engineering in one sitting.

---

## 12. References

- Google Cloud — *Announcing Agent Payments Protocol (AP2)* and the `google-agentic-commerce/AP2` reference implementation (mandate schemas, VC model).
- *SoK: Blockchain Agent-to-Agent Payments* (arXiv:2604.03733) — landscape survey.
- *Compliance-Aware Agentic Payments on Stablecoin Rails* (arXiv:2605.00071) — programmable-compliance mediator.
- *Whispers of Wealth: Red-Teaming Google's AP2 via Prompt Injection* (arXiv:2601.22569) — the "how the decision was made" gap (Feature 4).
- *Agentic AI Governance Framework for Real-Time Fraud Detection* (2026) — governance-layer architecture (perception/reasoning/governance).
- *How Agentic AI Will Reshape Payments*, IMF Notes 2026/004 — multi-agent, cross-jurisdiction compliance framing.
- Everest Group — *Google's AP2: A New Chapter in Agentic Commerce* — open regulatory & liability gaps (Features 1 & 6).
- FATF Recommendation 16; OFAC 50% Rule guidance; 31 U.S.C. §5324; EU AMLD6; PSD2 RTS on SCA; ISO 20022 external code sets; Federal Reserve SR 11-7.
- `EfeDurmaz16/sardis` — open authority-layer reference (fail-closed pre-execution pipeline, signed audit ledger).

---

*AEGIS is a reference design. Sanctions screening, SAR filing, and liability determinations in a live financial system must be reviewed by qualified compliance and legal counsel before production use.*
