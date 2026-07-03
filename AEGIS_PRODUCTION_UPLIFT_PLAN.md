# AEGIS — Production Uplift & Differentiation Plan

**Date:** July 2026 · **Scope:** everything except deployment/infrastructure operations · **Format:** instructions only, no code

---

## 1. Positioning thesis — why AEGIS can be distinctive

The agentic payments stack has consolidated remarkably fast, and every layer of it has **deliberately left compliance out of scope**. That omission is AEGIS's market.

The current state of the stack (mid-2026):

- **AP2** (Google → donated to the **FIDO Alliance**, April 2026) is the authorization layer: signed Intent/Cart/Payment Mandates as W3C Verifiable Credentials. v0.2 added **"Human Not Present"** autonomous payments. AP2 explicitly *does not settle payments* and does not perform sanctions screening, AML monitoring, or liability resolution.
- **ACP** (OpenAI + Stripe + Meta, Apache 2.0) is the checkout/merchant layer, with spec releases through 2026-04-17 adding cart, feed, orders, authentication, and MCP. It lets merchants "apply custom approval logic" — i.e., it *assumes* a compliance engine exists on the merchant/PSP side but does not provide one.
- **x402** (Coinbase → Linux Foundation **x402 Foundation**, April 2026; founding members include Google, Microsoft, AWS, Cloudflare, Stripe, Visa, Mastercard) is the stablecoin settlement rail, with V2 batch settlement live.
- **UCP** (Google + Shopify et al., Tech Council now includes Amazon, Meta, Microsoft, Salesforce, Stripe) is winning the commerce-orchestration governance layer.
- Card networks are shipping their own agent primitives: **Visa** Agent Score, Agentic Registry, card-based MPP; **Mastercard** Agent Pay for Machines (AP4M).

Independent analysts name the gap explicitly. Everest Group's AP2 analysis notes that AP2 "must still be reconciled with PCI-DSS requirements, data residency laws, and financial crime monitoring obligations" and that it "does not yet solve who is liable" for mistaken or fraudulent agent transactions. The mid-2026 "Agentic Stack" analysis concludes: an operator deploying a payment-initiating agent in the EU by H2 2027 must simultaneously satisfy EU AI Act audit requirements, PSD3 SCA-equivalent authentication, MiCA stablecoin compliance, and the AI Liability Directive's evidentiary standard — and "the protocol stack does not yet make all of these natively compliant. The compliance gap is where engineering organizations underestimate their exposure." The IMF's 2026 note on agentic AI in payments frames the coming regulatory shift as **Know-Your-Customer → Know-Your-Agent (KYA)**.

**The one-sentence pitch AEGIS should own:** *"The protocols decide whether a payment is authorized. AEGIS decides whether it is lawful. Fail-closed, deterministic, and rail-agnostic — the compliance control plane the agentic stack forgot to build."*

Nothing in open source occupies this exact position today. Moov Watchman screens names against watchlists. Marble and Tazama monitor *settled or in-flight transactions*. AEGIS is the only design that interdicts at the **mandate layer, pre-settlement**, speaks AP2's cryptographic vocabulary natively, and produces regulator-grade, replayable evidence. Every workstream below either closes a credibility gap (things a production adopter would check in the first hour) or widens this differentiation moat.

---

## 2. Honest baseline — where the repo stands today

Current strengths: 14 implemented features across two tracks; a fail-closed 7-stage pipeline; Ed25519-signed hash-chained ledger with deterministic replay; SD-JWT/KB-JWT delegation verification with selective disclosure; constraint DSL with unknown-type-fails-closed semantics; mandate sandbox/fuzzer; 85 passing tests; two serious design documents; a FastAPI gateway; zero-infrastructure local runnability.

Current gaps a sophisticated evaluator would find in the first hour:

1. **All state is simulated.** The README admits Redis velocity counters are an "in-memory sorted store" and the PostgreSQL WORM ledger is an "in-memory list + JSONL sink." Nothing survives a process restart.
2. **All data is synthetic.** The OFAC/PEP lists, ownership graphs, and jurisdiction thresholds are hand-authored fixtures, not real feeds. A real sanctions engine lives or dies by its data plane.
3. **Protocol conformance is aspirational.** The AP2 track is built against AP2 concepts (pre-v0.2), not validated against the published spec or its reference implementation, and predates "Human Not Present" mandates.
4. **No performance evidence.** The design doc names a p99 < 120 ms budget, but there is no benchmark harness, no load profile, and no published numbers.
5. **Single-signal detection.** Structuring detection is windowed-velocity over one counterparty; real laundering is multi-account, multi-hop, and graph-shaped.
6. **Key management is demo-grade.** Ledger and quorum signing keys are generated and held in-process; there is no rotation, custody abstraction, or threat model document.
7. **No published evaluation.** There are 85 unit/integration tests but no adversarial benchmark with reported detection/false-positive rates against a recognized dataset.
8. **Repo signals.** Single squashed commit, no CI, no CONTRIBUTING/SECURITY files, no versioned releases — all things open-source adopters and hiring managers check before the code.

---

## 3. Research inputs this plan is built on

**Specifications & ecosystems to track and conform to**

- AP2 specification and reference implementation — `github.com/google-agentic-commerce/AP2`, spec at ap2-protocol.org; now stewarded by the FIDO Alliance's Agentic Authentication and Payments Technical Working Groups. v0.2 (April 2026) adds Human-Not-Present payments.
- ACP — `github.com/agentic-commerce-protocol/agentic-commerce-protocol` (OpenAI/Stripe/Meta), date-versioned specs with RFCs for capability negotiation, payment handlers, extensions.
- x402 — Linux Foundation x402 Foundation, V2 spec with batch settlement; Fireblocks contributed a security extension for request integrity and spend governance (a direct architectural sibling of AEGIS — study it).
- ISO 20022 message model (via the Tazama project's ISO 20022-centric transaction monitoring design) for the canonical transaction schema.

**Open-source projects to integrate with or learn from (never copy — integrate as dependencies or study designs)**

- **Moov Watchman** (`moov-io/watchman`) — production-grade OFAC/global watchlist screening, HTTP + Go library, and notably an **MCP endpoint for agent-driven screening**. Candidate pluggable screening provider.
- **OpenSanctions + yente** (`opensanctions/*`) — 401-source consolidated sanctions/PEP dataset (free for non-commercial use; licensing required commercially) with a self-hostable entity-matching API; `followthemoney` data model; `rigour` name-normalization tooling.
- **Tazama** — open-source ISO 20022 transaction monitoring (Linux Foundation charity project); reference for rule-processor architecture and message schemas.
- **Marble** — open-source real-time AML/fraud decision engine; reference for case-management and rule-authoring UX.
- **IBM AMLSim** — multi-agent synthetic transaction generator with labeled laundering patterns; the evaluation dataset for Workstream 5.
- **Blnk Watch** — a DSL for real-time monitoring rules; comparative reference for the constraint-compiler DSL's ergonomics.

**Research papers to incorporate (2025–2026)**

- *Whispers of Wealth: Red-Teaming Google's Agent Payments Protocol via Prompt Injection* — documented attack classes against AP2 flows (product-ranking manipulation, sensitive-data extraction). Source of the adversarial test corpus in WS5.
- *TessPay: Verify-then-Pay Infrastructure for Trusted Agentic Commerce* — escrow + cryptographic proof-of-execution before release; the conceptual basis for AEGIS's conditional-settlement verdict (WS5).
- *StepShield: When, Not Whether to Intervene on Rogue Agents* — temporal intervention metrics (how *early* in an agent trajectory a violation is caught); adopt its metric style for AEGIS's evaluation reports.
- IMF Note 2026/004, *How Agentic AI Will Reshape Payments* — Know-Your-Agent framing, verifiable agent identity linked to legal entities; the regulatory anchor for WS6.
- *AI Agents under EU Law: A Compliance Architecture for AI Providers* (arXiv 2604.04604) and the *SoK: Blockchain Agent-to-Agent Payments* (arXiv 2604.03733) — regulatory-architecture and threat-taxonomy references for WS8/WS9.
- *When AI Agents Collude Online* (arXiv 2511.06448) — multi-agent collusive fraud patterns; motivates cross-agent correlation in WS4.

---

## 4. Workstreams

Each workstream states the objective, the tasks (as instructions), and acceptance criteria. No code appears here by design; every task describes *what to build and how to know it's done*.

### WS1 — Protocol conformance: become the compliance layer *of* the stack, not beside it

**Objective:** AEGIS verdicts should consume and emit the actual artifacts of AP2 v0.2, with adapter seams for ACP and x402, so an adopter can drop AEGIS between their existing protocol handler and their settlement call without translation glue.

Tasks:

1. Obtain the AP2 v0.2 specification and reference implementation from the FIDO-stewarded repository. Produce a written conformance matrix: every mandate field, credential format, and lifecycle state in the spec, mapped to how AEGIS currently models it, with three columns — conformant, divergent, absent.
2. Close the divergences. Priority one is **Human-Not-Present (HNP) mandates**: define how AEGIS's risk scorer treats HNP differently (higher baseline risk, mandatory scope-ledger enforcement, stricter step-up thresholds), since HNP is precisely the mode regulators will scrutinize first.
3. Define a formal **adapter interface** at the gateway boundary: a small, documented contract ("give AEGIS an authorization artifact and transaction context; receive a verdict envelope"). Then specify — as design documents, not code yet — three adapters: AP2-native (mandate VCs in), ACP (checkout-session + payment-handler events in, using ACP's 2026-04-17 schema), and x402 (the 402 challenge/commitment pair in, referencing the Fireblocks security extension for field semantics).
4. Add a conformance test suite that replays the official AP2 sample flows from the reference repo through AEGIS end-to-end.
5. Join or at minimum monitor the FIDO Agentic Payments Technical Working Group mailing list and the ACP SEP process; log spec changes in a `CONFORMANCE.md` changelog so adopters can see the project tracks the standards.

Acceptance criteria: conformance matrix published in-repo; all AP2 reference sample flows produce verdicts without schema shims; HNP mandates exercise a visibly different policy path in tests; adapter contracts documented well enough that a third party could implement one.

### WS2 — Real sanctions data plane

**Objective:** replace hand-authored fixtures with real, refreshable watchlist data behind a pluggable provider interface, while keeping the zero-infrastructure demo mode.

Tasks:

1. Define a **screening-provider interface** with exactly the semantics the pipeline already needs (entity query in; scored candidate matches with list provenance out). AEGIS's own Jaro-Winkler + phonetic matcher becomes the built-in provider; demo fixtures become the "offline" provider.
2. Implement an **OpenSanctions/yente provider**: ingest the consolidated dataset (respecting its commercial licensing terms — document this clearly for adopters) or call a self-hosted yente instance. Adopt the FollowTheMoney entity model as the canonical internal entity schema so ownership graphs (the OFAC 50% Rule feature) can be populated from real relationship data instead of synthetic graphs.
3. Implement a **Moov Watchman provider** as the second integration, which also demonstrates ecosystem citizenship (Watchman is Apache-licensed and battle-tested in production).
4. Specify the **data-freshness contract**: lists refresh on a schedule; every verdict's evidence bundle records the list version/timestamp used; a stale-data condition (list older than a configured bound) triggers the fail-closed path with a distinct reason code rather than silently screening against old data. This "stale list ⇒ fail closed" rule is a differentiator worth documenting loudly — most screening tools fail open on stale data.
5. Rebuild the fuzzy-matching evaluation on real names: use OpenSanctions data plus `rigour` normalization to construct a labeled match/non-match benchmark; report precision/recall of the matcher and tune thresholds per script/language family (transliteration behaves very differently for Cyrillic, Arabic, and CJK names).

Acceptance criteria: pipeline runs unmodified against all three providers via configuration; every verdict records list provenance and version; published matcher precision/recall table; stale-data fail-closed behavior covered by tests.

### WS3 — Persistence and durable state

**Objective:** make the two simulated stores real without breaking the zero-infrastructure demo, and prove the ledger's integrity properties survive restarts.

Tasks:

1. Keep the existing in-memory implementations as the default "demo" backend, but define storage interfaces and add a real backend for each: a durable key-value/sorted-set store for velocity counters and the scope ledger, and an append-only relational store for the WORM ledger. Choose boring, embeddable-first technology so the "no external infrastructure" promise holds for evaluation (an embedded store locally; a server-grade store as configuration for adopters).
2. Specify the **WORM semantics precisely** in a design note: append-only, no UPDATE/DELETE paths in the data-access layer, hash chain computed over the serialized canonical form, chain head checkpointed. Include a documented recovery procedure: on startup, re-verify the chain from the last checkpoint and refuse to serve (fail closed) if verification fails.
3. Extend deterministic replay to work **across process restarts**: a decision recorded yesterday must replay byte-for-byte today from durable state alone. This is the property that turns "audit trail" from a claim into a demonstrable guarantee.
4. Define retention and export: evidence bundles exportable per-decision as a self-contained, signature-verifiable file a regulator or auditor could validate with only the public key.

Acceptance criteria: kill-and-restart test proves no verdict, ledger entry, or scope-ledger receipt is lost; chain verification failure blocks startup with a clear diagnostic; cross-restart replay test passes; single-decision evidence export verifies with an external, documented procedure.

### WS4 — Detection depth: from windowed velocity to graph- and behavior-aware analytics

**Objective:** upgrade financial-crime detection from single-counterparty velocity windows to the multi-account, multi-hop patterns real laundering uses — while preserving determinism and explainability, which are AEGIS's brand.

Tasks:

1. Introduce a **counterparty graph** maintained from the mandate/receipt stream: nodes for payers, beneficiaries, and agents; edges for transfers with amounts and timestamps. Specify it as an incremental, bounded structure (windowed retention) so it stays deterministic and memory-safe.
2. Implement graph-shaped structuring detection: fan-out/fan-in patterns (one source to many sub-threshold beneficiaries and the mirror image), circular flows, and rapid pass-through (in-and-out within a short window). Each detector must emit the same style of explainable reason codes with the concrete evidence subgraph attached.
3. Add **cross-agent correlation**: the collusion literature (arXiv 2511.06448) shows coordinated multi-agent fraud is a distinct threat; detect when multiple distinct agent identities operate on behalf of overlapping principals against the same beneficiary set within a window.
4. Align the canonical transaction schema with **ISO 20022** field naming (study Tazama's schema work) so bank-side adopters can map their pacs/pain messages without a translation dictionary.
5. Build the **evaluation harness on IBM AMLSim**: generate labeled synthetic transaction sets containing known laundering typologies, stream them through AEGIS, and report detection rate, false-positive rate, and — adopting StepShield's framing — *time-to-interdiction* (how many transactions into a scheme AEGIS fires). Publish these numbers in the README. An open-source compliance engine with published benchmark numbers against a recognized synthetic dataset is rare and instantly credible.
6. Optional, clearly-fenced ML track: if a learned risk model is added later, it must be a *feature input* to the deterministic scorer, never a verdict authority — document this as an architectural invariant ("the pipeline never blocks on an unexplainable signal"), because determinism-with-explainability is the moat against every ML-first fraud vendor.

Acceptance criteria: graph detectors covered by tests including at least fan-out, fan-in, cycle, and pass-through typologies; AMLSim benchmark report checked into the repo with reproduction instructions; ISO 20022 field mapping table published; cross-agent correlation demonstrable in the demo narrative.

### WS5 — Adversarial robustness: institutionalize the red team

**Objective:** convert the existing fuzzer into a standing adversarial benchmark aligned with published attack research, and add a conditional-settlement verdict for the highest-risk flows.

Tasks:

1. Build an **attack corpus** from the *Whispers of Wealth* AP2 red-teaming paper: reproduce each documented attack class (prompt-injection into mandate construction, ranking manipulation, data-extraction attempts) as fixture cases in the adversarial suite, each expected to be rejected with a specific reason code. Where the paper's attacks target flows AEGIS doesn't yet model, log them as tracked gaps rather than silently skipping.
2. Expand the mandate fuzzer from constraint mutation to **protocol-state fuzzing**: out-of-order mandate presentation, replayed receipts, expired-then-renewed credentials, delegation chains that exceed configured depth, disclosure sets that leak more than the minimal-disclosure solver would permit.
3. Keep the existing invariant — `escaped == []` wired into CI — and extend it: any new feature must ship with at least one adversarial case attempting to bypass it.
4. Add a **conditional-settlement verdict** inspired by TessPay's verify-then-pay model: alongside ALLOW/BLOCK/STEP_UP, define an ESCROW-style verdict where settlement is gated on post-authorization proof (delivery confirmation, receipt match against `checkout_hash`). Specify the state machine, timeout behavior (fail toward refund, never toward silent release), and how the dispute-reconciliation feature consumes it.
5. Adopt **temporal intervention metrics** (StepShield): for every multi-step attack scenario in the suite, record *at which step* AEGIS interdicts, and report the distribution. "We catch structuring at transfer 3 of 3 before settlement" is a measurably stronger claim than "we catch structuring."

Acceptance criteria: adversarial suite includes every reproducible attack class from the cited paper with expected reason codes; protocol-state fuzzing runs in CI; conditional-settlement verdict specified, implemented, tested, and added to the demo narrative; intervention-timing report generated by the evaluation harness.

### WS6 — Know-Your-Agent (KYA) identity layer

**Objective:** ride the KYC→KYA regulatory shift the IMF note describes; make agent identity a first-class pipeline input rather than an opaque string.

Tasks:

1. Design an **agent registry** model: each agent identity binds a public key/DID to a responsible legal entity, a declared capability scope, and a standing risk tier. Registration is out of band; the pipeline consumes registry lookups.
2. Extend the delegation-chain verifier to resolve the chain **to a registered root**: an unregistered or revoked agent identity anywhere in the chain fails closed with a distinct reason code.
3. Add **agent-level behavioral standing**: rolling statistics per agent identity (block rate, step-up rate, dispute rate) that feed the risk scorer as deterministic features. Design the interface so an external reputation signal (Visa's Agent Score is the market precedent) can plug in as a provider later without becoming a hard dependency.
4. Specify revocation: registry entries support suspension with immediate pipeline effect; document the propagation guarantee (next decision after revocation must see it — tie this to WS3's durable state).
5. Write a short position document, `KYA.md`, mapping this design to the IMF framing and to the EU AI Act's traceability expectations — this document is marketing and engineering at once, and it is the kind of artifact regulators and design partners actually read.

Acceptance criteria: pipeline rejects unregistered/revoked agents with tests; agent standing visibly moves risk scores in the demo; provider interface for external reputation documented; `KYA.md` published.

### WS7 — Performance engineering: turn the latency budget into evidence

**Objective:** the design doc promises p99 < 120 ms on the ALLOW path; production credibility requires measuring, publishing, and protecting that number.

Tasks:

1. Build a **benchmark harness**: synthetic mandate streams at configurable rates and mixes (clean/risky/adversarial), measuring per-stage and end-to-end latency percentiles, with results emitted as a machine-readable report plus a human-readable summary.
2. Profile the two known hot spots (screening and velocity/graph lookups) under the real backends from WS2/WS3, not the in-memory sims; document where the budget is spent stage by stage.
3. Define **degradation semantics** explicitly — this is where fail-closed systems earn trust or lose it: if the screening provider is slow or down, decisions queue or fail closed (configurable, documented default: fail closed) with a distinct reason code; nothing ever silently skips a pipeline stage on timeout. Write this into the design doc as a named invariant and test it with fault injection (kill the provider mid-load-test).
4. Add performance regression to CI in a lightweight form: a smoke benchmark with a generous threshold that fails the build if end-to-end latency regresses by a large factor, so performance is protected continuously even if full benchmarks run manually.
5. Publish the numbers: a `BENCHMARKS.md` with methodology, hardware notes, and honest caveats. Modest, reproducible, honest numbers beat impressive unreproducible ones — the LiteLLM-style "8ms at 1,000 RPS" marketing claim is exactly the genre to avoid.

Acceptance criteria: reproducible benchmark harness in-repo; per-stage latency breakdown published; fault-injection tests prove no stage is silently skipped under dependency failure; CI perf smoke test active.

### WS8 — Security hardening and threat model

**Objective:** the system that signs the audit ledger must itself withstand audit.

Tasks:

1. Write a **threat model document** (STRIDE or equivalent) covering: mandate forgery, ledger tampering, key compromise, replay, provider spoofing (a fake screening provider returning "no match"), and insider modification of policy. For each threat: current mitigation, residual risk, planned mitigation.
2. Abstract **key custody**: signing keys behind a keystore interface with an in-process implementation for demo mode and a documented contract for HSM/KMS-backed implementations. Specify **key rotation** for the ledger chain: how a rotation event is itself recorded in the chain so historical verification survives rotation.
3. Harden the gateway surface: strict schema validation with reject-on-unknown-fields (consistent with the constraint registry's fail-closed philosophy), rate limiting semantics specified (even if enforcement is deployment-level, the API contract should define behavior), and authenticated verdict responses (verdict envelopes signed so downstream settlement gates can verify AEGIS's output was not tampered with in transit).
4. Supply-chain hygiene: pin dependencies, add automated vulnerability scanning to CI, generate an SBOM per release, and sign release artifacts. These are checkbox items individually but collectively signal production seriousness.
5. Add a `SECURITY.md` with a disclosure policy.

Acceptance criteria: threat model published; keystore interface with rotation test (verify a chain spanning a rotation); signed verdict envelopes verified in the settlement-gate tests; CI includes dependency scanning; SBOM and signing wired into the release process.

### WS9 — Regulatory mapping expansion

**Objective:** extend the existing regulatory-mapping section from a US-centric sketch to the 2026–2027 landscape adopters actually face, feature by feature.

Tasks:

1. Build a **regulation × feature matrix**: rows are concrete obligations — BSA/FinCEN structuring and SAR duties, OFAC screening (including the expected wallet-screening guidance for stablecoin agent payments), PSD3/SCA dynamic linking, EU AI Act logging/traceability for high-risk systems, MiCA obligations where the x402/stablecoin adapter is in play, and the AI Liability Directive's evidentiary presumptions; columns are AEGIS features; cells state precisely what the feature does and does not satisfy. Honesty in the "does not" cells is what makes the document credible.
2. Version the **reason-code taxonomy** and treat it as a public contract: reason codes get a registry file with stable identifiers, human descriptions, regulatory citations, and a deprecation policy — because downstream case-management systems will key on them.
3. Map SAR drafting output fields to the actual FinCEN SAR schema so the auto-drafted SAR is a genuine pre-filled filing skeleton rather than prose.
4. Add jurisdiction packs as data: the conflict-of-laws resolver's thresholds and rules externalized into versioned, reviewable data files per jurisdiction, with provenance notes for every threshold (citation to the rule it encodes).

Acceptance criteria: matrix published; reason-code registry versioned with CI check preventing silent renames; SAR output field-mapped to the FinCEN schema; at least three jurisdiction packs (US, EU, India) externalized with citations.

### WS10 — Open-source launch readiness and market positioning

**Objective:** package everything above so that on launch day the repo reads as a serious infrastructure project, and the differentiation is legible in sixty seconds.

Tasks:

1. **Fix repository history.** A single "finally working" commit undermines everything else. Going forward, develop in small, well-messaged commits; retroactively, add the documents and features from this plan as a real commit trail. Enable branch protection and PR-based flow even solo — reviewers judge process signals.
2. Stand up **CI** running the full test suite, the adversarial suite, lint/type checks, dependency scanning, and the perf smoke test on every push, with badges in the README.
3. Add governance scaffolding: `LICENSE` (choose deliberately — Apache 2.0 matches the surrounding protocol ecosystem and eases enterprise adoption), `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue templates, and a public roadmap distilled from this plan.
4. Write the **positioning README**: open with the one-sentence pitch, a sixty-second architecture diagram, and a comparison table that is generous to neighbors — Watchman (name screening; AEGIS integrates it), Tazama/Marble (post-facto transaction monitoring; AEGIS interdicts pre-settlement at the mandate layer), Fireblocks x402 extension (request integrity for one rail; AEGIS is rail-agnostic policy + evidence). Positioning *with* the ecosystem, not against it, is both accurate and strategically smart for a project seeking adoption.
5. Produce demo assets that don't require running code: a recorded terminal demo of the five-scenario narrative, and the AMLSim benchmark report — these are what get shared.
6. Write one long-form technical launch post ("Why the agentic payments stack has no compliance layer — and what one looks like") anchored in the citations from §3, and prepare the repo for the scrutiny a Show HN / r/fintech launch brings.
7. Define versioning and release policy (semver; changelog per release; the reason-code registry and adapter contracts under compatibility guarantees).

Acceptance criteria: green CI with badges; all governance files present; README passes the "sixty-second test" with a fresh reader; comparison table reviewed for factual fairness; first tagged release cut with signed artifacts, SBOM, changelog, and benchmark report attached.

---

## 5. Sequencing

Dependencies are the only hard ordering constraint; within phases, workstreams can interleave.

**Phase 1 — Credibility floor.** WS3 (persistence) and WS2 (real data plane) first: everything else gains meaning once state is durable and data is real. Begin WS10 items 1–3 (history, CI, governance files) immediately — they cost little and compound.

**Phase 2 — Conformance and evidence.** WS1 (AP2 v0.2 conformance + adapter contracts) and WS7 (benchmarks on the now-real backends). At the end of this phase, the claim "a compliance control plane for AP2" is demonstrably true rather than thematic.

**Phase 3 — Depth and defense.** WS4 (graph detection + AMLSim benchmark) and WS5 (adversarial corpus + conditional settlement). These produce the two published reports (detection benchmark, intervention-timing report) that anchor the launch post.

**Phase 4 — Moat and launch.** WS6 (KYA), WS8 (threat model/keys), WS9 (regulatory matrix), then the WS10 launch package. KYA and the regulatory matrix are the pieces that make the startup story ("compliance layer for the agent economy") rather than merely a good repo.

---

## 6. Risks and open questions

- **Spec volatility.** AP2 moved to FIDO three months ago and v0.3 will come; the adapter-seam architecture (WS1) is the hedge — conformance lives in adapters, the pipeline stays stable. Track WG output continuously.
- **Data licensing.** OpenSanctions is free non-commercially but licensed commercially; the provider abstraction (WS2) plus the Watchman path keeps adopters unblocked either way. Document licensing implications prominently.
- **Scope discipline.** The temptation is to become a case-management suite (Marble's territory). Resist: AEGIS's identity is the deterministic pre-settlement decision point and its evidence. Emit webhooks/events for case managers; don't build one.
- **Determinism vs. detection power.** Graph and behavioral features must remain replayable; any nondeterministic input (wall-clock, external reputation calls) must be captured in the evidence bundle at decision time so replay uses recorded values. Make this a written invariant before WS4 begins.
- **Solo-maintainer signal.** Mitigate with process (CI, PRs, signed releases) and by upstreaming small contributions to neighbors (Watchman, AP2 samples) — ecosystem presence is a trust asset money can't buy.

---

## 7. Reference index

Protocols and stewardship: AP2 spec & reference (`google-agentic-commerce/AP2`, ap2-protocol.org; FIDO Alliance donation + v0.2/HNP, Apr 2026) · ACP (`agentic-commerce-protocol/agentic-commerce-protocol`; agenticcommerce.dev; Stripe/OpenAI/Meta) · x402 Foundation (Linux Foundation, Apr 2026; V2 batch settlement; Fireblocks security extension) · UCP (Google + Tech Council) · Visa Agent Score/Agentic Registry/MPP; Mastercard AP4M.

Open source: `moov-io/watchman` · OpenSanctions (`opensanctions`, `yente`, `followthemoney`, `rigour`) · Tazama · Marble · IBM AMLSim · Blnk Watch.

Research: *Whispers of Wealth* (AP2 red-teaming via prompt injection) · *TessPay* (verify-then-pay escrow) · *StepShield* (temporal intervention metrics) · IMF Notes 2026/004 (agentic AI in payments; Know-Your-Agent) · *AI Agents under EU Law* (arXiv 2604.04604) · *SoK: Blockchain Agent-to-Agent Payments* (arXiv 2604.03733) · *When AI Agents Collude Online* (arXiv 2511.06448).

Analysis: Everest Group on AP2's compliance/liability gaps · "The Agentic Stack" mid-2026 protocol-layer mapping (EU AI Act + PSD3 + MiCA + AI Liability Directive compounding; expected OFAC wallet-screening guidance ~2027).
