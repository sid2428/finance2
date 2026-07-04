# AEGIS Roadmap

Distilled from the production uplift plan (`AEGIS_PRODUCTION_UPLIFT_PLAN.md`).
Sequenced by dependency; checkboxes track shipped work.

## Phase 1 — Credibility floor

- [x] Governance: LICENSE (Apache-2.0), CONTRIBUTING, SECURITY, CODE_OF_CONDUCT
- [x] CI: tests + adversarial suite on every push
- [x] **WS3 Persistence**: storage interfaces; SQLite append-only WORM ledger
      (chain verified on startup, fail-closed on corruption); durable velocity
      counters; cross-restart deterministic replay; per-decision evidence
      export verifiable with only the public key
- [ ] **WS2 Real sanctions data plane**: pluggable `ScreeningProvider`
      interface; offline fixture provider; OpenSanctions/yente provider;
      Moov Watchman provider; list provenance recorded in every verdict;
      **stale list ⇒ fail closed** with a distinct reason code

## Phase 2 — Conformance and evidence

- [ ] **WS1 AP2 v0.2 conformance**: conformance matrix (conformant / divergent
      / absent per spec field); Human-Not-Present mandate policy path (higher
      baseline risk, mandatory scope-ledger enforcement, stricter step-up);
      formal adapter interface + AP2/ACP/x402 adapter design docs;
      `CONFORMANCE.md` changelog tracking WG output
- [ ] **WS7 Benchmarks**: harness with per-stage latency percentiles on real
      backends; degradation semantics as a named invariant with fault-injection
      tests; CI perf smoke test; honest `BENCHMARKS.md`

## Phase 3 — Depth and defense

- [ ] **WS4 Graph detection**: counterparty graph (bounded, deterministic);
      fan-out/fan-in, cycle, pass-through detectors with evidence subgraphs;
      cross-agent collusion correlation; ISO 20022 field mapping;
      IBM AMLSim benchmark with published detection/false-positive rates and
      time-to-interdiction
- [ ] **WS5 Adversarial robustness**: attack corpus from the *Whispers of
      Wealth* AP2 red-teaming paper; protocol-state fuzzing (out-of-order,
      replayed receipts, expired credentials, depth abuse); ESCROW
      conditional-settlement verdict (verify-then-pay; timeout fails toward
      refund); temporal intervention metrics

## Phase 4 — Moat and launch

- [ ] **WS6 Know-Your-Agent**: agent registry (key → legal entity, capability
      scope, risk tier); chain resolution to a registered root; behavioral
      standing as deterministic risk features; revocation with propagation
      guarantee; `KYA.md`
- [ ] **WS8 Security hardening**: STRIDE threat model; keystore abstraction +
      ledger key rotation recorded in-chain; signed verdict envelopes verified
      at the settlement gate (done) hardened for transit; SBOM + dependency
      scanning + signed releases
- [ ] **WS9 Regulatory matrix**: regulation × feature matrix (BSA/FinCEN,
      OFAC, PSD3/SCA, EU AI Act, MiCA, AI Liability Directive) with honest
      "does not satisfy" cells; versioned reason-code registry as a public
      contract; SAR output mapped to the FinCEN schema; jurisdiction packs
      (US, EU, IN) as cited data files
- [ ] **WS10 Launch**: positioning README with fair comparison table
      (Watchman / Tazama / Marble / Fireblocks x402 extension); recorded demo;
      benchmark report; semver + signed releases; launch post

## Non-goals

Case management (emit events instead), settlement rails, ML-as-verdict-
authority, and anything that breaks zero-infrastructure demo mode.
