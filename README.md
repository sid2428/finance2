# AEGIS — reference implementation

[![CI](https://github.com/sid2428/finance2/actions/workflows/ci.yml/badge.svg)](https://github.com/sid2428/finance2/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

> *The protocols decide whether a payment is authorized. AEGIS decides whether
> it is lawful. Fail-closed, deterministic, and rail-agnostic — the compliance
> control plane the agentic stack forgot to build.*

**Agentic Enforcement, Governance & Interdiction of Settlement.** A fail-closed,
deterministic compliance & regulation control plane that sits between an AP2
payment authorization and the settlement rail. See [`AEGIS.md`](AEGIS.md) for the
full design; this README covers the working code.

This build implements the complete decision pipeline (all 7 flagship features),
the fail-closed orchestrator, the Ed25519-signed hash-chained audit ledger, the
FastAPI gateway, a provider-neutral settlement gate, and an end-to-end demo — all
runnable locally with **no external infrastructure**.

## Quickstart

```bash
pip install -r requirements.txt

python -m demo.demo            # compliance track: 5-scenario narrative
python -m demo.advanced_demo   # AP2 track: full SD-JWT delegation lifecycle
python -m pytest               # 85 tests (both tracks)
uvicorn aegis.gateway.main:app --port 8080   # run the API
```

This repo contains **two complementary tracks**:

- **Compliance control plane** (`aegis/pipeline`, `AEGIS.md`) — the fail-closed
  regulatory pipeline below.
- **AEGIS·CORE advanced track** (`aegis/ap2`, `AEGIS-ADVANCED.md`) — seven
  features built on AP2's real cryptographic authorization machinery (SD-JWT
  VCs, KB-JWT proof-of-possession, `sd_hash`/`checkout_hash` binding, selective
  disclosure, Mandate Receipts, custom constraints). See the section near the end.

## What the demo shows

Running `python -m demo.demo` walks the portfolio narrative in one sitting:

1. **Clean transaction → `ALLOW`** and settles through the gate.
2. **Structuring cluster → `BLOCK` + auto-drafted SAR** — three sub-threshold
   transfers to one beneficiary summing over the CTR threshold within 24h.
3. **Transliterated sanctioned name → `BLOCK`** — `Ivan Petroff Volkoff` fuzzy
   -matches OFAC SDN `Ivan Petrov Volkov` (Jaro-Winkler + phonetic); plus the
   OFAC 50% Rule via the ownership graph.
4. **Prompt-injected / price-breached cart → `BLOCK`**, and settlement is
   physically refused on the block envelope.
5. **Mid-risk transaction → `STEP_UP` → m-of-n quorum → settle** — the maker is
   structurally barred from approving (four-eyes); guardian signatures are bound
   to the exact cart hash (SCA dynamic linking).

Then it **replays** a decision to prove byte-for-byte determinism and **tampers**
with a historical ledger entry to show the hash chain breaks.

## The 7 features → where they live

| # | Feature | Module |
|---|---|---|
| 1 | Jurisdiction firewall (FATF Travel Rule, GDPR residency, rail eligibility) | `aegis/pipeline/f1_jurisdiction.py` + `policy/*.rego` |
| 2 | Sanctions/PEP interdiction (fuzzy match, OFAC 50% rule) | `aegis/pipeline/f2_sanctions.py`, `aegis/matching/` |
| 3 | Structuring & velocity analyzer (SAR drafting) | `aegis/pipeline/f3_structuring.py`, `aegis/state/velocity.py` |
| 4 | Adversarial / intent-drift detector (injection firewall) | `aegis/pipeline/f4_adversarial.py`, `aegis/ml/embedder.py` |
| 5 | Risk scorer + step-up quorum (four-eyes) | `aegis/pipeline/f5_risk_stepup.py`, `aegis/ml/risk_model.py` |
| 6 | Liability attribution (EMV shift + Reg E floor) | `aegis/pipeline/f6_liability.py` |
| 7 | Explainable reason-codes + hash-chained ledger | `aegis/pipeline/f7_reasoncodes.py`, `aegis/ledger/store.py` |

The **fail-closed orchestrator** is `aegis/pipeline/orchestrator.py`; the
**settlement gate** (the only path to money movement) is
`aegis/adapters/settlement.py`.

## Design invariants (enforced in code)

- **Single authority path.** `adapters.settle()` refuses any envelope that is not
  a signature-valid `ALLOW` (or a `STEP_UP` whose quorum is satisfied) — see
  `test_orchestrator.py`.
- **Fail-closed.** Any stage exception / dependency failure resolves to `BLOCK`
  (`Orchestrator._finalize_failclosed`).
- **Deterministic core.** A decision is a pure function of
  `(mandate, world_snapshot, ruleset_version)`; `/replay` reproduces it exactly.
- **ML on the periphery.** Model scores may only *raise* risk; a hard block
  short-circuits before scoring ever runs (`test_ml_cannot_lift_a_hard_block`).

## API contract

| Method / path | Purpose |
|---|---|
| `POST /v1/mandates/evaluate` | Evaluate an AP2 mandate bundle → `DecisionEnvelope` |
| `POST /v1/stepup/{id}/approve` | Contribute one quorum signature |
| `GET  /v1/ledger/{decision_id}` | Full audit record |
| `POST /v1/ledger/{decision_id}/replay` | Determinism proof |
| `GET  /v1/ledger` | Chain depth + integrity status |
| `GET  /v1/sar/drafts` | Queued Suspicious Activity Reports |
| `GET  /healthz` `/readyz` `/metrics` | Ops |

## Production stand-ins

To stay dependency-free and locally runnable, the following are in-process and
sit behind clean seams so they swap for the real thing without touching call
sites:

| Spec component | This build | Swap point |
|---|---|---|
| OPA/Rego policy engine | Python firewall mirroring `policy/*.rego` | `f1_jurisdiction.py` |
| Redis velocity counters | in-memory sorted store | `aegis/state/velocity.py` |
| PostgreSQL WORM ledger | in-memory list + JSONL sink | `aegis/ledger/store.py` |
| ONNX risk/embedder models | deterministic scorers | `aegis/ml/` |
| `jellyfish` fuzzy matching | pure-Python Jaro-Winkler + phonetic | `aegis/matching/fuzzy.py` |
| HSM/KMS signing keys | `KeyRing` | `aegis/crypto.py` |

> The intent-drift threshold is tuned for the bag-of-words stand-in embedder
> (which under-scores related short texts); a production sentence-embedder uses a
> lower threshold. Swap the embedder and threshold together — see `config.py`.

## Layout

```
aegis/        core package (models, crypto, pipeline, ledger, adapters, gateway, ml, state, data)
aegis/ap2/    advanced track: sdjwt, constraints, mandates, verifier, sandbox,
              scope_ledger, wysiwys, disputes, disclosure
policy/       Rego bundle (Feature 1 authority) + manifest
demo/         demo.py (compliance) + advanced_demo.py (AP2 lifecycle)
tests/        assurance suites for both tracks
deploy/       Dockerfile
```

## AEGIS·CORE — the advanced AP2 track

Where the compliance track sits *above* the protocol, this track builds *on*
AP2's actual cryptographic primitives. **The crypto is real** — EdDSA SD-JWTs
signed and verified with `cryptography`, disclosure digests recomputed, KB-JWT
proof-of-possession checked against the endorsed `cnf` key. No `verified=True`
shortcut. Run `python -m demo.advanced_demo` for the whole lifecycle.

| # | Feature | Module |
|---|---|---|
| 1 | Financial Constraint Compiler — custom AP2 constraint DSL (`spend_curve`, `mcc_allowlist`, `fx_slippage_bound`, `velocity_envelope`); unknown types fail closed | `aegis/ap2/constraints.py` |
| 2 | Minimal-Disclosure Solver + decoy privacy budget | `aegis/ap2/disclosure.py` |
| 3 | Open-Mandate Scope Ledger — receipt-driven double-spend prevention | `aegis/ap2/scope_ledger.py` |
| 4 | **Delegation-Chain Verifier** — the single gate (sig · locked-claims · KB-JWT · `sd_hash` · `checkout_hash` · constraints) | `aegis/ap2/verifier.py` |
| 5 | WYSIWYS Intent Integrity Oracle — settled cart == approved cart | `aegis/ap2/wysiwys.py` |
| 6 | `checkout_hash` Dispute Reconciliation & refund engine | `aegis/ap2/disputes.py` |
| 7 | Mandate Sandbox / adversarial fuzzer (8 attacks, `escaped == []`) | `aegis/ap2/sandbox.py` |

SD-JWT/KB-JWT/JWK/disclosure primitives live in `aegis/ap2/sdjwt.py`; open/closed
mandate construction in `aegis/ap2/mandates.py`.

**Design notes**
- **F4 is the spine** — nothing verifies without the full chain check; F1's
  registry is what it evaluates in its final step; F7 fuzzes it every CI run.
- The anti-rebind `sd_hash` binds to the open mandate's **immutable issuer JWT**
  (via `SDJWT.issuer_hash()`), so it is stable under selective disclosure — the
  closed mandate stays bound however much (or little) the agent discloses.
- F4 binds the closed mandate's amount/payee/line-items to the hash-referenced
  checkout, so `amount_inflate` / `payee_swap` are caught at verification, not
  only by WYSIWYS.
- Decoys are **issuance-time** (`issue_sd_jwt(sd_array_decoys=…)`); they cannot
  be added at presentation without breaking the issuer signature.

---

*AEGIS is a reference design. Sanctions screening, SAR filing, and liability
determinations in a live financial system must be reviewed by qualified
compliance and legal counsel before production use.*
