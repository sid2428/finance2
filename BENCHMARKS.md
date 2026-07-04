# AEGIS Benchmarks

**Honest numbers, modest hardware, reproducible method.** The design budget
is p99 < 120 ms on the ALLOW path; the reference implementation clears it by
an order of magnitude on a laptop. That headroom is the claim — not a
marketing RPS figure.

## Method

```
python -m aegis.tools.bench --n 500            # in-memory demo backends
python -m aegis.tools.bench --n 500 --durable  # SQLite backends (WS3)
```

* 500 decisions after 25 warmup calls, single-threaded, one process.
* Workload mix: 80% clean human-present purchases (ALLOW path), 10% risky
  (STEP_UP path), 10% sanctioned-counterparty (BLOCK at screening).
* Bundles are built and Ed25519-signed **before** the timed loop —
  client-side signing is not gateway latency.
* Decision clocks are spaced so velocity windows stay empty: these numbers
  measure the lookup cost, not a tripped-structuring narrative.
* Per-stage timings come from `Orchestrator.last_stage_timings`
  (observational only; never part of the envelope or replay archive).

## Results — 2026-07-04

Hardware: consumer laptop (Windows 11, CPython 3.11), offline fixture
screening provider. Machine-readable reports: `--json out.json`.

### End-to-end latency (ms per decision)

| Backend | p50 | p95 | p99 | max | mean |
|---|---|---|---|---|---|
| in-memory demo | 1.10 | 2.83 | 4.28 | 14.7 | 1.43 |
| SQLite durable (WAL, `synchronous=FULL`) | 4.92 | 8.77 | 11.5 | 29.0 | 5.29 |

### Per-stage mean (p99) — durable backend

| Stage | mean ms | p99 ms |
|---|---|---|
| verify_signatures (3× Ed25519) | 0.54 | 1.29 |
| f1_jurisdiction | 0.01 | 0.07 |
| f2_sanctions (offline provider) | 0.25 | 0.56 |
| f3_structuring (SQLite velocity window) | **3.03** | 8.19 |
| f4_adversarial (drift embedder) | 0.20 | 0.52 |
| f5_risk_stepup | 0.04 | 0.27 |
| finalize (sign + WORM append, fsync) | **1.36** | 3.49 |

The two durable-mode hot spots are exactly where the design doc predicted:
the velocity-window read (DELETE-prune + SELECT + commit per lookup) and the
fsync'd ledger append. Both are the price of `synchronous=FULL` on an
evidence store — deliberately paid. If they ever matter at your volume, the
storage seam is the swap point (server-grade store, group commit).

## Degradation semantics (named invariant: NO-SILENT-SKIP)

Under dependency failure, decisions **fail closed with a distinct reason
code** — configurable queuing may be layered in front, but the pipeline
default is refusal:

* Screening provider unreachable → BLOCK, `AGENT.SANC.PROVIDER_UNAVAILABLE`.
* Screening data stale → BLOCK, `AGENT.SANC.STALE_LIST`.
* Any non-BLOCK verdict without attested screening provenance → BLOCK,
  `AGENT.SYS.STAGE_SKIPPED` (a bypassed stage can never emit an ALLOW).

Fault-injection coverage: `tests/test_degradation.py` kills the provider
mid-stream and proves every subsequent decision fails closed; a monkeypatched
no-op stage is caught by the finalizer. The CI perf smoke test
(`test_perf_smoke_regression_guard`) fails the build if p95 exceeds 150 ms —
a deliberately generous bound that catches order-of-magnitude regressions,
not hardware noise.

## Caveats

* Single-threaded CPython on a laptop; no network transport in the loop
  (FastAPI/HTTP overhead not included).
* The offline screening provider is an in-process matcher over a small
  fixture list; a yente/Watchman deployment adds a network round trip to
  f2 — budget accordingly (their own p99s are typically single-digit ms
  in-datacenter).
* Synthetic workload; real mandate bundles are larger and verify more
  slowly roughly linearly with mandate count.
