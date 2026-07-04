"""WS7 benchmark harness.

Streams synthetic mandate bundles through a fully-wired AEGIS system and
reports end-to-end and per-stage latency percentiles, per verdict mix.

Usage:
    python -m aegis.tools.bench                     # demo backends, 500 decisions
    python -m aegis.tools.bench --durable           # SQLite backends (WS3)
    python -m aegis.tools.bench --n 2000 --json out.json

Methodology notes (also see BENCHMARKS.md):
  * Bundles are built and signed BEFORE the timed loop — client-side signing
    is not gateway latency.
  * Decision clocks are spaced far apart so velocity windows stay empty; the
    harness measures the lookup cost, not a tripped-velocity narrative.
  * The mix is clean / step-up-risky / sanctioned-adversarial, weighted
    80/10/10 by default, matching the design doc's ALLOW-path budget focus.
  * Timings are observational (``Orchestrator.last_stage_timings``); they are
    never part of the envelope or the replay archive.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

from ..models import Party
from ..runtime import build_system
from ..testkit import build_bundle

MIX = (("clean", 0.8), ("risky", 0.1), ("adversarial", 0.1))
GUARDIANS = ["did:aegis:g1", "did:aegis:g2", "did:aegis:g3", "did:aegis:g4"]


def _make_bundles(system, n: int) -> list:
    """Pre-build the signed workload (excluded from timing)."""
    bundles = []
    counts = {kind: int(n * share) for kind, share in MIX}
    counts["clean"] += n - sum(counts.values())      # remainder to clean
    i = 0
    for kind, count in counts.items():
        for _ in range(count):
            i += 1
            if kind == "clean":
                b = build_bundle(system.keyring, mandate_id=f"bench-{i}",
                                 total_usd=40.0 + (i % 50), human_present=True)
            elif kind == "risky":
                b = build_bundle(system.keyring, mandate_id=f"bench-{i}",
                                 total_usd=6500.0, max_value_usd=9000.0,
                                 human_present=True, guardians=GUARDIANS)
            else:  # adversarial: sanctioned counterparty
                b = build_bundle(
                    system.keyring, mandate_id=f"bench-{i}",
                    total_usd=100.0, human_present=True,
                    merchant_legal_name="Bank Melli Iran",
                    beneficiary=Party(legal_name="Bank Melli Iran",
                                      account_ref="acct-x"),
                )
            bundles.append(b)
    return bundles


def _pct(sorted_ms: list[float], p: float) -> float:
    if not sorted_ms:
        return 0.0
    idx = min(len(sorted_ms) - 1, max(0, round(p / 100 * (len(sorted_ms) - 1))))
    return sorted_ms[idx]


def run_bench(n: int = 500, durable: bool = False, warmup: int = 25) -> dict:
    tmp = None
    if durable:
        tmp = tempfile.TemporaryDirectory(prefix="aegis-bench-")
        system = build_system(tmp.name)
    else:
        system = build_system()

    try:
        bundles = _make_bundles(system, n + warmup)

        # Spaced decision clocks: one decision per 100_000 s keeps every
        # sliding window empty, so we measure lookups, not tripped velocity.
        base_now = 1_800_000_000.0

        for i in range(warmup):
            system.orchestrator.evaluate(bundles[i], now=base_now + i * 100_000)

        e2e_ms: list[float] = []
        stage_ms: dict[str, list[float]] = {}
        verdicts: dict[str, int] = {}
        for i, bundle in enumerate(bundles[warmup:]):
            now = base_now + (warmup + i) * 100_000
            t0 = time.perf_counter()
            env = system.orchestrator.evaluate(bundle, now=now)
            e2e_ms.append((time.perf_counter() - t0) * 1000.0)
            verdicts[env.verdict.value] = verdicts.get(env.verdict.value, 0) + 1
            for stage, secs in system.orchestrator.last_stage_timings.items():
                stage_ms.setdefault(stage, []).append(secs * 1000.0)

        e2e_sorted = sorted(e2e_ms)
        report = {
            "config": {
                "n": n, "warmup": warmup,
                "backend": "sqlite-durable" if durable else "in-memory-demo",
                "mix": dict(MIX),
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "verdicts": verdicts,
            "end_to_end_ms": {
                "p50": round(_pct(e2e_sorted, 50), 3),
                "p95": round(_pct(e2e_sorted, 95), 3),
                "p99": round(_pct(e2e_sorted, 99), 3),
                "max": round(e2e_sorted[-1], 3),
                "mean": round(statistics.fmean(e2e_ms), 3),
            },
            "stages_ms": {
                stage: {
                    "mean": round(statistics.fmean(vals), 3),
                    "p99": round(_pct(sorted(vals), 99), 3),
                    "samples": len(vals),
                }
                for stage, vals in sorted(stage_ms.items())
            },
        }
        return report
    finally:
        system.close()
        if tmp is not None:
            tmp.cleanup()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=500)
    ap.add_argument("--durable", action="store_true",
                    help="run against the SQLite backends instead of demo memory")
    ap.add_argument("--json", type=Path, default=None,
                    help="write the machine-readable report here")
    args = ap.parse_args(argv)

    report = run_bench(n=args.n, durable=args.durable)

    e = report["end_to_end_ms"]
    print(f"AEGIS bench — {report['config']['backend']}, "
          f"n={report['config']['n']} (mix {report['config']['mix']})")
    print(f"  end-to-end ms: p50={e['p50']}  p95={e['p95']}  "
          f"p99={e['p99']}  max={e['max']}  mean={e['mean']}")
    print(f"  verdicts: {report['verdicts']}")
    print("  per-stage mean ms (p99):")
    for stage, s in report["stages_ms"].items():
        print(f"    {stage:22s} {s['mean']:8.3f}  ({s['p99']:.3f})")

    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"  report written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
