"""WS7 — degradation semantics and the perf smoke test.

Named invariant under test: **NO-SILENT-SKIP** — under dependency failure a
decision queues or fails closed with a distinct reason code; no pipeline
stage is ever silently skipped, and nothing ALLOWs without attested
screening provenance.
"""

from __future__ import annotations

import time

from aegis.models import Verdict
from aegis.runtime import build_system
from aegis.screening import OfflineFixtureProvider, ScreeningUnavailable
from aegis.testkit import build_bundle

NOW = 1_800_000_000.0


class DiesMidStream(OfflineFixtureProvider):
    """Healthy for the first ``healthy_calls`` provenance lookups, then the
    data plane goes down — the kill-the-provider-mid-load-test scenario."""

    def __init__(self, healthy_calls: int):
        super().__init__()
        self._budget = healthy_calls

    def provenance(self):
        if self._budget <= 0:
            raise ScreeningUnavailable("screening provider killed mid-stream")
        self._budget -= 1
        return super().provenance()

    def screen(self, name):
        if self._budget < 0:
            raise ScreeningUnavailable("screening provider killed mid-stream")
        return super().screen(name)


def test_provider_death_mid_stream_fails_closed_never_open():
    provider = DiesMidStream(healthy_calls=5)
    system = build_system(screening=provider)

    verdicts = []
    for i in range(10):
        b = build_bundle(system.keyring, mandate_id=f"deg-{i}",
                         total_usd=100.0, human_present=True)
        env = system.orchestrator.evaluate(b, now=NOW + i * 100_000)
        verdicts.append(env)

    healthy = verdicts[:5]
    degraded = verdicts[5:]
    assert all(e.verdict == Verdict.ALLOW for e in healthy)
    # After the provider dies: every decision fails CLOSED with the distinct
    # reason code — never an ALLOW that silently skipped screening.
    assert all(e.verdict == Verdict.BLOCK for e in degraded)
    assert all("AGENT.SANC.PROVIDER_UNAVAILABLE" in e.reason_codes
               for e in degraded)
    # And every ALLOW that did happen carries attested screening provenance.
    assert all(e.screening is not None for e in healthy)


def test_no_silent_skip_invariant(system, make_bundle, monkeypatch):
    """If a pipeline stage is bypassed entirely (bad patch, partial deploy),
    the finalizer refuses to emit a non-BLOCK verdict without screening
    provenance."""
    import aegis.pipeline.f2_sanctions as f2

    monkeypatch.setattr(f2, "run", lambda ctx, provider: None)  # silent no-op
    env = system.orchestrator.evaluate(make_bundle(total_usd=100.0,
                                                   human_present=True))
    assert env.verdict == Verdict.BLOCK
    assert "AGENT.SYS.STAGE_SKIPPED" in env.reason_codes


def test_perf_smoke_regression_guard():
    """CI smoke benchmark (WS7 task 4): a *generous* bound that catches
    order-of-magnitude regressions, not hardware noise. Local p95 is ~3 ms
    (see BENCHMARKS.md); the bound is 50x that."""
    system = build_system()
    bundles = [
        build_bundle(system.keyring, mandate_id=f"perf-{i}",
                     total_usd=50.0 + i, human_present=True)
        for i in range(60)
    ]
    # Warmup, then measure.
    for b in bundles[:10]:
        system.orchestrator.evaluate(b, now=NOW)
    samples = []
    for i, b in enumerate(bundles[10:]):
        t0 = time.perf_counter()
        system.orchestrator.evaluate(b, now=NOW + (i + 1) * 100_000)
        samples.append((time.perf_counter() - t0) * 1000.0)
    samples.sort()
    p95 = samples[int(0.95 * (len(samples) - 1))]
    assert p95 < 150.0, f"perf smoke: p95={p95:.1f}ms exceeded the 150ms guard"
