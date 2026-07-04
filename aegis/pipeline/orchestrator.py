"""The fail-closed decision orchestrator.

Runs the ordered pipeline (Features 1-7). Hard blocks short-circuit; graduated
signals accumulate into the risk score. ANY unhandled failure — a stage error,
a timeout, an unavailable dependency — resolves to BLOCK, never ALLOW. There is
no code path from here to settlement without a signed ALLOW/quorum envelope.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from ..crypto import KeyRing
from ..gateway.verify import verify_bundle
from ..ledger import DecisionLedger, EvaluationArchive
from ..ml import DriftEmbedder, RiskModel, default_embedder, default_risk_model
from ..models import DecisionEnvelope, MandateBundle, Severity, Signal, Verdict
from ..screening import (
    OfflineFixtureProvider,
    RecordedScreeningProvider,
    ScreeningProvider,
)
from ..state import (
    StepUpStore,
    VelocityStore,
    default_stepup_store,
    default_velocity_store,
)
from . import f1_jurisdiction as f1
from . import f2_sanctions as f2
from . import f3_structuring as f3
from . import f4_adversarial as f4
from . import f5_risk_stepup as f5
from . import f6_liability as f6
from . import f7_reasoncodes as f7
from .context import ControlEvidence, DecisionContext


@dataclass
class ReplayResult:
    decision_id: str
    original_verdict: Verdict
    reproduced_verdict: Verdict
    matches_original: bool
    world_snapshot_matches: bool
    reason_codes_match: bool


class Orchestrator:
    def __init__(
        self,
        ledger: DecisionLedger,
        keyring: KeyRing,
        velocity_store: Optional[VelocityStore] = None,
        stepup_store: Optional[StepUpStore] = None,
        embedder: Optional[DriftEmbedder] = None,
        risk_model: Optional[RiskModel] = None,
        screening: Optional[ScreeningProvider] = None,
    ):
        self.ledger = ledger
        self.keyring = keyring
        self.velocity = velocity_store or default_velocity_store()
        self.stepup = stepup_store or default_stepup_store()
        self.embedder = embedder or default_embedder()
        self.risk_model = risk_model or default_risk_model()
        self.screening = screening or OfflineFixtureProvider()

    # -- public API ------------------------------------------------------
    def evaluate(
        self,
        bundle: MandateBundle,
        controls: Optional[ControlEvidence] = None,
        now: Optional[float] = None,
    ) -> DecisionEnvelope:
        ctx: Optional[DecisionContext] = None
        try:
            ctx = DecisionContext(
                bundle=bundle,
                controls=controls or ControlEvidence(),
                now=now if now is not None else time.time(),
            )

            # Gate 0: signature verification.
            ok, code, detail = verify_bundle(bundle, self.keyring.public_key)
            if not ok:
                ctx.add_signal(Signal(
                    code=code, detail=detail, severity=Severity.HIGH,
                    hard_block=True, stage="verify_signatures",
                ))
                return self._finalize(ctx, Verdict.BLOCK)

            verdict = self._run_pipeline(ctx, self.velocity, self.screening,
                                         record=True)
            return self._finalize(ctx, verdict)

        except Exception as exc:  # fail-closed: any error → BLOCK
            return self._finalize_failclosed(bundle, ctx, exc)

    def replay(self, decision_id: str) -> ReplayResult:
        """Re-run the pipeline against the archived inputs and confirm the
        verdict reproduces byte-for-byte — the audit determinism guarantee."""
        original = self.ledger.get(decision_id)
        archive = self.ledger.archive_for(decision_id)
        if original is None or archive is None:
            raise KeyError(f"no replayable record for decision {decision_id}")

        bundle = MandateBundle.model_validate(archive.bundle)
        controls = ControlEvidence(**archive.controls)
        ctx = DecisionContext(bundle=bundle, controls=controls, now=archive.now)

        # Isolated velocity store seeded to reproduce the exact window, and a
        # recorded screening provider so replay never makes a live data-plane
        # call — the decision is re-derived from archived inputs alone.
        iso_store = VelocityStore()
        iso_store.seed(archive.velocity_snapshot)
        recorded = RecordedScreeningProvider(archive.screening_snapshot)

        ok, code, detail = verify_bundle(bundle, self.keyring.public_key)
        if not ok:
            ctx.add_signal(Signal(
                code=code, detail=detail, severity=Severity.HIGH,
                hard_block=True, stage="verify_signatures",
            ))
            verdict = Verdict.BLOCK
        else:
            verdict = self._run_pipeline(ctx, iso_store, recorded, record=False)

        f6.run(ctx)
        reproduced = f7.build_envelope(ctx, verdict)

        return ReplayResult(
            decision_id=decision_id,
            original_verdict=original.verdict,
            reproduced_verdict=verdict,
            matches_original=(verdict == original.verdict),
            world_snapshot_matches=(
                ctx.world_snapshot_hash == original.world_snapshot_hash
            ),
            reason_codes_match=(reproduced.reason_codes == original.reason_codes),
        )

    # -- internals -------------------------------------------------------
    def _run_pipeline(
        self, ctx: DecisionContext, store: VelocityStore,
        screening: ScreeningProvider, record: bool
    ) -> Verdict:
        # Hard-block stages (short-circuit on any hard block).
        f1.run(ctx)
        if ctx.has_hard_block:
            return Verdict.BLOCK
        f2.run(ctx, screening)
        if ctx.has_hard_block:
            return Verdict.BLOCK
        f3.run(ctx, store)
        if ctx.has_hard_block:
            return Verdict.BLOCK
        f4.run(ctx, self.embedder)
        if ctx.has_hard_block:
            return Verdict.BLOCK
        # Graduated resolution.
        return f5.run(ctx, self.risk_model)

    def _finalize(self, ctx: DecisionContext, verdict: Verdict) -> DecisionEnvelope:
        f6.run(ctx)
        env = f7.build_envelope(ctx, verdict)
        archive = EvaluationArchive(
            bundle=ctx.bundle.model_dump(mode="json"),
            now=ctx.now,
            controls=dict(ctx.controls.__dict__),
            velocity_snapshot=ctx.velocity_snapshot,
            screening_snapshot={
                "provenance": ctx.screening_provenance,
                "queries": ctx.screening_log,
                "error": ctx.screening_error,
            },
        )
        self.ledger.append(env, archive)
        if verdict == Verdict.STEP_UP and ctx.stepup is not None:
            self.stepup.put(ctx.stepup)
        return env

    def _finalize_failclosed(
        self, bundle: MandateBundle, ctx: Optional[DecisionContext], exc: Exception
    ) -> DecisionEnvelope:
        if ctx is None:
            ctx = DecisionContext(bundle=bundle)
        # Ensure no partial ALLOW leaks: force a hard block signal.
        ctx.add_signal(Signal(
            code="AGENT.SYS.FAILCLOSED",
            detail=f"{type(exc).__name__}: {exc}",
            severity=Severity.HIGH,
            hard_block=True,
            stage="orchestrator",
        ))
        return self._finalize(ctx, Verdict.BLOCK)
