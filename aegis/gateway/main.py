"""FastAPI gateway implementing the AEGIS API contract.

Endpoints:
  POST /v1/mandates/evaluate            -> DecisionEnvelope
  POST /v1/stepup/{challenge_id}/approve-> quorum contribution
  GET  /v1/ledger/{decision_id}         -> full audit record
  POST /v1/ledger/{decision_id}/replay  -> determinism proof
  GET  /v1/ledger                       -> chain + integrity status
  GET  /v1/sar/drafts                   -> queued SAR drafts
  GET  /healthz /readyz /metrics        -> ops

In production every endpoint is mTLS-authenticated with DID-bound identities;
here the app is transport-agnostic so it can be exercised locally / in tests.
"""

from __future__ import annotations

from collections import Counter

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ..models import MandateBundle, Verdict
from ..pipeline.f5_risk_stepup import verify_quorum
from ..runtime import AegisSystem, build_system


class StepUpApproval(BaseModel):
    signer_did: str
    signature: str  # hex Ed25519 signature over the challenge cart_hash


def create_app(system: AegisSystem | None = None) -> FastAPI:
    system = system or build_system()
    app = FastAPI(title="AEGIS", version="0.1.0")
    app.state.aegis = system

    @app.post("/v1/mandates/evaluate")
    def evaluate(bundle: MandateBundle):
        env = system.orchestrator.evaluate(bundle)
        return env.model_dump(mode="json")

    @app.post("/v1/stepup/{challenge_id}/approve")
    def approve(challenge_id: str, body: StepUpApproval):
        challenge = system.stepup.get(challenge_id)
        if challenge is None:
            raise HTTPException(404, "unknown or expired challenge")
        challenge.contributions[body.signer_did] = body.signature
        satisfied, remaining = verify_quorum(
            challenge, challenge.contributions, system.keyring.public_key
        )
        return {"satisfied": satisfied, "remaining": remaining}

    @app.get("/v1/ledger/{decision_id}")
    def get_ledger(decision_id: str):
        env = system.ledger.get(decision_id)
        if env is None:
            raise HTTPException(404, "unknown decision")
        return env.model_dump(mode="json")

    @app.post("/v1/ledger/{decision_id}/replay")
    def replay(decision_id: str):
        try:
            result = system.orchestrator.replay(decision_id)
        except KeyError:
            raise HTTPException(404, "no replayable record")
        return {
            "reproduced_verdict": result.reproduced_verdict.value,
            "matches_original": result.matches_original,
            "world_snapshot_matches": result.world_snapshot_matches,
            "reason_codes_match": result.reason_codes_match,
        }

    @app.get("/v1/ledger")
    def ledger_chain():
        ok, bad = system.ledger.verify_chain()
        return {
            "entries": len(system.ledger.all()),
            "chain_valid": ok,
            "first_bad_seq": bad,
            "head_hash": system.ledger.head_hash(),
        }

    @app.get("/v1/sar/drafts")
    def sar_drafts():
        drafts = [
            e.sar_draft for e in system.ledger.all() if e.sar_draft is not None
        ]
        return {"count": len(drafts), "drafts": drafts}

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz():
        ok, _ = system.ledger.verify_chain()
        return {"ready": ok}

    @app.get("/metrics")
    def metrics():
        verdicts = Counter(e.verdict.value for e in system.ledger.all())
        reasons = Counter(
            code for e in system.ledger.all() for code in e.reason_codes
        )
        return {
            "aegis_decisions_total": dict(verdicts),
            "aegis_block_reasons": dict(reasons),
            "ledger_depth": len(system.ledger.all()),
        }

    return app


app = create_app()
