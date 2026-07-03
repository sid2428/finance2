"""Per-decision evidence export (WS3 task 4).

An evidence bundle is a self-contained, signature-verifiable file a regulator
or auditor can validate **with only the ledger's public key** — no AEGIS
deployment, no database access:

  1. ``envelope.signature`` verifies (Ed25519) over the envelope's canonical
     signing payload against ``signing_pub_hex``.
  2. ``envelope.this_hash`` recomputes from the fully-signed envelope.
  3. If the replay archive is included, the archived inputs re-hash to the
     envelope's pinned ``world_snapshot_hash`` — proving the recorded inputs
     are the ones the decision was made on.

Verification procedure (external, documented): run
``python -m aegis.tools.verify_evidence <bundle.json>`` or reimplement the
three checks above in ~30 lines of any language with SHA-256 + Ed25519.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..crypto import canonical_bytes, hash_object, sha256_hex, verify
from ..models import DecisionEnvelope
from .store import DecisionLedger

EVIDENCE_FORMAT = "aegis-evidence/1"


def export_evidence(ledger: DecisionLedger, decision_id: str) -> dict:
    env = ledger.get(decision_id)
    if env is None:
        raise KeyError(f"unknown decision {decision_id}")
    archive = ledger.archive_for(decision_id)
    return {
        "format": EVIDENCE_FORMAT,
        "signing_pub_hex": ledger.signing_pub.hex(),
        "envelope": env.model_dump(mode="json"),
        "archive": archive.__dict__ if archive is not None else None,
    }


def write_evidence(ledger: DecisionLedger, decision_id: str, path: Path | str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(export_evidence(ledger, decision_id),
                            indent=2, default=str), encoding="utf-8")
    return p


def verify_evidence(bundle: dict) -> tuple[bool, dict]:
    """Validate an evidence bundle using only its embedded public key.

    Returns (ok, checks) where ``checks`` reports each verification step.
    Fail-closed: any malformed field is a failure, never a skip.
    """
    checks: dict[str, Optional[bool]] = {
        "format": None, "signature": None, "this_hash": None, "world_snapshot": None,
    }
    try:
        checks["format"] = bundle.get("format") == EVIDENCE_FORMAT
        pub = bytes.fromhex(bundle["signing_pub_hex"])
        env = DecisionEnvelope.model_validate(bundle["envelope"])

        checks["signature"] = verify(pub, env.signing_payload(), env.signature)

        recomputed = sha256_hex(
            canonical_bytes(env.model_dump(mode="json", exclude={"this_hash"}))
        )
        checks["this_hash"] = recomputed == env.this_hash

        archive = bundle.get("archive")
        if archive is None:
            checks["world_snapshot"] = True   # no archive claimed; nothing to check
        else:
            snapshot = {
                "bundle": archive["bundle"],
                "ruleset_version": env.ruleset_version,
                "now": archive["now"],
                "controls": archive["controls"],
            }
            checks["world_snapshot"] = hash_object(snapshot) == env.world_snapshot_hash
    except Exception:
        return (False, {k: bool(v) for k, v in checks.items()})

    return (all(bool(v) for v in checks.values()), checks)
