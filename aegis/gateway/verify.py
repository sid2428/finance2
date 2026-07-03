"""AP2 mandate signature verification (W3C VC / Ed25519).

Each mandate carries a detachable ``proof`` whose signature covers the
mandate's canonical content with the proof removed. The proof's
``verification_method`` is a DID URL whose base DID must equal the mandate's
declared signer, and which resolves (via the key resolver) to the Ed25519
public key. Any failure is fail-closed: the caller BLOCKs.
"""

from __future__ import annotations

from typing import Callable, Optional

from ..crypto import sign, verify
from ..models import (
    CartMandate,
    IntentMandate,
    MandateBundle,
    PaymentMandate,
    VerifiableCredentialProof,
    _SignedMandate,
)

PubKeyResolver = Callable[[str], Optional[bytes]]


def _base_did(verification_method: str) -> str:
    return verification_method.split("#", 1)[0]


def _verify_mandate(
    mandate: _SignedMandate,
    expected_signer: str,
    resolver: PubKeyResolver,
) -> tuple[bool, str]:
    proof = mandate.proof
    if proof is None:
        return (False, "proof absent")
    signer_did = _base_did(proof.verification_method)
    if signer_did != expected_signer:
        return (False, f"proof signer {signer_did} != declared {expected_signer}")
    pub = resolver(signer_did)
    if pub is None:
        return (False, f"no public key for {signer_did}")
    if not verify(pub, mandate.signing_payload(), proof.signature):
        return (False, "signature verification failed")
    return (True, "ok")


def verify_bundle(
    bundle: MandateBundle,
    resolver: PubKeyResolver,
) -> tuple[bool, str, str]:
    """Verify all three mandates. Returns (ok, reason_code, detail)."""
    checks = [
        (bundle.intent, bundle.intent.signer_did),
        (bundle.cart, bundle.cart.merchant_did),
        (bundle.payment, bundle.payment.initiator_agent),
    ]
    for mandate, signer in checks:
        ok, detail = _verify_mandate(mandate, signer, resolver)
        if not ok:
            kind = type(mandate).__name__
            return (False, "AGENT.SIG.INVALID", f"{kind}: {detail}")
    return (True, "", "")


def sign_mandate(mandate: _SignedMandate, signer_did: str, private_key) -> None:
    """Test/demo helper: attach a valid VC proof to a mandate."""
    sig = sign(private_key, mandate.signing_payload())
    mandate.proof = VerifiableCredentialProof(
        verification_method=f"{signer_did}#key-1",
        signature=sig,
    )
