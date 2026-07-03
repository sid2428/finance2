"""Feature 4 — Delegation-Chain Cryptographic Verifier.

The single gate every other advanced feature depends on. Implements the AP2
Verification & Processing Rules exactly, each step fail-closed:

  1. Parse & verify each SD-JWT (issuer/holder signature + disclosure digests).
  2. Locked open-mandate claims must appear UNCHANGED in the closed mandate.
  3. Key Binding: the closed mandate + KB-JWT must be signed by the key
     endorsed in the open mandate's ``cnf`` (proof-of-possession).
  4. ``sd_hash`` must bind the closed mandate to the exact open mandate presented.
  5. ``checkout_hash`` must match the hash of the merchant's checkout JWT.
  6. Evaluate EVERY constraint via the Feature 1 registry (unknown => fail).

No boolean ``verified=True`` shortcut anywhere — the crypto is real.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from . import sdjwt as S
from .constraints import ConstraintRegistry

# Claims that are authorization-critical and must carry from open to closed
# byte-for-byte. ``constraints`` is the security-critical one.
LOCKED_CLAIMS = ("constraints",)


@dataclass
class VerifyContext:
    now: float
    nonce: str
    registry: ConstraintRegistry
    issuer_resolver: Callable[[str], Optional[bytes]]   # iss DID -> Ed25519 pub raw
    executed_fx_rate: Optional[float] = None
    velocity_observed: Optional[dict] = None

    def constraint_ctx(self, disclosed_merchants: list) -> dict:
        return {
            "now": self.now,
            "executed_fx_rate": self.executed_fx_rate,
            "velocity_observed": self.velocity_observed,
            "disclosed_merchants": disclosed_merchants,
        }


@dataclass
class VerifyResult:
    ok: bool
    code: str = ""
    detail: str = ""
    closed_payload: Optional[dict] = None
    constraint_results: list = field(default_factory=list)

    @staticmethod
    def fail(code: str, detail: str = "") -> "VerifyResult":
        return VerifyResult(ok=False, code=code, detail=detail)

    @staticmethod
    def passed(closed_payload: dict, constraint_results: list) -> "VerifyResult":
        return VerifyResult(ok=True, code="ok", closed_payload=closed_payload,
                            constraint_results=constraint_results)


def verify_delegation_chain(
    chain: list[str], expected_checkout_jwt: str, ctx: VerifyContext
) -> VerifyResult:
    if len(chain) < 2:
        return VerifyResult.fail("invalid_mandate", "chain must be open + closed")

    try:
        open_m = S.SDJWT.parse(chain[0])
        closed_m = S.SDJWT.parse(chain[-1])
        open_payload = open_m.payload
        closed_payload = closed_m.payload
    except Exception as e:  # malformed anything -> terminal
        return VerifyResult.fail("invalid_credential", f"parse error: {e}")

    # 1. Signatures + disclosure integrity.
    issuer_pub = ctx.issuer_resolver(open_payload.get("iss", ""))
    if issuer_pub is None or not S.verify_jws(open_m.issuer_jwt, issuer_pub):
        return VerifyResult.fail("invalid_credential", "open mandate signature invalid")

    cnf = open_payload.get("cnf", {}).get("jwk")
    if not cnf:
        return VerifyResult.fail("invalid_credential", "open mandate missing cnf key")
    try:
        cnf_pub = S.public_raw_from_jwk(cnf)
    except Exception:
        return VerifyResult.fail("invalid_credential", "malformed cnf jwk")

    # Closed mandate is holder-signed with the cnf key (proof of possession).
    if not S.verify_jws(closed_m.issuer_jwt, cnf_pub):
        return VerifyResult.fail("invalid_credential", "closed mandate signature invalid")

    for sd in (open_m, closed_m):
        _, disc_ok = S.disclose(sd)
        if not disc_ok:
            return VerifyResult.fail("invalid_credential", "disclosure digest mismatch")

    # 2. Locked claims unchanged open -> closed.
    for k in LOCKED_CLAIMS:
        if open_payload.get(k) != closed_payload.get(k):
            return VerifyResult.fail("invalid_mandate", f"claim '{k}' mutated open->closed")
    if closed_payload.get("open_iat") != open_payload.get("iat"):
        return VerifyResult.fail("invalid_mandate", "open_iat linkage mismatch")

    # 3. Key Binding proof-of-possession (KB-JWT: nonce + closed presentation hash).
    if not closed_m.kb_jwt:
        return VerifyResult.fail("invalid_credential", "closed mandate missing KB-JWT")
    if not S.verify_kb_jwt(closed_m.kb_jwt, cnf, expected_nonce=ctx.nonce,
                           expected_sd_hash=closed_m.sd_hash()):
        return VerifyResult.fail("invalid_credential", "proof-of-possession failed")

    # 4. sd_hash binds closed -> exact open mandate (anti-rebind). Bound to the
    # immutable issuer JWT so it is stable under selective disclosure.
    if closed_payload.get("sd_hash") != open_m.issuer_hash():
        return VerifyResult.fail("invalid_mandate", "sd_hash mismatch (rebind attack)")

    # 5. checkout_hash binds closed -> merchant checkout, AND the closed
    # mandate's content must be consistent with that (hash-bound) checkout.
    expected_ch = S.sha256_b64u(expected_checkout_jwt.encode("ascii"))
    if closed_payload.get("checkout_hash") != expected_ch:
        return VerifyResult.fail("invalid_mandate", "checkout_hash mismatch")
    try:
        checkout = S.parse_jws(expected_checkout_jwt)[1]
    except Exception:
        return VerifyResult.fail("invalid_mandate", "unparseable checkout jwt")
    if closed_payload.get("payment_amount") != checkout.get("amount"):
        return VerifyResult.fail("invalid_mandate", "amount differs from bound checkout")
    if closed_payload.get("payee") != checkout.get("merchant"):
        return VerifyResult.fail("invalid_mandate", "payee differs from bound checkout")
    if closed_payload.get("line_items") != checkout.get("line_items"):
        return VerifyResult.fail("invalid_mandate", "line_items differ from bound checkout")

    # 6. Evaluate every constraint (unknown => fail). The constraint context
    # carries only the merchants the agent actually disclosed (Feature 2).
    disclosed_open, _ = S.disclose(open_m)
    results = ctx.registry.evaluate(
        closed_payload, ctx.constraint_ctx(disclosed_open.get("allowed_merchants", []))
    )
    for r in results:
        if not r.ok:
            return VerifyResult.fail("unresolved_constraint", f"{r.type}: {r.detail}")

    return VerifyResult.passed(closed_payload, results)
