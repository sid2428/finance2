"""Feature 7 — Mandate Sandbox: replay simulator + adversarial constraint fuzzer.

Before a user ever signs an open mandate, prove what an adversarial (compromised
/ prompt-injected) agent can and cannot do with it. The fuzzer models an agent
that HOLDS the ``cnf`` key — so it can re-sign mutated mandates — and asserts the
Feature 4 verifier rejects every malicious variant. ``escaped`` MUST be empty;
wire this into CI so any verifier/constraint regression fails the build.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..crypto import generate_keypair
from . import sdjwt as S
from .mandates import Chain, seal_closed
from .verifier import VerifyContext, verify_delegation_chain


@dataclass
class Attack:
    name: str
    chain: list[str]         # [open_serialized, mutated_closed_serialized]


@dataclass
class FuzzReport:
    baseline_ok: bool
    attempted: int
    rejected: int
    escaped: list[str] = field(default_factory=list)   # MUST be empty

    @property
    def clean(self) -> bool:
        return self.baseline_ok and not self.escaped


def _mutate_closed(chain: Chain, mutate, *, key: Optional[Ed25519PrivateKey] = None) -> list[str]:
    payload = copy.deepcopy(chain.closed_m.payload)
    mutate(payload)
    sealed = seal_closed(payload, key or chain.agent_key,
                         nonce=chain.nonce, aud=chain.aud, closed_iat=chain.closed_iat)
    return [chain.open_m.serialize(), sealed.serialize()]


class MandateFuzzer:
    def attacks(self, chain: Chain) -> list[Attack]:
        wrong_key, _ = generate_keypair()

        def inflate(p): p["payment_amount"]["value_usd"] *= 10; p["payment_amount"]["value"] = p["payment_amount"]["value_usd"]
        def swap_payee(p): p["payee"] = {"id": "attacker", "name": "Attacker LLC", "mcc": p["payee"].get("mcc")}
        def rebind(p): p["sd_hash"] = "A" * 43
        def swap_checkout(p): p["checkout_hash"] = "B" * 43
        def drop_constraint(p): p["constraints"] = p["constraints"][1:]
        def swap_line_item(p): p["line_items"] = [{"title": "gift card", "quantity": 1, "price": p["payment_amount"]["value_usd"]}]

        atks = [
            Attack("amount_inflate", _mutate_closed(chain, inflate)),
            Attack("payee_swap", _mutate_closed(chain, swap_payee)),
            Attack("rebind_open", _mutate_closed(chain, rebind)),
            Attack("checkout_swap", _mutate_closed(chain, swap_checkout)),
            Attack("constraint_drop", _mutate_closed(chain, drop_constraint)),
            Attack("line_item_swap", _mutate_closed(chain, swap_line_item)),
            # Re-signed with the WRONG key (attacker's, not the endorsed cnf).
            Attack("kb_key_swap", _mutate_closed(chain, lambda p: None, key=wrong_key)),
            # Flood with bogus disclosures that match no digest (DoS / leak probe).
            Attack("disclosure_flood", self._disclosure_flood(chain)),
        ]
        return atks

    def _disclosure_flood(self, chain: Chain) -> list[str]:
        bogus = [S.make_object_disclosure(f"junk{i}", i).raw for i in range(1000)]
        flooded = S.SDJWT(issuer_jwt=chain.closed_m.issuer_jwt,
                          disclosures=list(chain.closed_m.disclosures) + bogus,
                          kb_jwt=chain.closed_m.kb_jwt)
        return [chain.open_m.serialize(), flooded.serialize()]

    def run(self, chain: Chain, ctx: VerifyContext) -> FuzzReport:
        baseline = verify_delegation_chain(chain.as_list(), chain.checkout_jwt, ctx)
        attacks = self.attacks(chain)
        escaped = []
        for atk in attacks:
            res = verify_delegation_chain(atk.chain, chain.checkout_jwt, ctx)
            if res.ok:                         # an attack that verified == a hole
                escaped.append(atk.name)
        return FuzzReport(
            baseline_ok=baseline.ok,
            attempted=len(attacks),
            rejected=len(attacks) - len(escaped),
            escaped=escaped,
        )
