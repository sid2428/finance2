"""Feature 2 — Minimal-Disclosure Solver + Decoy-Digest Privacy Budget.

Selective disclosure treated as a constrained minimization: given a verifier's
constraint set, compute the *smallest* subset of open-mandate disclosures that
still satisfies every constraint, so the agent never over-reveals. Decoy array
elements (added at issuance) pad the number of hidden claims so the *count*
itself doesn't leak intent.
"""

from __future__ import annotations

from . import sdjwt as S
from .constraints import ConstraintRegistry


def _array_disclosure_digests(open_m: S.SDJWT) -> set[str]:
    """Digests of the open mandate's selectively-disclosable array elements
    (the allowed-merchant slots the agent may choose to reveal)."""
    return {S.parse_disclosure(r).digest for r in open_m.disclosures
            if S.parse_disclosure(r).kind == "array"}


def minimal_disclosure_set(
    open_m: S.SDJWT, closed_payload: dict, registry: ConstraintRegistry, ctx: dict
) -> set[str]:
    """Return the minimal set of open-mandate disclosure digests that still
    satisfies every constraint (greedy shrink from the full set)."""
    candidates = _array_disclosure_digests(open_m)

    def satisfies(subset: set[str]) -> bool:
        disclosed_open, ok = S.disclose(S.present(open_m, subset))
        if not ok:
            return False
        eval_ctx = {**ctx, "disclosed_merchants": disclosed_open.get("allowed_merchants", [])}
        return all(r.ok for r in registry.evaluate(closed_payload, eval_ctx))

    if not satisfies(candidates):
        return candidates                    # cannot be satisfied even fully open

    working = set(candidates)
    for d in list(candidates):
        trial = working - {d}
        if satisfies(trial):
            working = trial                  # d was not needed
    return working


def observable_slots(open_m: S.SDJWT) -> int:
    """What an observer can count: allowed-merchant array placeholders in the
    signed payload (real + decoy). Invariant to how much the agent discloses."""
    count = 0
    for v in open_m.payload.values():
        if isinstance(v, list):
            count += sum(1 for e in v if isinstance(e, dict) and set(e) == {"..."})
    return count


def add_decoys_note() -> str:
    """Decoys are issuer-time (see ``issue_sd_jwt(sd_array_decoys=...)``); they
    cannot be added at presentation without breaking the issuer signature."""
    return "decoys are added at issuance via sd_array_decoys"
