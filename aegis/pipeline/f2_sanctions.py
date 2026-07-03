"""Feature 2 — Sanctions & PEP Interdiction Engine.

Screens every identity in the mandate chain (merchant legal name, beneficiary
name/wallet, agent DIDs) against OFAC SDN / EU Consolidated / UN SC lists using
Jaro-Winkler + phonetic matching, and applies the OFAC 50% Rule via the
beneficial-ownership graph.

A sanctions hit is a HARD BLOCK (regulatory strict liability). A PEP hit is
NOT a block — it flags Enhanced Due Diligence (EDD) and raises risk.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import (
    OFAC_OWNERSHIP_BLOCK_RATIO,
    PHONETIC_MATCH_BONUS,
    SANCTIONS_MATCH_THRESHOLD,
)
from ..data import (
    OwnershipGraph,
    WatchlistEntry,
    default_ownership_graph,
    default_watchlist,
)
from ..matching import jaro_winkler_similarity, phonetic_key
from ..models import Severity, Signal
from .context import DecisionContext

STAGE = "f2_sanctions"


@dataclass
class Hit:
    entry: WatchlistEntry
    score: float
    is_pep: bool


def screen_name(candidate: str, watchlist: list[WatchlistEntry]) -> list[Hit]:
    if not candidate:
        return []
    cand_phon = phonetic_key(candidate)
    cand_l = candidate.lower()
    hits: list[Hit] = []
    for entry in watchlist:
        jw = jaro_winkler_similarity(cand_l, entry.name.lower())
        bonus = PHONETIC_MATCH_BONUS if entry.phonetic == cand_phon else 0.0
        score = jw + bonus
        if score >= SANCTIONS_MATCH_THRESHOLD:
            hits.append(Hit(entry=entry, score=min(score, 1.0), is_pep=entry.is_pep))
    return sorted(hits, key=lambda h: h.score, reverse=True)


def ofac_50_percent(entity_id: str, graph: OwnershipGraph) -> float:
    """Return aggregate sanctioned ownership share (>= 0.50 → blocked)."""
    return graph.sanctioned_share(entity_id)


def _candidate_names(ctx: DecisionContext) -> list[str]:
    b = ctx.bundle
    names = [
        b.cart.merchant_legal_name,
        b.cart.beneficiary.legal_name if b.cart.beneficiary else None,
        b.intent.beneficiary.legal_name if b.intent.beneficiary else None,
    ]
    # De-duplicate (case-insensitively) so a name repeated across mandate
    # fields is screened — and risk-scored — only once.
    seen: set[str] = set()
    unique: list[str] = []
    for n in names:
        if n and n.lower() not in seen:
            seen.add(n.lower())
            unique.append(n)
    return unique


def run(ctx: DecisionContext) -> None:
    ctx.controls.psp_ran_sanctions_screen = True  # this stage IS the screen
    watchlist = default_watchlist()
    graph = default_ownership_graph()

    # --- Name screening (sanctions = block, PEP = EDD) ---
    for name in _candidate_names(ctx):
        for hit in screen_name(name, watchlist):
            if hit.is_pep and hit.entry.list_name == "PEP":
                ctx.add_signal(Signal(
                    code="AGENT.SANC.PEP_EDD",
                    detail=(
                        f"'{name}' ~ PEP '{hit.entry.name}' "
                        f"(score={hit.score:.3f}); enhanced due diligence required"
                    ),
                    severity=Severity.MEDIUM,
                    hard_block=False,
                    risk_delta=25.0,
                    stage=STAGE,
                    recommend="ENHANCED_DUE_DILIGENCE",
                ))
            else:
                ctx.add_signal(Signal(
                    code="AGENT.SANC.SDN_HIT",
                    detail=(
                        f"'{name}' matches {hit.entry.list_name} entry "
                        f"'{hit.entry.name}' ({hit.entry.entity_id}) "
                        f"score={hit.score:.3f}"
                    ),
                    severity=Severity.HIGH,
                    hard_block=True,
                    stage=STAGE,
                ))
                return  # strict-liability hard block short-circuits

    # --- OFAC 50% Rule on the beneficiary entity, if identified by id ---
    benef_id = None
    if ctx.bundle.cart.beneficiary and ctx.bundle.cart.beneficiary.account_ref:
        benef_id = ctx.bundle.cart.beneficiary.account_ref
    if benef_id:
        share = ofac_50_percent(benef_id, graph)
        if share >= OFAC_OWNERSHIP_BLOCK_RATIO:
            ctx.add_signal(Signal(
                code="AGENT.SANC.OFAC_50PCT",
                detail=(
                    f"Beneficiary {benef_id} is {share:.0%} owned by sanctioned "
                    f"parties (>= {OFAC_OWNERSHIP_BLOCK_RATIO:.0%} OFAC 50% Rule)"
                ),
                severity=Severity.HIGH,
                hard_block=True,
                stage=STAGE,
            ))
            return
