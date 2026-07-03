"""Tunable thresholds and constants for the AEGIS decision pipeline.

Every magic number a compliance auditor would question lives here, with the
regulation it derives from noted inline. In production these are loaded from a
versioned ruleset bundle (see ``ruleset_version``); here they are module-level
so the whole thing is inspectable in one place.
"""

from __future__ import annotations

# The ruleset version pinned into every decision envelope. Bump on any change
# to the constants below so decisions remain replayable against the ruleset
# that produced them.
RULESET_VERSION = "aegis-ruleset-2026.07.0"

# --- Feature 1: Jurisdiction / FATF Travel Rule (Rec. 16) -------------------
# Originator/beneficiary attestation required at/above this USD-equivalent.
# Strictest-binding = min() across all touched jurisdictions.
TRAVEL_RULE_THRESHOLD_DEFAULT_USD = 1_000.0
TRAVEL_RULE_THRESHOLDS_USD = {
    "US": 3_000.0,   # legacy US $3,000
    "EU": 1_000.0,
    "GB": 1_000.0,
    "SG": 1_000.0,
    "JP": 1_000.0,
    "CH": 1_000.0,
    "AE": 1_000.0,
}
# Jurisdictions on which a settlement rail may be categorically ineligible.
RESTRICTED_JURISDICTIONS = {"IR", "KP", "SY", "CU"}

# --- Feature 2: Sanctions & PEP -------------------------------------------
# Jaro-Winkler (+phonetic bonus) acceptance band. Tuned per audit to balance
# false-positive (over-block) vs false-negative (evasion) cost.
SANCTIONS_MATCH_THRESHOLD = 0.90
PHONETIC_MATCH_BONUS = 0.06
# OFAC 50% Rule: block if aggregate sanctioned ownership >= this share.
OFAC_OWNERSHIP_BLOCK_RATIO = 0.50

# --- Feature 3: Structuring & Velocity ------------------------------------
CTR_THRESHOLD_USD = 10_000.0            # US Currency Transaction Report (31 USC)
STRUCTURING_WINDOW_SECONDS = 24 * 3600  # rolling 24h cluster window
STRUCTURING_MIN_CLUSTER = 3             # N sub-threshold transfers to trip
# Per-agent velocity caps (fail-closed if exceeded).
VELOCITY_MAX_COUNT_24H = 50
VELOCITY_MAX_VALUE_24H_USD = 250_000.0

# --- Feature 4: Adversarial / intent drift --------------------------------
# Cosine *distance* (1 - similarity) above which the cart has drifted from the
# signed intent. HIGH severity (injection / price breach) hard-blocks; a plain
# drift is MEDIUM and only raises risk.
#
# Tuned for the dependency-free hashed-bag-of-words stand-in embedder, which
# under-scores *related* short texts (a legit item match lands near 0.68) while
# unrelated carts sit at ~1.0. A production sentence-embedder is tuned lower
# (~0.35). Swap the embedder and this threshold together.
INTENT_DRIFT_THRESHOLD = 0.85

# --- Feature 5: Risk bands & step-up quorum --------------------------------
# Risk score is 0..100. Below LOW: frictionless ALLOW. LOW..STEPUP: quorum
# step-up. Above STEPUP: BLOCK.
RISK_LOW_BAND = 40.0
RISK_STEPUP_BAND = 75.0

# --- Feature 6: Liability floors ------------------------------------------
# Reg E / Reg Z consumer-protection floor: a consumer's apportioned share of an
# *unauthorized* transaction is capped here regardless of control failures.
REG_E_CONSUMER_CAP_RATIO = 0.10

# --- System ----------------------------------------------------------------
STEPUP_CHALLENGE_TTL_SECONDS = 15 * 60
