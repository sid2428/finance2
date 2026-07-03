"""Pydantic data models.

Inbound models are AP2-aligned (Intent / Cart / Payment mandate chain, each a
W3C Verifiable Credential). Outbound is the AEGIS-native signed DecisionEnvelope
plus the internal signal types the pipeline stages emit.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field

from .crypto import canonical_bytes


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --- Verifiable Credential proof ------------------------------------------

class VerifiableCredentialProof(BaseModel):
    """W3C VC-style proof. ``verification_method`` is a DID URL (did#key) that
    resolves to an Ed25519 public key; ``signature`` covers the mandate's
    canonical content with the proof removed."""

    type: str = "Ed25519Signature2020"
    verification_method: str            # e.g. "did:aegis:buyer-1#key-1"
    signature: str                      # hex
    created: datetime = Field(default_factory=utcnow)


# --- Shared value objects --------------------------------------------------

class Jurisdiction(BaseModel):
    iso: str                            # ISO-3166 alpha-2
    role: Literal["buyer", "merchant", "rail", "data_residency"]


class Amount(BaseModel):
    value: float
    currency: str = "USD"
    value_usd: float


class Party(BaseModel):
    legal_name: Optional[str] = None
    account_ref: Optional[str] = None
    wallet: Optional[str] = None
    did: Optional[str] = None


class LineItem(BaseModel):
    sku: str
    description: str
    quantity: int = 1
    unit_price_usd: float


class PaymentInstrument(BaseModel):
    kind: Literal["card", "x402_stablecoin", "bank"]
    reference: str                      # PAN token / wallet / IBAN token


# --- Inbound AP2 mandates --------------------------------------------------

class _SignedMandate(BaseModel):
    """Base for mandates carrying a detachable VC proof."""

    proof: Optional[VerifiableCredentialProof] = None

    def signing_payload(self) -> bytes:
        """Canonical bytes of the mandate with the proof field excluded."""
        data = self.model_dump(mode="json", exclude={"proof"})
        return canonical_bytes(data)


class IntentMandate(_SignedMandate):
    mandate_id: str
    natural_language_description: str
    max_value_usd: Optional[float] = None
    allowed_merchants: list[str] = Field(default_factory=list)
    requires_refundability: bool = False
    intent_expiry: datetime
    signer_did: str
    originator: Party = Field(default_factory=Party)
    beneficiary: Party = Field(default_factory=Party)


class CartMandate(_SignedMandate):
    mandate_id: str
    intent_ref: str
    line_items: list[LineItem]
    total_usd: float
    refund_period_days: int = 0
    merchant_did: str
    merchant_legal_name: Optional[str] = None
    beneficiary: Party = Field(default_factory=Party)

    def summary_text(self) -> str:
        items = ", ".join(
            f"{li.quantity}x {li.description}" for li in self.line_items
        )
        return f"{items} totalling {self.total_usd:.2f} USD"


class PaymentMandate(_SignedMandate):
    mandate_id: str
    cart_ref: str
    instrument: PaymentInstrument
    human_present: bool = False
    settlement_rail: str                # e.g. "card", "x402", "sepa", "sim"
    initiator_agent: str                # DID of the agent initiating (maker)


class MandateBundle(BaseModel):
    """The full AP2 chain submitted for evaluation, plus routing/world hints."""

    intent: IntentMandate
    cart: CartMandate
    payment: PaymentMandate
    touched_jurisdictions: list[Jurisdiction] = Field(default_factory=list)
    processing_region: str = "US"       # region actually evaluating this mandate
    guardians: list[str] = Field(default_factory=list)  # eligible step-up signers


# --- Internal pipeline signals --------------------------------------------

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Signal(BaseModel):
    """A finding emitted by a pipeline stage.

    ``hard_block`` short-circuits the pipeline (regulatory strict liability).
    ``risk_delta`` lets graduated signals push the risk score up — never down.
    """

    code: str                           # ISO-20022-style external reason code
    detail: str
    severity: Severity = Severity.MEDIUM
    hard_block: bool = False
    risk_delta: float = 0.0
    stage: str = ""
    recommend: Optional[str] = None     # e.g. "FILE_SAR"


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    BLOCK = "BLOCK"


# --- Step-up (Feature 5) ---------------------------------------------------

class StepUpChallenge(BaseModel):
    challenge_id: str
    cart_hash: str                      # SCA dynamic linking: bound to this cart
    required_m: int
    initiator: str                      # maker — excluded from approving
    eligible_approvers: list[str]
    created: datetime = Field(default_factory=utcnow)
    contributions: dict[str, str] = Field(default_factory=dict)  # did -> sig hex


# --- Outbound decision envelope -------------------------------------------

class DecisionEnvelope(BaseModel):
    decision_id: str
    mandate_id: str
    verdict: Verdict
    reason_codes: list[str] = Field(default_factory=list)
    rationale: str = ""
    signals: list[Signal] = Field(default_factory=list)
    risk_score: float = 0.0
    model_provenance: dict[str, str] = Field(default_factory=dict)
    liability: dict[str, float] = Field(default_factory=dict)
    liability_basis: str = ""
    stepup: Optional[StepUpChallenge] = None
    sar_draft: Optional[dict] = None
    ruleset_version: str = ""
    world_snapshot_hash: str = ""
    prev_envelope_hash: str = ""
    this_hash: str = ""
    ts: datetime = Field(default_factory=utcnow)
    signature: str = ""

    def signing_payload(self) -> bytes:
        """Envelope bytes excluding the fields set *by* signing/hashing."""
        data = self.model_dump(mode="json", exclude={"signature", "this_hash"})
        return canonical_bytes(data)
