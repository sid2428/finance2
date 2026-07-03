"""A compact but real SD-JWT implementation (RFC 9901) over EdDSA/Ed25519.

Supports the pieces the advanced features need:
  * JWS compact signing/verification (alg=EdDSA, OKP/Ed25519 JWK).
  * Object-property disclosures ``[salt, key, value]`` and array-element
    disclosures ``[salt, value]``, with SHA-256 digests placed in ``_sd`` /
    ``{"...": digest}``.
  * Selective presentation (reveal a chosen subset of disclosures).
  * Key-Binding JWT (``kb+jwt``) carrying ``nonce``, ``aud``, ``iat`` and the
    ``sd_hash`` over the presented SD-JWT.
  * Decoy digests (RFC 9901 §4.2.5) so the count of hidden claims does not leak.

Not a complete JOSE stack — just what AP2 mandate chains require, implemented
faithfully enough that the binding/proof checks in Feature 4 are genuine.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..crypto import verify as _ed_verify

# --- base64url ------------------------------------------------------------

def b64u_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    import base64
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_b64u(data: bytes) -> str:
    return b64u_encode(hashlib.sha256(data).digest())


# --- JWK (OKP / Ed25519) --------------------------------------------------

def jwk_from_public(pub_raw: bytes) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(pub_raw)}


def public_raw_from_jwk(jwk: dict) -> bytes:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("unsupported JWK (expected OKP/Ed25519)")
    return b64u_decode(jwk["x"])


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint (canonical members only)."""
    canonical = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    return sha256_b64u(_json_bytes(canonical))


# --- JWS compact (EdDSA) --------------------------------------------------

def sign_jws(header: dict, payload: dict, private_key: Ed25519PrivateKey) -> str:
    h = dict(header)
    h.setdefault("alg", "EdDSA")
    signing_input = f"{b64u_encode(_json_bytes(h))}.{b64u_encode(_json_bytes(payload))}"
    sig = private_key.sign(signing_input.encode("ascii"))
    return f"{signing_input}.{b64u_encode(sig)}"


def parse_jws(compact: str) -> tuple[dict, dict, bytes, bytes]:
    parts = compact.split(".")
    if len(parts) != 3:
        raise ValueError("malformed JWS")
    h_b64, p_b64, s_b64 = parts
    header = json.loads(b64u_decode(h_b64))
    payload = json.loads(b64u_decode(p_b64))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    return header, payload, signing_input, b64u_decode(s_b64)


def verify_jws(compact: str, public_raw: bytes) -> bool:
    try:
        _, _, signing_input, sig = parse_jws(compact)
        Ed25519PublicKey.from_public_bytes(public_raw).verify(sig, signing_input)
        return True
    except Exception:
        return False


# --- Disclosures ----------------------------------------------------------

def _salt() -> str:
    return b64u_encode(os.urandom(16))


@dataclass(frozen=True)
class Disclosure:
    raw: str                 # base64url of the disclosure array JSON
    kind: str                # "object" | "array"
    key: Optional[str]       # object property name (None for array element)
    value: Any

    @property
    def digest(self) -> str:
        return sha256_b64u(self.raw.encode("ascii"))


def make_object_disclosure(key: str, value: Any, salt: Optional[str] = None) -> Disclosure:
    salt = salt or _salt()
    raw = b64u_encode(_json_bytes([salt, key, value]))
    return Disclosure(raw=raw, kind="object", key=key, value=value)


def make_array_disclosure(value: Any, salt: Optional[str] = None) -> Disclosure:
    salt = salt or _salt()
    raw = b64u_encode(_json_bytes([salt, value]))
    return Disclosure(raw=raw, kind="array", key=None, value=value)


def parse_disclosure(raw: str) -> Disclosure:
    arr = json.loads(b64u_decode(raw))
    if len(arr) == 3:
        return Disclosure(raw=raw, kind="object", key=arr[1], value=arr[2])
    if len(arr) == 2:
        return Disclosure(raw=raw, kind="array", key=None, value=arr[1])
    raise ValueError("invalid disclosure arity")


def decoy_digest() -> str:
    """A digest with no corresponding disclosure — indistinguishable from real."""
    return sha256_b64u(os.urandom(32))


# --- SD-JWT container -----------------------------------------------------

@dataclass
class SDJWT:
    issuer_jwt: str                      # the signed JWS (issuer/holder part)
    disclosures: list[str] = field(default_factory=list)   # raw disclosure strs
    kb_jwt: Optional[str] = None

    def serialize(self) -> str:
        parts = [self.issuer_jwt, *self.disclosures]
        body = "~".join(parts) + "~"
        if self.kb_jwt:
            body += self.kb_jwt
        return body

    @staticmethod
    def parse(s: str) -> "SDJWT":
        segments = s.split("~")
        issuer = segments[0]
        rest = segments[1:]
        kb = None
        if rest and rest[-1] != "":
            kb = rest[-1]
            rest = rest[:-1]
        else:
            rest = rest[:-1] if rest and rest[-1] == "" else rest
        disclosures = [d for d in rest if d]
        return SDJWT(issuer_jwt=issuer, disclosures=disclosures, kb_jwt=kb)

    @property
    def payload(self) -> dict:
        return parse_jws(self.issuer_jwt)[1]

    @property
    def header(self) -> dict:
        return parse_jws(self.issuer_jwt)[0]

    def presentation_without_kb(self) -> str:
        return "~".join([self.issuer_jwt, *self.disclosures]) + "~"

    def sd_hash(self) -> str:
        """RFC 9901 sd_hash over the issuer-JWT + disclosures presentation.
        Used for KB-JWT binding of a specific presentation."""
        return sha256_b64u(self.presentation_without_kb().encode("ascii"))

    def issuer_hash(self) -> str:
        """Hash of the immutable issuer-signed JWT only — stable across
        selective disclosure. Used to bind a closed mandate to the exact open
        mandate it derives from (anti-rebind), independent of what the holder
        chooses to disclose."""
        return sha256_b64u(self.issuer_jwt.encode("ascii"))


# --- Issuance -------------------------------------------------------------

_SD = "_sd"
_ARRAY_KEY = "..."


def issue_sd_jwt(
    signer_key: Ed25519PrivateKey,
    *,
    claims: dict,
    sd_object: Optional[dict] = None,
    sd_array: Optional[dict] = None,
    header: Optional[dict] = None,
    decoys: int = 0,
    sd_array_decoys: Optional[dict] = None,
) -> tuple["SDJWT", list[Disclosure]]:
    """Issue an SD-JWT.

    ``claims``      -> plain (always-disclosed, "locked") payload claims.
    ``sd_object``   -> {name: value} object properties made selectively
                       disclosable (digests go into top-level ``_sd``).
    ``sd_array``    -> {name: [values]} arrays whose elements are each
                       selectively disclosable (``{"...": digest}`` placeholders).
    ``decoys``      -> number of decoy digests padded into ``_sd``.
    """
    payload: dict = dict(claims)
    disclosures: list[Disclosure] = []

    sd_digests: list[str] = []
    for key, value in (sd_object or {}).items():
        d = make_object_disclosure(key, value)
        disclosures.append(d)
        sd_digests.append(d.digest)
    for _ in range(decoys):
        sd_digests.append(decoy_digest())
    if sd_digests:
        payload[_SD] = sorted(sd_digests)

    import random
    for name, values in (sd_array or {}).items():
        elements = []
        for v in values:
            d = make_array_disclosure(v)
            disclosures.append(d)
            elements.append({_ARRAY_KEY: d.digest})
        # Decoy array elements (RFC 9901 §4.2.5): pad so the number of real
        # elements is not observable from the count of placeholders.
        n_decoy = (sd_array_decoys or {}).get(name, 0)
        for _ in range(n_decoy):
            elements.append({_ARRAY_KEY: decoy_digest()})
        random.shuffle(elements)     # decoys indistinguishable from real slots
        payload[name] = elements

    jwt = sign_jws(header or {"typ": "sd-jwt"}, payload, signer_key)
    return SDJWT(issuer_jwt=jwt, disclosures=[d.raw for d in disclosures]), disclosures


def _disclosure_map(raws: list[str]) -> dict[str, Disclosure]:
    return {parse_disclosure(r).digest: parse_disclosure(r) for r in raws}


def disclose(sdjwt: "SDJWT") -> tuple[dict, bool]:
    """Reconstruct the revealed claim set from the disclosures present.

    Returns (processed_payload, ok). ``ok`` is False if any presented
    disclosure does not correspond to a digest in the payload (a tampered or
    forged disclosure) — RFC 9901 §7 processing.
    """
    dmap: dict[str, Disclosure] = {}
    malformed = False
    for r in sdjwt.disclosures:
        try:
            d = parse_disclosure(r)
            dmap[d.digest] = d
        except Exception:
            malformed = True
    used: set[str] = set()

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                if k == _SD:
                    for digest in v:
                        d = dmap.get(digest)
                        if d is not None and d.kind == "object":
                            used.add(digest)
                            out[d.key] = walk(d.value)
                        # else: hidden/decoy — skip
                    continue
                out[k] = walk(v)
            return out
        if isinstance(node, list):
            out_list = []
            for elem in node:
                if isinstance(elem, dict) and set(elem.keys()) == {_ARRAY_KEY}:
                    d = dmap.get(elem[_ARRAY_KEY])
                    if d is not None and d.kind == "array":
                        used.add(elem[_ARRAY_KEY])
                        out_list.append(walk(d.value))
                    # else hidden
                else:
                    out_list.append(walk(elem))
            return out_list
        return node

    processed = walk(sdjwt.payload)
    # Every presented disclosure must be well-formed and consumed by a digest.
    ok = (not malformed) and used == set(dmap.keys())
    return processed, ok


def present(sdjwt: "SDJWT", keep_digests: set[str]) -> "SDJWT":
    """Return a copy revealing only the disclosures whose digest is in
    ``keep_digests`` (used by the minimal-disclosure solver)."""
    kept = [r for r in sdjwt.disclosures
            if parse_disclosure(r).digest in keep_digests]
    return SDJWT(issuer_jwt=sdjwt.issuer_jwt, disclosures=kept, kb_jwt=sdjwt.kb_jwt)


# --- Key-Binding JWT ------------------------------------------------------

def make_kb_jwt(
    holder_key: Ed25519PrivateKey, *, nonce: str, aud: str, iat: int, sd_hash: str
) -> str:
    header = {"typ": "kb+jwt", "alg": "EdDSA"}
    payload = {"nonce": nonce, "aud": aud, "iat": iat, "sd_hash": sd_hash}
    return sign_jws(header, payload, holder_key)


def verify_kb_jwt(
    kb_jwt: str, cnf_jwk: dict, *, expected_nonce: str, expected_sd_hash: str
) -> bool:
    try:
        header, payload, _, _ = parse_jws(kb_jwt)
        if header.get("typ") != "kb+jwt":
            return False
        if payload.get("nonce") != expected_nonce:
            return False
        if payload.get("sd_hash") != expected_sd_hash:
            return False
        return verify_jws(kb_jwt, public_raw_from_jwk(cnf_jwk))
    except Exception:
        return False
