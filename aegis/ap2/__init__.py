"""AEGIS·CORE — the advanced track built directly on AP2's cryptographic
authorization machinery: SD-JWT Verifiable Credentials, Key-Binding
proof-of-possession (``cnf``), the ``sd_hash`` / ``checkout_hash`` binding
claims, selective disclosure, Mandate Receipts, and custom constraint types.

See AEGIS-ADVANCED.md. This package is self-contained (real EdDSA SD-JWT crypto
via ``cryptography``) and independent of the compliance pipeline in
``aegis.pipeline``.
"""

from . import sdjwt  # noqa: F401
