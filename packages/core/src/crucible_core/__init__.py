"""Crucible primitives.

The one package every other package may import: JCS (RFC 8785) for
canonicalization, sha256 digests, COSE_Sign1 (RFC 9052) for signing, and the
local Ed25519 key format. Ported from v1's ``crucible_core`` without its trust
tiers and salted intent hashes, which SPEC.md has no use for
(``docs/v1-audit.md`` §1).
"""

from __future__ import annotations

from .canonical import (
    CanonicalizationError,
    DuplicateJSONKeyError,
    canonicalize,
    digest,
    digest_hex,
    is_digest,
    loads_one_reading,
    sha256_bytes,
    sha256_file,
)
from .cose import Envelope, SignatureError, decode, envelope_digest, sign, sign_with, verify
from .keys import PrivateKey, PublicKey, compute_key_id

__version__ = "0.0.0"

__all__ = [
    "CanonicalizationError",
    "DuplicateJSONKeyError",
    "Envelope",
    "PrivateKey",
    "PublicKey",
    "SignatureError",
    "__version__",
    "canonicalize",
    "compute_key_id",
    "decode",
    "digest",
    "digest_hex",
    "envelope_digest",
    "is_digest",
    "loads_one_reading",
    "sha256_bytes",
    "sha256_file",
    "sign",
    "sign_with",
    "verify",
]
