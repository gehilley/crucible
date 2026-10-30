"""COSE_Sign1 envelopes (RFC 9052) over JCS payloads (RFC 8785).

Every signed object in Crucible -- event batches, service checkpoints -- is the
same shape:

    COSE_Sign1(
        protected = {1: -8 (EdDSA), 4: <key_id ascii>, 3: "application/crucible+json"},
        payload   = JCS(<the object>),
        signature = Ed25519 over the RFC 9052 Sig_structure
    )

**Envelope digest.** The identity of a signed object is the digest of its
*encoded envelope bytes*, not of its payload:

    envelope_digest = sha256(COSE_Sign1 encoding)

Hashing the envelope rather than the payload means re-signing an unchanged
payload under a different key yields a different identity -- key substitution
is visible, not a silent swap.

**Determinism.** Ed25519 is deterministic and pycose emits the protected header
as canonical CBOR, so signing the same payload with the same key twice yields
byte-identical envelopes. Goldens depend on this; ``test_cose.py`` asserts it.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

import cbor2

from pycose.algorithms import EdDSA
from pycose.headers import KID, Algorithm, ContentType
from pycose.keys import OKPKey
from pycose.keys.curves import Ed25519 as Ed25519Curve
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.keys.keyparam import KpKeyOps
from pycose.messages import Sign1Message

from .canonical import canonicalize, sha256_bytes
from .keys import PrivateKey, PublicKey

#: Content type recorded in the COSE protected header.
CONTENT_TYPE = "application/crucible+json"
#: A key id is ``sha256:`` and 64 hex digits; a kid far longer than that is refused unread.
MAX_KID = 128


class SignatureError(Exception):
    """Raised when an envelope is malformed or its signature does not verify."""


def _sign_key(key: PrivateKey) -> OKPKey:
    return OKPKey(
        crv=Ed25519Curve,
        d=key.private_bytes,
        x=key.public_bytes,
        optional_params={KpKeyOps: [SignOp]},
    )


def _verify_key(public_bytes: bytes) -> OKPKey:
    return OKPKey(
        crv=Ed25519Curve,
        x=public_bytes,
        optional_params={KpKeyOps: [VerifyOp]},
    )


def sign(payload: object, key: PrivateKey) -> bytes:
    """Canonicalize ``payload``, wrap in COSE_Sign1, sign with ``key``."""
    msg = Sign1Message(
        phdr={
            Algorithm: EdDSA,
            KID: key.key_id.encode("ascii"),
            ContentType: CONTENT_TYPE,
        },
        payload=canonicalize(payload),
    )
    msg.key = _sign_key(key)
    return msg.encode(tag=True)


def _protected(key_id: str) -> bytes:
    """The one protected header this code writes, in the order `sign` encodes it."""
    return cbor2.dumps({1: -8, 4: key_id.encode("ascii"), 3: CONTENT_TYPE})


def sign_with(payload: object, key_id: str, sign_bytes: Callable[[bytes], bytes]) -> bytes:
    """Build the same COSE_Sign1 as `sign`, asking ``sign_bytes`` for the signature.

    For a key that never leaves its holder -- a KMS key -- the caller passes a
    function that sends the RFC 9052 ``Sig_structure`` bytes to the holder and
    returns the raw 64-byte Ed25519 signature. Ed25519 is deterministic, so for
    the same key this is byte-identical to `sign`; ``test_cose.py`` asserts it.

    The protected header is encoded exactly as pycose encodes it: a CBOR map in
    the order alg, kid, content type.
    """
    protected = _protected(key_id)
    body = canonicalize(payload)
    to_be_signed = cbor2.dumps(["Signature1", protected, b"", body])
    signature = sign_bytes(to_be_signed)
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        raise SignatureError("an Ed25519 signer must return 64 bytes")
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, body, bytes(signature)]))


@dataclass(frozen=True)
class Envelope:
    """A decoded COSE_Sign1 envelope, not yet verified."""

    raw: bytes
    key_id: str
    payload_bytes: bytes

    @property
    def envelope_digest(self) -> str:
        return sha256_bytes(self.raw)

    def payload(self) -> object:
        return json.loads(self.payload_bytes)


def decode(raw: bytes) -> Envelope:
    """Parse envelope bytes. Does *not* check the signature -- use ``verify``."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SignatureError("envelope must be bytes")
    try:
        msg = Sign1Message.decode(bytes(raw))
    except Exception as exc:
        raise SignatureError(f"not a COSE_Sign1 envelope: {exc}") from exc
    kid = msg.phdr.get(KID)
    if not kid:
        raise SignatureError("envelope has no kid in its protected header")
    # Owned here rather than inherited. `pycose` refuses a non-bytestring `kid`
    # while decoding the header today, which keeps an integer `kid` from driving
    # an allocation before any signature is checked. That is a guard in a
    # dependency: if a version bump relaxes it, an integer reaches `kid.decode`
    # below and leaves as an `AttributeError`, past every `except SignatureError`
    # a caller writes. A parser at an untrusted boundary answers
    # `SignatureError` or nothing.
    if not isinstance(kid, (bytes, bytearray)):
        raise SignatureError(f"kid is not a byte string, but {type(kid).__name__}")
    if len(kid) > MAX_KID:
        raise SignatureError(f"kid is {len(kid)} bytes, longer than any key id")
    if msg.phdr.get(Algorithm) is not EdDSA:
        raise SignatureError("envelope algorithm is not EdDSA")
    if msg.payload is None:
        raise SignatureError("envelope has a detached payload; not supported")
    try:
        key_id = kid.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SignatureError("kid is not ASCII") from exc
    # One encoding per signed object: the protected header exactly as `sign`
    # writes it (so no `crit` or other label rides along), an empty unprotected
    # header, and nothing after the envelope. Otherwise the same signature would
    # have many envelopes, each with its own digest, and the digest is the
    # signed object's identity.
    signature = getattr(msg, "signature", None)
    if not isinstance(signature, (bytes, bytearray)):
        raise SignatureError("envelope has no signature")
    canonical = cbor2.dumps(cbor2.CBORTag(18, [_protected(key_id), {}, bytes(msg.payload), bytes(signature)]))
    if canonical != bytes(raw):
        raise SignatureError("envelope is not in the one encoding this code writes (headers, or bytes after it)")
    return Envelope(raw=bytes(raw), key_id=key_id, payload_bytes=bytes(msg.payload))


def verify(raw: bytes, public: PublicKey) -> Envelope:
    """Decode and verify ``raw`` against ``public``.

    Raises ``SignatureError`` on a bad signature or a kid/key_id mismatch.
    Returning normally means: these exact bytes were signed by this exact key.
    """
    env = decode(raw)
    if env.key_id != public.key_id:
        raise SignatureError(f"envelope kid {env.key_id} does not match key {public.key_id}")
    msg = Sign1Message.decode(env.raw)
    msg.key = _verify_key(public.public_bytes)
    try:
        ok = msg.verify_signature()
    except Exception as exc:
        raise SignatureError(f"signature verification failed: {exc}") from exc
    if not ok:
        raise SignatureError(f"bad signature on envelope {env.envelope_digest}")
    return env


def envelope_digest(raw: bytes) -> str:
    """Digest of encoded envelope bytes; a signed object's identity."""
    return sha256_bytes(raw)


__all__ = [
    "CONTENT_TYPE",
    "Envelope",
    "SignatureError",
    "decode",
    "envelope_digest",
    "sign",
    "sign_with",
    "verify",
]
