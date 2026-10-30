"""The service's signing key in AWS KMS (SPEC.md §5 Scale; docs/phase0-deployment.md).

The key is ``ECC_NIST_EDWARDS25519``; KMS signs the RFC 9052 ``Sig_structure``
bytes with ``ED25519_SHA_512`` and ``MessageType=RAW`` (pure Ed25519, COSE alg
-8), so the envelope is byte-identical to one `crucible_core.cose.sign` makes
with the same key (`cose.sign_with`). The private half never exists outside
KMS.

**One key, one log.** A key that signed two logs would let two contradicting
histories both verify. Genesis tags the key ``crucible:log_id=<id>`` and
refuses a key that already carries the tag; opening a log refuses a key whose
tag names another log (`bind`).
"""

from __future__ import annotations

from crucible_core.cose import sign_with
from crucible_core.keys import PublicKey, compute_key_id

from .journal import JournalError

LOG_TAG = "crucible:log_id"


def region_of(key: str) -> str | None:
    """The region a KMS key ARN names (a key lives there); None for a bare id or alias."""
    if not key.startswith("arn:"):
        return None
    parts = key.split(":")
    if len(parts) < 6 or parts[2] != "kms" or not parts[3]:
        raise ValueError(f"{key!r} is not a KMS key ARN (arn:aws:kms:<region>:<account>:key/<id>)")
    return parts[3]


def _client(key: str):
    import boto3

    return boto3.client("kms", region_name=region_of(key))


class KmsSigner:
    """A `signer.Signer` whose key is a KMS key."""

    def __init__(self, key: str, *, client=None, label: str = "") -> None:
        from botocore.exceptions import BotoCoreError, ClientError
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

        self.key = key
        self.client = client or _client(key)
        try:
            info = self.client.get_public_key(KeyId=key)
        except (ClientError, BotoCoreError) as exc:
            raise JournalError(f"cannot read the KMS key {key}: {exc}") from exc
        if info.get("KeySpec") != "ECC_NIST_EDWARDS25519" or "ED25519_SHA_512" not in info.get("SigningAlgorithms", []):
            raise ValueError(f"KMS key {key} is not an Ed25519 signing key ({info.get('KeySpec')})")
        public = load_der_public_key(info["PublicKey"])
        if not isinstance(public, Ed25519PublicKey):
            raise ValueError(f"KMS key {key} does not hold an Ed25519 public key")
        raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._public = PublicKey(role="service", key_id=compute_key_id(raw), public_bytes=raw, label=label)
        self.key_id = self._public.key_id

    def public(self) -> PublicKey:
        return self._public

    def _sign_bytes(self, message: bytes) -> bytes:
        resp = self.client.sign(KeyId=self.key, Message=message, MessageType="RAW", SigningAlgorithm="ED25519_SHA_512")
        return resp["Signature"]

    def sign(self, payload: object) -> bytes:
        return sign_with(payload, self.key_id, self._sign_bytes)

    # --- one key, one log ----------------------------------------------------------
    def bound_to(self) -> str | None:
        tags = self.client.list_resource_tags(KeyId=self.key).get("Tags", [])
        return next((t["TagValue"] for t in tags if t.get("TagKey") == LOG_TAG), None)

    def bind(self, log_id: str, *, genesis: bool) -> None:
        """At genesis, mark the key as this log's; otherwise, check it is."""
        held = self.bound_to()
        if genesis:
            if held is not None:
                raise JournalError(f"KMS key {self.key} already signs log {held}; one key signs one log")
            self.client.tag_resource(KeyId=self.key, Tags=[{"TagKey": LOG_TAG, "TagValue": log_id}])
            if self.bound_to() != log_id:
                raise JournalError(f"KMS key {self.key} could not be bound to log {log_id}")
        elif held != log_id:
            raise JournalError(f"KMS key {self.key} is bound to log {held!r}, not {log_id}")


__all__ = ["LOG_TAG", "KmsSigner", "region_of"]
