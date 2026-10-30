"""The service's signing key, behind one interface (SPEC.md §5 Scale).

"Signing keys live in a managed key service rather than on a host." In
production the checkpoint key is a KMS Ed25519 key (``ECC_NIST_EDWARDS25519``,
``ED25519_SHA_512``, ``MessageType=RAW``); its private half never exists as a
file. Tests and local runs use a key file. Both produce the same COSE_Sign1
bytes for the same key, through `crucible_core.cose.sign_with`.
"""

from __future__ import annotations

from typing import Protocol

from crucible_core.cose import sign_with
from crucible_core.keys import PrivateKey, PublicKey


class Signer(Protocol):
    key_id: str

    def public(self) -> PublicKey:
        """The public half, which verifiers are given out of band."""

    def sign(self, payload: object) -> bytes:
        """A COSE_Sign1 envelope over JCS(payload)."""


class LocalSigner:
    """A key held in a local file. For tests and local runs, never production."""

    def __init__(self, key: PrivateKey) -> None:
        if key.role != "service":
            raise ValueError(f"a service signer needs a service key, not a {key.role} key")
        self._key = key
        self.key_id = key.key_id

    def public(self) -> PublicKey:
        return self._key.public()

    def sign(self, payload: object) -> bytes:
        return sign_with(payload, self.key_id, self._key.obj.sign)


__all__ = ["LocalSigner", "Signer"]
