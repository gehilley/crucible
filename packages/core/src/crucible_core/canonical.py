"""Canonicalization and content addressing.

Every logical object is serialized with JCS (RFC 8785) before it is hashed or
signed: SPEC.md §3 seals each event as ``H(h_{n-1} || canonical(event_n))``. Two
implementations that agree on the logical JSON value MUST produce identical
bytes, hence identical digests, across platforms and Python versions.

Digests are carried as ``"sha256:<lowercase-hex>"`` strings everywhere in the
protocol. Bare hex never appears in an envelope field.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import rfc8785

DIGEST_PREFIX = "sha256:"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonicalized under RFC 8785."""


class DuplicateJSONKeyError(ValueError):
    """Raised when a JSON object states one key more than once.

    A ``ValueError`` on purpose, and not a new exception family: every reader in
    this repository that decodes untrusted JSON text already writes
    ``except ValueError`` and turns the failure into a counted, classified
    unreadable record. Subclassing means a duplicate key lands in the arm that
    was already built for "this line could not be read", rather than escaping as
    a traceback from a checker -- which would be a checker's own bug filed as an
    accusation against the document it was reading.
    """


def canonicalize(value: Any) -> bytes:
    """Serialize ``value`` to RFC 8785 canonical JSON bytes.

    Rejects anything JCS cannot represent deterministically (NaN, Infinity,
    non-string object keys, sets, bytes, arbitrary objects).
    """
    try:
        return rfc8785.dumps(value)
    except Exception as exc:  # rfc8785 raises several unrelated types
        raise CanonicalizationError(f"value is not JCS-serializable: {exc}") from exc


def _one_reading(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that refuses an object stating a key twice."""
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise DuplicateJSONKeyError(
                f"a JSON object states the key {key!r} more than once. `json.loads` keeps the "
                f"last silently, so the value a reader sees in the file and the value a checker "
                f"verifies would be two different things -- a document with two readings is not "
                f"an audit record"
            )
        seen[key] = value
    return seen


def loads_one_reading(
    text: str | bytes | bytearray,
    *,
    parse_constant: Any = None,
    parse_int: Any = None,
    parse_float: Any = None,
) -> Any:
    """Decode JSON text, refusing any object that states a key twice.

    ``json.loads`` resolves a duplicate key by keeping the last one, silently.
    That makes a document say one thing to a person reading it and another to
    the code checking it: a receipt whose visible text reads
    ``"leaf_index": 4096`` can verify as leaf 9, and both parties are looking at
    the same bytes. Every other integrity property in this system rests on the
    two agreeing, so the decoder is where the disagreement has to be refused --
    JCS (RFC 8785) makes one value have one encoding, and this is the read-side
    half of that: one encoding has one reading.

    Used for JSON that arrives as **text from outside** -- an export line, a
    transcript line, a service response body. Signed payloads are deliberately
    *not* routed through here: a verifier that checks a signed payload
    re-canonicalizes to the exact bytes that were signed already refuses a
    duplicate key, and reports it as the determinate ``fail`` it is. Raising here
    instead would downgrade that finding to an unreadable record -- a
    demonstrated forgery turned back into a hole.

    Raises ``DuplicateJSONKeyError`` (a ``ValueError``) on a repeated key, and
    whatever ``json.loads`` raises otherwise.

    ``parse_constant``/``parse_int``/``parse_float`` are forwarded to
    ``json.loads`` unchanged so a caller that already rejects NaN/Infinity, an
    oversized integer literal, or a non-finite float keeps that rejection *and*
    gains duplicate-key refusal in one call. Each defaults to
    ``None``, which is exactly what ``json.loads`` receives when the keyword is
    omitted, so every existing caller -- all of which pass ``text`` alone -- is
    byte-for-byte unchanged: ``json.loads(text, object_pairs_hook=_one_reading,
    parse_constant=None, parse_int=None, parse_float=None)`` is the same call as
    ``json.loads(text, object_pairs_hook=_one_reading)``.
    """
    return json.loads(
        text,
        object_pairs_hook=_one_reading,
        parse_constant=parse_constant,
        parse_int=parse_int,
        parse_float=parse_float,
    )


def sha256_bytes(data: bytes) -> str:
    """Digest raw bytes -> ``"sha256:<hex>"``."""
    return DIGEST_PREFIX + hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    """Digest a JSON value via its canonical form -> ``"sha256:<hex>"``."""
    return sha256_bytes(canonicalize(value))


def sha256_file(path, chunk_size: int = 1024 * 1024) -> str:
    """Digest a file's contents without loading it whole."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(chunk_size):
            h.update(chunk)
    return DIGEST_PREFIX + h.hexdigest()


def is_digest(value: object) -> bool:
    """True iff ``value`` is a well-formed ``sha256:`` digest string.

    ``fullmatch``, not ``match``: Python's ``$`` also matches immediately before
    a trailing newline, so ``match`` would accept ``"sha256:<hex>\n"``. That
    value seals into a signed record and then fails to equal the same digest
    anywhere else -- a content store would report a missing blob for content
    that is present.
    """
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None


def digest_hex(value: str) -> bytes:
    """Extract the raw 32 digest bytes from a ``"sha256:<hex>"`` string."""
    if not is_digest(value):
        raise ValueError(f"not a sha256 digest string: {value!r}")
    return bytes.fromhex(value[len(DIGEST_PREFIX) :])

