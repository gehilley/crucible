"""Checking a service receipt (SPEC.md §3 Sending, §5 Ingest, §7).

A receipt is the only evidence that part of a record was anchored. The service
returns one per accepted batch; it binds the chain head at the batch's last
event to a server timestamp, inside a Merkle log whose checkpoint the service
signs::

    {
      "v": 2,
      "service": "log.cruciblehub.org",       # which service holds the record
      "log_id": "<id>",
      "entry": {                               # the log leaf, verbatim
        "v": 2, "kind": "batch", "ts": <server microseconds>,
        "payload": {"session": ..., "key_id": <researcher key>,
                    "from_seq": a, "to_seq": b, "head": <h_b>,
                    "last_ts": <event b's ts>, "batch": <digest>}
      },
      "entry_hash": "sha256:...",              # sha256(JCS(entry))
      "leaf_index": i,
      "inclusion_path": ["sha256:...", ...],   # RFC 6962 PATH(i, D[i+1])
      "checkpoint": "<base64 COSE_Sign1>",     # signs {v, kind: "checkpoint",
                                               #   service, log_id,
                                               #   tree_size: i+1, root, ts}
      "consistency": null | {"from_size": m, "path": ["sha256:...", ...]}
    }

A receipt is always against the checkpoint signed when its leaf was appended
(tree size ``leaf_index + 1``), so asking for it again returns the same bytes.
``consistency`` is the RFC 6962 proof that the tree at the session's previous
receipt (size ``m``) is a prefix of this one; it is null on a session's first
receipt. Checked pairwise, these proofs show that the log only grew between a
session's receipts.

The checkpoint travels only as its signed envelope, so there is no unsigned
copy of the root or tree size that could disagree with the signed one.

This module checks with its own code: the leaf is recomputed from the entry's
canonical bytes, the path is walked by `crucible_verify.merkle` (which shares
nothing with the service's tree builder), and the signature is checked against
service public keys the caller supplies. A key is never fetched from the
service whose word it is meant to check.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from crucible_core.canonical import CanonicalizationError, canonicalize, digest_hex, is_digest, sha256_bytes
from crucible_core.cose import SignatureError, decode, verify
from crucible_core.keys import PublicKey

from . import merkle
from .results import Check, State

PROTOCOL_VERSION = 2
MAX_SAFE_INT = 2**53 - 1
RECEIPT_FIELDS = frozenset(
    {"v", "service", "log_id", "entry", "entry_hash", "leaf_index", "inclusion_path", "checkpoint", "consistency"}
)
CHECKPOINT_FIELDS = frozenset({"v", "kind", "service", "log_id", "tree_size", "root", "ts"})


@dataclass(frozen=True)
class ReceiptResult:
    """One receipt's check, with what it claims and, once verified, what it proves.

    ``authenticated`` is True when the receipt is signed by a supplied key, its
    entry is in the signed tree, and it is for this session: its span is then
    the service's word, and a mismatch with the record is evidence about the
    events. A receipt that fails before that point says nothing about them.
    ``beyond`` is True when it anchors an event the given heads do not hold.
    """

    check: Check
    from_seq: int | None = None
    to_seq: int | None = None
    service: str | None = None
    log_id: str | None = None
    key_id: str | None = None
    tree_size: int | None = None
    root: str | None = None
    ts: int | None = None
    leaf_index: int | None = None
    entry_hash: str | None = None
    consistency: dict | None = None
    authenticated: bool = False
    beyond: bool = False

    def to_json(self) -> dict:
        return {
            **self.check.to_json(),
            "from_seq": self.from_seq,
            "to_seq": self.to_seq,
            "service": self.service,
            "log_id": self.log_id,
            "key_id": self.key_id,
            "tree_size": self.tree_size,
            "ts": self.ts,
        }


def _int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _name(v: object) -> bool:
    return isinstance(v, str) and bool(v.strip())


class _Unreadable(ValueError):
    """A checkpoint in a format version this code does not read."""


def keyring(keys: PublicKey | Iterable[PublicKey] | Mapping[str, PublicKey] | None) -> dict[str, PublicKey]:
    """Service keys by key id, from one key, several, or none."""
    if keys is None:
        return {}
    if isinstance(keys, PublicKey):
        return {keys.key_id: keys}
    if isinstance(keys, Mapping):
        return dict(keys)
    return {k.key_id: k for k in keys}


def _envelope_bytes(envelope_b64: object) -> bytes:
    if not isinstance(envelope_b64, str):
        raise ValueError("the checkpoint is not a base64 string")
    try:
        raw = base64.b64decode(envelope_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"the checkpoint is not base64: {exc}") from exc
    if base64.b64encode(raw).decode("ascii") != envelope_b64:
        raise ValueError("the checkpoint is not in canonical base64")
    return raw


def signed_checkpoint(envelope_b64: object, service_key: PublicKey) -> dict:
    """Decode and verify a checkpoint envelope; return its signed payload.

    Raises ValueError with the reason when it is not a checkpoint signed by
    ``service_key`` (`_Unreadable`, a ValueError, when it is one in a format
    version this code does not read).
    """
    raw = _envelope_bytes(envelope_b64)
    try:
        env = verify(raw, service_key)
    except SignatureError as exc:
        raise ValueError(f"the checkpoint is not signed by service key {service_key.key_id}: {exc}") from exc
    try:
        payload = json.loads(env.payload_bytes)
        if canonicalize(payload) != env.payload_bytes:
            raise ValueError("the signed checkpoint is not in canonical form")
    except (json.JSONDecodeError, CanonicalizationError) as exc:
        raise ValueError(f"the signed checkpoint is not canonical JSON: {exc}") from exc
    if isinstance(payload, dict) and _int(payload.get("v")) and payload["v"] != PROTOCOL_VERSION:
        raise _Unreadable(f"the checkpoint is in format version {payload['v']}, which this code does not read")
    if not isinstance(payload, dict) or set(payload) != CHECKPOINT_FIELDS:
        raise ValueError(f"the signed checkpoint has fields {sorted(payload) if isinstance(payload, dict) else payload!r}")
    if payload["v"] != PROTOCOL_VERSION or payload["kind"] != "checkpoint":
        raise ValueError("the signed object is not a version 2 checkpoint")
    if not (_name(payload["service"]) and _name(payload["log_id"])):
        raise ValueError("the signed checkpoint does not name its service and log")
    size, ts = payload["tree_size"], payload["ts"]
    if not (_int(size) and 0 < size <= MAX_SAFE_INT and is_digest(payload["root"]) and _int(ts) and 0 < ts <= MAX_SAFE_INT):
        raise ValueError("the signed checkpoint's tree size, root or timestamp is malformed")
    return payload


def check_receipt(
    receipt: object,
    *,
    session: str,
    heads: Mapping[int, str],
    service_key: PublicKey | Iterable[PublicKey] | Mapping[str, PublicKey],
) -> ReceiptResult:
    """Check one receipt against the replayed chain's ``heads`` (seq -> head).

    The span the receipt claims is read first, as far as it can be, so that a
    malformed receipt is still reported against the events it claims to cover.
    A receipt signed by a key not in ``service_key`` could not be checked; one
    signed under a supplied key id that does not verify fails.
    """
    keys = keyring(service_key)
    entry = receipt.get("entry") if isinstance(receipt, dict) else None
    payload = entry.get("payload") if isinstance(entry, dict) else None
    a = payload.get("from_seq") if isinstance(payload, dict) else None
    b = payload.get("to_seq") if isinstance(payload, dict) else None
    span: dict = {"from_seq": a if _int(a) else None, "to_seq": b if _int(b) else None}

    def fail(reason: str) -> ReceiptResult:
        return ReceiptResult(Check("receipt", State.FAIL, reason), **span)

    def unchecked(reason: str) -> ReceiptResult:
        return ReceiptResult(Check("receipt", State.COULD_NOT_CHECK, reason), **span)

    if isinstance(receipt, dict) and _int(receipt.get("v")) and receipt["v"] != PROTOCOL_VERSION:
        return unchecked(f"the receipt is in format version {receipt['v']}, which this code does not read")
    if isinstance(entry, dict) and _int(entry.get("v")) and entry["v"] != PROTOCOL_VERSION:
        return unchecked(f"the receipt's entry is in format version {entry['v']}, which this code does not read")
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        got = sorted(receipt) if isinstance(receipt, dict) else type(receipt).__name__
        return fail(f"not a receipt: fields {got}")
    if receipt["v"] != PROTOCOL_VERSION or not (isinstance(entry, dict) and entry.get("v") == PROTOCOL_VERSION):
        return fail("the receipt or its entry has no format version")
    if not (entry.get("kind") == "batch" and isinstance(payload, dict)):
        return fail("the receipt's entry is not a batch entry")
    if not (_int(a) and _int(b) and 0 <= a <= b <= MAX_SAFE_INT):
        return fail("the batch entry's span is malformed")
    span["service"] = receipt["service"] if isinstance(receipt["service"], str) else None
    span["log_id"] = receipt["log_id"] if isinstance(receipt["log_id"], str) else None
    try:
        entry_bytes = canonicalize(entry)
    except CanonicalizationError as exc:
        return fail(f"the entry cannot be canonicalized: {exc}")
    if receipt["entry_hash"] != sha256_bytes(entry_bytes):
        return fail("entry_hash is not the digest of the entry it travels with")
    try:
        kid = decode(_envelope_bytes(receipt["checkpoint"])).key_id
    except (ValueError, SignatureError) as exc:
        return fail(f"the checkpoint is not a signed envelope: {exc}")
    span["key_id"] = kid
    key = keys.get(kid)
    if key is None:
        return unchecked(f"the checkpoint is signed by key {kid}, and no key with that id was given")
    try:
        cp = signed_checkpoint(receipt["checkpoint"], key)
    except _Unreadable as exc:
        return unchecked(str(exc))
    except ValueError as exc:
        return fail(str(exc))
    span.update(tree_size=cp["tree_size"], root=cp["root"])
    if cp["service"] != receipt["service"] or cp["log_id"] != receipt["log_id"]:
        return fail("the receipt names a different service or log than its signed checkpoint")
    index, path = receipt["leaf_index"], receipt["inclusion_path"]
    if not (isinstance(path, list) and all(is_digest(p) for p in path)):
        return fail("the inclusion path is not a list of digests")
    walked = merkle.verify_inclusion(
        leaf=merkle.leaf_hash(entry_bytes),
        leaf_index=index,
        tree_size=cp["tree_size"],
        path=[digest_hex(p) for p in path],
        root=digest_hex(cp["root"]),
    )
    if walked.outcome != merkle.Outcome.PASS:
        return fail(f"the entry is not in the signed tree: {walked.render()}")
    span.update(leaf_index=index, entry_hash=receipt["entry_hash"])
    consistency = receipt["consistency"]
    if consistency is not None:
        if not (
            isinstance(consistency, dict)
            and set(consistency) == {"from_size", "path"}
            and _int(consistency["from_size"])
            and 0 < consistency["from_size"] < cp["tree_size"]
            and isinstance(consistency["path"], list)
            and all(is_digest(p) for p in consistency["path"])
        ):
            return fail("the receipt's consistency proof is malformed")
        span["consistency"] = consistency
    if payload.get("session") != session:
        return fail(f"the receipt is for session {payload.get('session')!r}, not {session!r}")
    ts = entry.get("ts")
    if not (_int(ts) and 0 < ts <= cp["ts"]):
        return fail("the entry's server timestamp is missing, or later than the checkpoint that signs it")
    span.update(ts=ts, authenticated=True)
    if b not in heads:
        span["beyond"] = True
        return fail(f"the receipt anchors event {b}, which the record does not contain")
    if payload.get("head") != heads[b]:
        return fail(f"the receipt anchors head {payload.get('head')} at event {b}; the record's head there is {heads[b]}")
    return ReceiptResult(
        Check("receipt", State.PASS, f"events {a}..{b} anchored by {cp['service']} (log {cp['log_id']}, key {kid}, tree size {cp['tree_size']}) at {ts}"),
        **span,
    )


def check_link(earlier: ReceiptResult, later: ReceiptResult) -> Check:
    """Whether two passing receipts of one session, in one log, agree with each other.

    ``earlier`` anchors the lower span. The log must have appended the later
    leaf after the earlier one, never signed two roots for one size, and only
    grown between them (shown by ``later``'s consistency proof when the sizes
    differ).
    """
    pair = f"events {earlier.from_seq}..{earlier.to_seq} and {later.from_seq}..{later.to_seq}"
    if later.leaf_index <= earlier.leaf_index:
        if later.entry_hash == earlier.entry_hash:
            return Check("link", State.FAIL, f"{pair} are anchored by one entry")
        return Check("link", State.FAIL, f"{pair}: the later events are at leaf {later.leaf_index}, not after leaf {earlier.leaf_index}")
    if later.tree_size == earlier.tree_size:
        if later.root != earlier.root:
            return Check("link", State.FAIL, f"{pair}: the log signed two roots for tree size {later.tree_size}")
        return Check("link", State.PASS, f"{pair} are in one signed tree")
    small, big = sorted((earlier, later), key=lambda x: x.tree_size)
    proof = big.consistency
    if proof is None or proof["from_size"] != small.tree_size:
        have = "no consistency proof" if proof is None else f"a proof from size {proof['from_size']}"
        return Check("link", State.COULD_NOT_CHECK, f"{pair}: trees of size {small.tree_size} and {big.tree_size}, and {have}")
    walked = merkle.verify_consistency(
        first_size=small.tree_size,
        first_root=digest_hex(small.root),
        second_size=big.tree_size,
        second_root=digest_hex(big.root),
        path=[digest_hex(p) for p in proof["path"]],
    )
    if walked.outcome != merkle.Outcome.PASS:
        return Check("link", State.FAIL, f"{pair}: the tree of size {small.tree_size} is not a prefix of the tree of size {big.tree_size}: {walked.render()}")
    return Check("link", State.PASS, f"{pair}: the log only grew from size {small.tree_size} to {big.tree_size}")


__all__ = ["CHECKPOINT_FIELDS", "RECEIPT_FIELDS", "ReceiptResult", "check_link", "check_receipt", "keyring", "signed_checkpoint"]
