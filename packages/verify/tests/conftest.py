"""A test-only receipt minter.

Builds the Merkle tree with a recursive transcription of RFC 6962 §2.1 (MTH and
PATH), not with the service's builder, so these receipts are independent of the
code they will later be compared against.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from crucible_core.canonical import canonicalize, sha256_bytes
from crucible_core.cose import sign


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _k(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves: list[bytes]) -> bytes:
    if not leaves:
        return _h(b"")
    if len(leaves) == 1:
        return _h(b"\x00" + leaves[0])
    k = _k(len(leaves))
    return _h(b"\x01" + mth(leaves[:k]) + mth(leaves[k:]))


def path(m: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) <= 1:
        return []
    k = _k(len(leaves))
    if m < k:
        return path(m, leaves[:k]) + [mth(leaves[k:])]
    return path(m - k, leaves[k:]) + [mth(leaves[:k])]


def subproof(m: int, leaves: list[bytes], whole: bool = True) -> list[bytes]:
    """RFC 6962 §2.1.2 SUBPROOF(m, D[n], b)."""
    n = len(leaves)
    if m == n:
        return [] if whole else [mth(leaves)]
    k = _k(n)
    if m <= k:
        return subproof(m, leaves[:k], whole) + [mth(leaves[k:])]
    return subproof(m - k, leaves[k:], False) + [mth(leaves[:k])]


def _hex(b: bytes) -> str:
    return "sha256:" + b.hex()


def checkpoint_envelope(leaves, size, key, *, service, log_id, ts, root=None):
    cp = {"v": 2, "kind": "checkpoint", "service": service, "log_id": log_id, "tree_size": size,
          "root": root or _hex(mth(leaves[:size])), "ts": ts}
    return base64.b64encode(sign(cp, key)).decode("ascii")


def mint(entries: list[dict], key, *, service="test.service", log_id="log-1", ts=1_761_264_100_000_000, at="leaf") -> list[dict]:
    """One receipt per entry, as the service issues them.

    ``at="leaf"``: each against the checkpoint at its own leaf (size i+1), with
    a consistency proof from the previous entry of its session. ``at="end"``:
    all against one checkpoint of the whole tree, with no proofs.
    """
    leaves = [canonicalize(e) for e in entries]
    out, last_of = [], {}
    for i, e in enumerate(entries):
        size = i + 1 if at == "leaf" else len(leaves)
        session = e["payload"].get("session")
        prev = last_of.get(session)
        consistency = None
        if at == "leaf" and prev is not None:
            consistency = {"from_size": prev + 1, "path": [_hex(p) for p in subproof(prev + 1, leaves[:size])]}
        last_of[session] = i
        out.append({
            "v": 2,
            "service": service,
            "log_id": log_id,
            "entry": e,
            "entry_hash": sha256_bytes(leaves[i]),
            "leaf_index": i,
            "inclusion_path": [_hex(p) for p in path(i, leaves[:size])],
            "checkpoint": checkpoint_envelope(leaves, size, key, service=service, log_id=log_id, ts=ts),
            "consistency": consistency,
        })
    return out


def batch_entry(session: str, a: int, b: int, head: str, *, ts: int, key_id: str = "sha256:" + "aa" * 32) -> dict:
    return {
        "v": 2,
        "kind": "batch",
        "ts": ts,
        "payload": {"session": session, "key_id": key_id, "from_seq": a, "to_seq": b, "head": head,
                    "last_ts": ts, "batch": "sha256:" + "bb" * 32},
    }


@pytest.fixture
def receipts_for():
    """receipts_for(records, spans, key, **kw): receipts for the given (a, b) spans."""

    def make(records, spans, key, **kw):
        session = records[0]["event"]["session"]
        entries = [batch_entry(session, a, b, records[b]["head"], ts=1_761_264_050_000_000 + b) for a, b in spans]
        return mint(entries, key, **kw)

    return make


@pytest.fixture
def minter():
    """The minter's functions, for tests that build receipts entry by entry."""
    from types import SimpleNamespace

    return SimpleNamespace(mint=mint, batch_entry=batch_entry, checkpoint_envelope=checkpoint_envelope,
                           subproof=subproof, mth=mth, path=path, hex=_hex)
