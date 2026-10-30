"""RFC 6962-style Merkle tree.

The hashing rules are Certificate Transparency's, unchanged::

    MTH({})     = SHA-256()                                  # empty tree
    MTH({d0})   = SHA-256(0x00 || d0)                         # leaf
    MTH(D[n])   = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])) # interior
                  where k is the largest power of two strictly less than n

The 0x00/0x01 domain separation is the point: without it a leaf could be
substituted for an interior node and the tree would be second-preimage
vulnerable.

**This module builds trees and emits proofs. It does not check them.**
`crucible_verify` carries its own independent implementation of path checking
and never imports this one. That split is deliberate: the independence that
matters for a transparency log is between the party making a proof and the
party checking it, and a verifier that borrowed the log's own code would
inherit any bug the log has.

The verification functions here exist only so the service's own tests can
assert that what it emits is checkable at all. Nothing outside
`packages/service` calls them.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

#: MTH of the empty tree: SHA-256 of the empty string.
EMPTY_ROOT = hashlib.sha256(b"").digest()


class ProofError(Exception):
    """Raised when a proof cannot be produced for the requested parameters."""


def leaf_hash(entry: bytes) -> bytes:
    """Hash one log entry into a leaf. ``entry`` is the canonical entry bytes."""
    return hashlib.sha256(LEAF_PREFIX + entry).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash two subtree roots into their parent."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than ``n`` (RFC 6962's ``k``)."""
    if n < 2:
        raise ValueError("split is only defined for n >= 2")
    return 1 << (n - 1).bit_length() - 1


def root(leaves: Sequence[bytes]) -> bytes:
    """Merkle tree hash over a sequence of *leaf hashes*."""
    n = len(leaves)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaves[0]
    k = _split(n)
    return node_hash(root(leaves[:k]), root(leaves[k:]))


def prefix_roots(leaves: Sequence[bytes]) -> list[bytes]:
    """``[root(leaves[:1]), root(leaves[:2]), ..., root(leaves)]`` in one pass.

    Keeps the perfect subtrees that size ``k`` decomposes into (one per set bit
    of ``k``, largest first) and folds them right to left, which is RFC 6962's
    MTH for every prefix; ``O(n log n)`` instead of ``root`` per prefix.
    """
    peaks: list[tuple[int, bytes]] = []  # (height, subtree root)
    out = []
    for leaf in leaves:
        node, height = leaf, 0
        while peaks and peaks[-1][0] == height:
            node, height = node_hash(peaks.pop()[1], node), height + 1
        peaks.append((height, node))
        acc = peaks[-1][1]
        for _, p in reversed(peaks[:-1]):
            acc = node_hash(p, acc)
        out.append(acc)
    return out


def inclusion_proof(index: int, leaves: Sequence[bytes]) -> list[bytes]:
    """Audit path for ``leaves[index]``, leaf-to-root order (RFC 6962 PATH)."""
    n = len(leaves)
    if not 0 <= index < n:
        raise ProofError(f"leaf index {index} is outside a tree of size {n}")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return [*inclusion_proof(index, leaves[:k]), root(leaves[k:])]
    return [*inclusion_proof(index - k, leaves[k:]), root(leaves[:k])]


def consistency_proof(m: int, leaves: Sequence[bytes]) -> list[bytes]:
    """Proof that a tree of size ``m`` is a prefix of this one (RFC 6962 PROOF).

    This is what bounds a log's ability to equivocate: a checkpoint the log
    published earlier must remain provably a prefix of everything it publishes
    later, so it cannot quietly rewrite history between two observers.
    """
    n = len(leaves)
    if not 0 < m <= n:
        raise ProofError(f"cannot prove consistency of size {m} against size {n}")
    if m == n:
        return []
    return _subproof(m, leaves, True)


def _subproof(m: int, leaves: Sequence[bytes], is_root: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if is_root else [root(leaves)]
    k = _split(n)
    if m <= k:
        return [*_subproof(m, leaves[:k], is_root), root(leaves[k:])]
    return [*_subproof(m - k, leaves[k:], False), root(leaves[:k])]


# --- verification, for this package's own tests only ------------------------


def verify_inclusion(
    leaf: bytes, index: int, tree_size: int, path: Sequence[bytes], expected_root: bytes
) -> bool:
    """Recompute a root from a leaf and its audit path.

    Present so the service's tests can assert its own proofs are checkable.
    `crucible_verify` re-implements this independently and does not import it.
    """
    if not 0 <= index < tree_size:
        return False
    node = leaf
    fn, sn = index, tree_size - 1
    for sibling in path:
        if fn % 2 == 1 or fn == sn:
            node = node_hash(sibling, node)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            node = node_hash(node, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and node == expected_root


def verify_consistency(
    m: int, n: int, proof: Sequence[bytes], old_root: bytes, new_root: bytes
) -> bool:
    """Check that a size-``m`` root is a prefix of a size-``n`` root."""
    if m < 1 or n < m:
        return False
    if m == n:
        return not proof and old_root == new_root
    if not proof:
        return False

    nodes = list(proof)
    if m & (m - 1) == 0:  # m is a power of two: the old root is implicit
        nodes.insert(0, old_root)

    fn, sn = m - 1, n - 1
    while fn % 2 == 1:
        fn >>= 1
        sn >>= 1

    fr = sr = nodes[0]
    for sibling in nodes[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr = node_hash(sibling, fr)
            sr = node_hash(sibling, sr)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, sibling)
        fn >>= 1
        sn >>= 1

    return sn == 0 and fr == old_root and sr == new_root


__all__ = [
    "EMPTY_ROOT",
    "LEAF_PREFIX",
    "NODE_PREFIX",
    "ProofError",
    "consistency_proof",
    "inclusion_proof",
    "leaf_hash",
    "node_hash",
    "prefix_roots",
    "root",
    "verify_consistency",
    "verify_inclusion",
]
