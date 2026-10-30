"""The RFC 6962 Merkle tree the service commits to (ported from v1's notary).

The tree is the service's entire claim to non-equivocation, so this file treats
RFC 6962 as the specification and `crucible_service.merkle` as the thing under
test -- never the reverse. The vectors at the top are the RFC's own published
known answers over its eight test entries, frozen. A change to any of them is a
protocol break that would silently invalidate every receipt ever issued; the fix
is never to update the expectation.

Below the goldens the coverage is exhaustive rather than sampled: for every tree
size up to 17 -- past the point where power-of-two boundaries, odd splits and the
ragged right edge all interact -- every audit path is verified, every single-node
mutation of it is rejected, and every prefix size is checked for consistency.
Sampling would be the wrong instinct here. A split bug that only shows up at one
awkward size is exactly the bug that survives review and reaches production, and
`merkle.py` is the one module in the service whose output a third party will still
be checking years after the service is gone.

`verify_inclusion` / `verify_consistency` exist in `merkle` for this file's
benefit only: `crucible_verify` re-implements path checking and never imports
this module, because a verifier that borrowed the log's own code would inherit
whatever the log got wrong. What these tests establish is that the proofs the
service emits are checkable and that no forged variant of them checks out. The
*independent* check is `crucible_verify`'s job, by design.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterator

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from crucible_service.merkle import (
    EMPTY_ROOT,
    LEAF_PREFIX,
    NODE_PREFIX,
    ProofError,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    node_hash,
    root,
    verify_consistency,
    verify_inclusion,
)

# --- frozen RFC 6962 known-answer vectors ----------------------------------
# The eight test entries from the RFC's reference test data, and the Merkle tree
# hash of the first n of them for n = 1..8. Reproduced here as hex so that a
# reader can check them against the RFC without running anything.

RFC_ENTRIES: tuple[str, ...] = (
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
)

RFC_ROOTS: tuple[str, ...] = (
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
)

#: SHA-256 of the empty string, which is what the RFC defines MTH({}) to be.
EMPTY_ROOT_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

#: ``(leaf index, tree size, audit path)``. The RFC's reference vectors are
#: 1-based on the leaf; these are converted to the 0-based index this API takes.
RFC_INCLUSION_PROOFS: tuple[tuple[int, int, tuple[str, ...]], ...] = (
    (0, 1, ()),
    (
        0,
        8,
        (
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ),
    ),
    (
        5,
        8,
        (
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ),
    ),
    (2, 3, ("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",)),
    (
        1,
        5,
        (
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        ),
    ),
)

#: ``(old size, new size, proof)`` from the same reference data.
RFC_CONSISTENCY_PROOFS: tuple[tuple[int, int, tuple[str, ...]], ...] = (
    (1, 1, ()),
    (
        1,
        8,
        (
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ),
    ),
    (
        6,
        8,
        (
            "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ),
    ),
    (
        2,
        5,
        (
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        ),
    ),
)

#: 17 crosses two power-of-two boundaries and leaves a single ragged leaf on the
#: right of the top split, which is where audit-path off-by-ones hide.
TREE_SIZES = tuple(range(1, 18))

# The fork fixtures: two trees agreeing on the first SHARED leaves, diverging
# after, and reaching the same size. Same size on purpose -- a size difference
# would let a test pass for the wrong reason.
SHARED = 5
FORK_SIZE = 12


def rfc_leaves(n: int) -> list[bytes]:
    """Leaf hashes of the first `n` RFC test entries."""
    return [leaf_hash(bytes.fromhex(entry)) for entry in RFC_ENTRIES[:n]]


def leaves(n: int) -> list[bytes]:
    """`n` distinct leaf hashes. `leaves(k)` is a prefix of `leaves(n)` for k < n.

    The tree only ever sees opaque bytes -- the service hands it `entry_bytes`, but
    nothing in `merkle` knows or cares what an entry is.
    """
    return [leaf_hash(f"entry-{i}".encode()) for i in range(n)]


def fork(tag: str, shared: int = SHARED, size: int = FORK_SIZE) -> list[bytes]:
    """A tree sharing `shared` leaves with `leaves(...)` and diverging after."""
    return [
        *leaves(shared),
        *(leaf_hash(f"{tag}-entry-{i}".encode()) for i in range(shared, size)),
    ]


def hexes(path: list[bytes]) -> list[str]:
    return [node.hex() for node in path]


# --- known answers ----------------------------------------------------------


def test_the_empty_tree_root_is_sha256_of_the_empty_string():
    """MTH({}) is not a hash of nothing-in-particular: RFC 6962 pins it, and a
    checkpoint over an empty log has to be a value both sides already agree on."""
    assert hashlib.sha256(b"").digest() == EMPTY_ROOT
    assert EMPTY_ROOT.hex() == EMPTY_ROOT_HEX
    assert root([]) == EMPTY_ROOT


@pytest.mark.parametrize(
    ("size", "expected"),
    list(enumerate(RFC_ROOTS, start=1)),
    ids=[f"n{i}" for i in range(1, len(RFC_ROOTS) + 1)],
)
def test_the_merkle_tree_hash_matches_the_rfc_6962_known_answer(size, expected):
    assert root(rfc_leaves(size)).hex() == expected


def test_a_single_leaf_tree_roots_at_the_leaf_itself():
    """The RFC gives the one-leaf tree no interior node, so MTH({d0}) is the leaf
    hash unmodified -- wrapping it once more would fork us off every other
    implementation at n=1 and nowhere else."""
    assert root(rfc_leaves(1)) == leaf_hash(b"")
    assert root(rfc_leaves(1)).hex() == RFC_ROOTS[0]


@pytest.mark.parametrize(("index", "size", "expected"), RFC_INCLUSION_PROOFS)
def test_inclusion_proofs_match_the_rfc_6962_reference_vectors(index, size, expected):
    tree = rfc_leaves(size)
    path = inclusion_proof(index, tree)

    assert hexes(path) == list(expected)
    assert verify_inclusion(tree[index], index, size, path, root(tree))


@pytest.mark.parametrize(("m", "n", "expected"), RFC_CONSISTENCY_PROOFS)
def test_consistency_proofs_match_the_rfc_6962_reference_vectors(m, n, expected):
    tree = rfc_leaves(n)
    proof = consistency_proof(m, tree)

    assert hexes(proof) == list(expected)
    assert verify_consistency(m, n, proof, root(rfc_leaves(m)), root(tree))


def test_every_proof_node_is_a_raw_thirty_two_byte_digest():
    """Proof nodes go into receipts as `sha256:<hex>` (schemas.build_receipt), so
    a node that is not raw digest bytes would serialize into a receipt that no
    verifier could parse."""
    tree = leaves(11)
    nodes = [*inclusion_proof(4, tree), *consistency_proof(6, tree), root(tree)]

    assert nodes and all(isinstance(n, bytes) and len(n) == 32 for n in nodes)


# --- domain separation ------------------------------------------------------


def test_the_leaf_and_node_prefixes_are_the_rfc_constants():
    assert (LEAF_PREFIX, NODE_PREFIX) == (b"\x00", b"\x01")
    assert leaf_hash(b"x") == hashlib.sha256(b"\x00x").digest()
    assert node_hash(b"l", b"r") == hashlib.sha256(b"\x01lr").digest()


def test_a_leaf_and_an_interior_node_over_the_same_bytes_hash_differently():
    """The 0x00/0x01 prefixes are second-preimage resistance, not decoration.

    Drop them and MTH of a two-leaf tree is SHA-256(l0 || l1) -- which is exactly
    the root a *one*-leaf tree over the entry `l0 || l1` would have. An attacker
    could then take an interior node, present it as a log entry, and produce a
    valid-looking receipt for bytes the log never committed to. The prefixes make
    the two constructions live in disjoint halves of the hash's input space, so
    no leaf can ever masquerade as a node or vice versa.
    """
    left, right = leaf_hash(b"left"), leaf_hash(b"right")
    unprefixed = hashlib.sha256(left + right).digest()

    assert leaf_hash(left + right) != node_hash(left, right)
    assert root([left, right]) != root([leaf_hash(left + right)])
    assert unprefixed not in (leaf_hash(left + right), node_hash(left, right))


def test_a_leaf_hash_is_not_the_bare_hash_of_the_entry():
    """Content addressing elsewhere in Crucible is plain SHA-256 (`sha256_bytes`),
    so a leaf must not collide with a content digest that happens to name the same
    bytes -- the two are answers to different questions."""
    entry = b"an entry"
    assert leaf_hash(entry) != hashlib.sha256(entry).digest()


# --- inclusion proofs, exhaustively ----------------------------------------


@pytest.mark.parametrize("n", TREE_SIZES)
def test_every_inclusion_proof_in_a_tree_of_this_size_verifies(n):
    tree = leaves(n)
    expected = root(tree)

    for index in range(n):
        path = inclusion_proof(index, tree)
        assert verify_inclusion(tree[index], index, n, path, expected), (
            f"the log's own proof for leaf {index} of {n} did not verify"
        )


@pytest.mark.parametrize("n", TREE_SIZES)
def test_an_inclusion_proof_is_at_most_ceil_log2_n_nodes_long(n):
    """Receipts are archived forever and travel inside exported chains, so path
    length is a storage cost that has to stay logarithmic; a linear path would
    also mean the tree had degenerated into a list and lost its whole point."""
    tree = leaves(n)
    bound = math.ceil(math.log2(n))

    for index in range(n):
        assert len(inclusion_proof(index, tree)) <= bound, f"leaf {index} of {n} exceeded {bound}"


def _flip(node: bytes) -> bytes:
    """A near-miss node: one bit off, still 32 bytes, still plausible on the wire."""
    return bytes([node[0] ^ 0x01]) + node[1:]


def _corrupted(path: list[bytes]) -> Iterator[list[bytes]]:
    for i in range(len(path)):
        yield [*path[:i], _flip(path[i]), *path[i + 1 :]]


def _dropped(path: list[bytes]) -> Iterator[list[bytes]]:
    for i in range(len(path)):
        yield [*path[:i], *path[i + 1 :]]


def _duplicated(path: list[bytes]) -> Iterator[list[bytes]]:
    for i in range(len(path)):
        yield [*path[: i + 1], path[i], *path[i + 1 :]]


def _reordered(path: list[bytes]) -> Iterator[list[bytes]]:
    for i in range(len(path) - 1):
        if path[i] != path[i + 1]:  # a swap of equal nodes would prove nothing
            yield [*path[:i], path[i + 1], path[i], *path[i + 2 :]]


#: name -> (mutator, smallest tree size whose paths that mutator can act on).
#: The minimum matters: a sweep that silently produced no mutated paths would
#: report green while testing nothing at all.
MUTATIONS = {
    "corrupted": (_corrupted, 2),
    "dropped": (_dropped, 2),
    "duplicated": (_duplicated, 2),
    "reordered": (_reordered, 3),
}

MUTATION_SWEEP = [
    (name, n) for name, (_, smallest) in MUTATIONS.items() for n in TREE_SIZES if n >= smallest
]


@pytest.mark.parametrize(("mutation", "n"), MUTATION_SWEEP, ids=lambda v: str(v))
def test_no_single_node_mutation_of_an_audit_path_still_verifies(mutation, n):
    """A forged inclusion proof, swept rather than sampled.

    Every position in every path of every tree up to 17 leaves gets corrupted,
    dropped, duplicated, and swapped with its neighbour. Any one of these that
    still verified would let a log prove membership of an entry it never
    committed to, which is the only lie a receipt is supposed to be unable to
    tell.
    """
    mutate, _ = MUTATIONS[mutation]
    tree = leaves(n)
    expected = root(tree)
    attempts = 0

    for index in range(n):
        path = inclusion_proof(index, tree)
        for forged in mutate(path):
            attempts += 1
            assert not verify_inclusion(tree[index], index, n, forged, expected), (
                f"a {mutation} audit path for leaf {index} of {n} verified: {hexes(forged)}"
            )

    assert attempts, f"the {mutation} sweep produced no mutated paths at n={n}"


def test_a_single_leaf_tree_accepts_only_the_empty_audit_path():
    """n=1 has no mutations to sweep because its path is empty -- so the case that
    matters is the opposite one: a fabricated node appended to nothing."""
    tree = leaves(1)

    assert inclusion_proof(0, tree) == []
    assert verify_inclusion(tree[0], 0, 1, [], root(tree))
    assert not verify_inclusion(tree[0], 0, 1, [leaf_hash(b"invented")], root(tree))


@pytest.mark.parametrize("n", TREE_SIZES)
def test_a_proof_for_one_leaf_never_proves_a_different_leaf(n):
    """The index is part of what is proved. A path that verified under a
    neighbouring index would make leaf order unenforceable."""
    tree = leaves(n)
    expected = root(tree)

    for index in range(n):
        path = inclusion_proof(index, tree)
        for other in range(n):
            if other != index:
                assert not verify_inclusion(tree[index], other, n, path, expected), (
                    f"leaf {index}'s path verified at index {other} in a tree of {n}"
                )


@pytest.mark.parametrize("m", range(1, 9))
def test_an_audit_path_issued_at_one_tree_size_does_not_verify_at_a_later_one(m):
    """A receipt is bound to the checkpoint it names. The audit path for a leaf
    covers every *other* leaf in the tree, so growing the log necessarily changes
    it -- which is why `verify` must check a receipt against the tree size the
    receipt claims, never against whatever the log serves today."""
    for n in range(m + 1, 13):
        grown = leaves(n)
        older = grown[:m]
        for index in range(m):
            stale = inclusion_proof(index, older)
            assert not verify_inclusion(grown[index], index, n, stale, root(grown)), (
                f"a size-{m} path for leaf {index} verified against a size-{n} root"
            )


@pytest.mark.parametrize(("index", "size"), [(-1, 4), (4, 4), (99, 4), (0, 0), (-1, 0)])
def test_an_inclusion_proof_outside_the_tree_raises_instead_of_returning_a_path(index, size):
    """Returning `[]` for an impossible index would hand the caller a proof that
    the caller then has to know to distrust; raising makes it impossible to miss."""
    with pytest.raises(ProofError, match=f"leaf index {index} is outside a tree of size {size}"):
        inclusion_proof(index, leaves(size))


@pytest.mark.parametrize(
    ("index", "size"),
    [(-1, 4), (4, 4), (0, 0)],
    ids=["negative-index", "index-at-size", "empty-tree"],
)
def test_verify_inclusion_rejects_an_index_outside_the_tree(index, size):
    tree = leaves(max(size, 1))
    assert not verify_inclusion(tree[0], index, size, [], root(tree))


# --- consistency proofs, exhaustively --------------------------------------


@pytest.mark.parametrize("n", TREE_SIZES)
def test_every_prefix_of_this_tree_has_a_verifying_consistency_proof(n):
    """What bounds the log's ability to equivocate: every checkpoint it ever
    published must remain provably a prefix of everything it publishes later."""
    tree = leaves(n)
    new_root = root(tree)

    for m in range(1, n + 1):
        proof = consistency_proof(m, tree)
        assert verify_consistency(m, n, proof, root(tree[:m]), new_root), (
            f"consistency of size {m} against size {n} did not verify"
        )


@pytest.mark.parametrize("n", TREE_SIZES)
def test_a_consistency_proof_is_at_most_ceil_log2_n_plus_one_nodes_long(n):
    """RFC 6962's bound. The extra node over an audit path is the old tree's own
    root when `m` is not a power of two and has to be reconstructed."""
    tree = leaves(n)
    bound = math.ceil(math.log2(n)) + 1

    for m in range(1, n + 1):
        assert len(consistency_proof(m, tree)) <= bound, f"m={m} n={n} exceeded {bound}"


@pytest.mark.parametrize("n", TREE_SIZES)
def test_the_only_consistency_proof_a_tree_gives_for_its_own_size_is_empty(n):
    """Same size, same root, nothing to prove -- but only if the roots really do
    match, or `verify` would accept a substituted checkpoint at an unchanged size."""
    tree = leaves(n)

    assert consistency_proof(n, tree) == []
    assert verify_consistency(n, n, [], root(tree), root(tree))
    assert not verify_consistency(n, n, [], root(tree), _flip(root(tree)))
    assert not verify_consistency(n, n, [root(tree)], root(tree), root(tree))


@pytest.mark.parametrize("n", TREE_SIZES[1:])
def test_a_growing_tree_is_never_consistent_on_an_empty_proof(n):
    """A log that grew and offered nothing must not be taken at its word."""
    tree = leaves(n)
    assert not verify_consistency(1, n, [], tree[0], root(tree))


@pytest.mark.parametrize(("m", "n"), [(0, 4), (-1, 4), (5, 4), (1, 0), (0, 0)])
def test_consistency_against_a_size_the_tree_never_had_raises(m, n):
    with pytest.raises(ProofError, match=f"cannot prove consistency of size {m} against size {n}"):
        consistency_proof(m, leaves(n))


@pytest.mark.parametrize(
    ("m", "n"),
    [(0, 4), (-1, 4), (5, 4)],
    ids=["zero-old-size", "negative-old-size", "shrinking-log"],
)
def test_verify_consistency_rejects_degenerate_size_pairs(m, n):
    """A log never shrinks, so a shrinking claim is a broken or lying log, not a
    proof to be evaluated."""
    tree = leaves(4)
    assert not verify_consistency(m, n, [root(tree)], root(tree[:1]), root(tree))


@pytest.mark.parametrize("n", TREE_SIZES[2:])
def test_no_single_node_mutation_of_a_consistency_proof_still_verifies(n):
    """The equivocation defence has to survive the same tampering the audit path
    does, or a log could rewrite its own history behind a plausible-looking proof."""
    tree = leaves(n)
    new_root = root(tree)
    attempts = 0

    for m in range(1, n):
        proof = consistency_proof(m, tree)
        old_root = root(tree[:m])
        for mutate, smallest in MUTATIONS.values():
            if len(proof) < smallest:
                continue
            for forged in mutate(proof):
                attempts += 1
                assert not verify_consistency(m, n, forged, old_root, new_root), (
                    f"a mutated consistency proof for {m} -> {n} verified: {hexes(forged)}"
                )

    assert attempts, f"no mutated consistency proofs were produced at n={n}"


# --- forked trees -----------------------------------------------------------


def test_two_trees_that_share_a_prefix_agree_up_to_the_fork_and_never_after():
    left, right = fork("left"), fork("right")

    assert root(left[:SHARED]) == root(right[:SHARED])
    for size in range(SHARED + 1, FORK_SIZE + 1):
        assert root(left[:size]) != root(right[:size]), f"forked trees agree at size {size}"


@pytest.mark.parametrize("m", range(1, SHARED + 1))
def test_a_checkpoint_from_before_the_fork_is_a_prefix_of_both_branches(m):
    """Establishes that the fork fixtures really do share a prefix, so the test
    below is proving something stronger than 'these are two different trees'."""
    left, right = fork("left"), fork("right")
    old_root = root(leaves(m))

    for branch in (left, right):
        proof = consistency_proof(m, branch)
        assert verify_consistency(m, FORK_SIZE, proof, old_root, root(branch))


@pytest.mark.parametrize("m", range(SHARED + 1, FORK_SIZE + 1))
def test_no_consistency_proof_makes_a_post_fork_checkpoint_a_prefix_of_the_other_branch(m):
    """The equivocation a transparency log must not get away with: having signed a
    checkpoint at size `m` on one branch, it cannot later serve the other branch
    and produce anything that makes the old checkpoint a prefix of it. Neither the
    proof the served branch would give, nor the one the abandoned branch would.
    """
    left, right = fork("left"), fork("right")
    stale = root(left[:m])
    served = root(right)

    assert not verify_consistency(m, FORK_SIZE, consistency_proof(m, right), stale, served)
    assert not verify_consistency(m, FORK_SIZE, consistency_proof(m, left), stale, served)


@pytest.mark.parametrize("index", range(SHARED, FORK_SIZE))
def test_a_leaf_from_one_branch_cannot_be_proved_into_the_other(index):
    """A forged inclusion proof again, in its realistic shape: the receipt is
    genuine, the checkpoint is genuine, and they are from different histories."""
    left, right = fork("left"), fork("right")
    path = inclusion_proof(index, left)

    assert verify_inclusion(left[index], index, FORK_SIZE, path, root(left))
    assert not verify_inclusion(left[index], index, FORK_SIZE, path, root(right))
    assert not verify_inclusion(
        left[index], index, FORK_SIZE, inclusion_proof(index, right), root(right)
    )


# --- properties -------------------------------------------------------------
# Random leaf sets, including duplicates: two log entries may legitimately hash
# to the same leaf, and the tree must not care.

_entries = st.lists(st.binary(max_size=24), min_size=1, max_size=24)


@settings(max_examples=150, deadline=None)
@given(_entries)
def test_every_inclusion_proof_over_a_random_tree_verifies(entries):
    tree = [leaf_hash(entry) for entry in entries]
    expected = root(tree)

    assert all(
        verify_inclusion(tree[i], i, len(tree), inclusion_proof(i, tree), expected)
        for i in range(len(tree))
    )


@settings(max_examples=150, deadline=None)
@given(_entries)
def test_a_random_tree_is_consistent_with_every_prefix_of_itself(entries):
    tree = [leaf_hash(entry) for entry in entries]
    n = len(tree)
    new_root = root(tree)

    assert all(
        verify_consistency(m, n, consistency_proof(m, tree), root(tree[:m]), new_root)
        for m in range(1, n + 1)
    )


@settings(max_examples=200, deadline=None)
@given(st.lists(st.binary(max_size=8), min_size=1, max_size=80))
def test_inclusion_proofs_stay_logarithmic_on_random_trees(entries):
    tree = [leaf_hash(entry) for entry in entries]
    bound = math.ceil(math.log2(len(tree)))

    assert all(len(inclusion_proof(i, tree)) <= bound for i in range(len(tree)))


@settings(max_examples=200, deadline=None)
@given(_entries, _entries)
def test_leaf_sequences_hash_to_the_same_root_exactly_when_they_are_the_same(left, right):
    left_root = root([leaf_hash(entry) for entry in left])
    right_root = root([leaf_hash(entry) for entry in right])

    if left == right:
        assert left_root == right_root
    else:
        assert left_root != right_root


@settings(max_examples=200, deadline=None)
@given(st.data(), _entries, st.binary(max_size=24))
def test_replacing_any_leaf_changes_the_root_and_voids_its_proof(data, entries, replacement):
    """The chain's rule, restated for trees: any byte flip anywhere flips
    verification. Here the flip is a whole entry, which is the realistic edit."""
    index = data.draw(st.integers(min_value=0, max_value=len(entries) - 1))
    assume(entries[index] != replacement)

    tree = [leaf_hash(entry) for entry in entries]
    tampered = [*tree[:index], leaf_hash(replacement), *tree[index + 1 :]]
    path = inclusion_proof(index, tree)

    assert root(tampered) != root(tree)
    assert not verify_inclusion(tampered[index], index, len(tree), path, root(tree))
    assert not verify_inclusion(tree[index], index, len(tree), path, root(tampered))


def test_prefix_roots_equal_the_root_of_every_prefix():
    from crucible_service.merkle import prefix_roots

    tree = leaves(70)
    assert prefix_roots(tree) == [root(tree[:k]) for k in range(1, 71)]
    assert prefix_roots(rfc_leaves(8))[-1].hex() == RFC_ROOTS[7]
