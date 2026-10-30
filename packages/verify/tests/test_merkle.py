"""The independent Merkle checker, against published known answers.

This is the validation the checker owes: the published RFC 6962 known-answer
vectors, plus full inclusion/consistency sweeps for all (m, n) pairs in the KAT
range, plus the refusals that keep a malformed or absent proof from reading as
a good one.

**Where the reference tree comes from.** `merkle.py` deliberately cannot build a
tree, so the sweeps need a generator, and it lives here. It is a direct
transcription of RFC 6962 §2.1's *recursive* definitions (MTH, PATH,
PROOF/SUBPROOF) while the module under test is a transcription of RFC 9162
§2.1.3.2/§2.1.4.2's *iterative* verification algorithms. Two formulations of one
specification, checked against each other -- and both pinned to the published
root hashes below, which come from outside this repository. Without that third
anchor the sweeps would only prove that the generator and the checker share a
misunderstanding, which is exactly the failure that splitting the log's builder
from its checker exists to prevent, rebuilt inside a test file.
"""

from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

from crucible_verify import merkle
from crucible_verify.merkle import (
    HASH_SIZE,
    MerkleCheck,
    Outcome,
    empty_tree_root,
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
VERIFY_SOURCE = REPO_ROOT / "packages" / "verify" / "src" / "crucible_verify"


# ============================================================================
# The RFC 6962 known answers, and a reference generator checked against them
# ============================================================================

#: The eight test entries from the RFC 6962 reference test data, as hex.
KAT_ENTRY_HEX = (
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
)
KAT_ENTRIES = tuple(bytes.fromhex(h) for h in KAT_ENTRY_HEX)

#: The published Merkle Tree Hash of the first n of those entries, n = 0..8.
#: These are **external** known answers, not values this repository computed:
#: they are the yardstick that keeps the generator below and the checker above
#: from agreeing with each other about something neither got right.
KAT_ROOT_HEX = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
)

#: A wider set for the sweeps that run past the KAT range. Distinct bytes per
#: entry, so no two nodes in any tree collide and a "reordered path still
#: verifies" result would mean a real defect rather than a coincidence.
WIDE_ENTRIES = tuple(f"crucible-sweep-entry-{i:03d}".encode() for i in range(17))


def ref_leaf(entry: bytes) -> bytes:
    """RFC 6962 §2.1: MTH({d}) = HASH(0x00 || d), transcribed here independently."""
    return hashlib.sha256(b"\x00" + entry).digest()


def ref_node(left: bytes, right: bytes) -> bytes:
    """RFC 6962 §2.1: HASH(0x01 || left || right), transcribed here independently."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def split(n: int) -> int:
    """The largest power of two strictly smaller than n (RFC 6962 §2.1, "let k")."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def ref_mth(entries: tuple[bytes, ...]) -> bytes:
    """MTH(D[n]), recursively, exactly as RFC 6962 §2.1 defines it."""
    if not entries:
        return hashlib.sha256(b"").digest()
    if len(entries) == 1:
        return ref_leaf(entries[0])
    k = split(len(entries))
    return ref_node(ref_mth(entries[:k]), ref_mth(entries[k:]))


def ref_path(m: int, entries: tuple[bytes, ...]) -> list[bytes]:
    """PATH(m, D[n]), recursively, as RFC 6962 §2.1.3.1 defines it."""
    if len(entries) == 1:
        return []
    k = split(len(entries))
    if m < k:
        return [*ref_path(m, entries[:k]), ref_mth(entries[k:])]
    return [*ref_path(m - k, entries[k:]), ref_mth(entries[:k])]


def ref_subproof(m: int, entries: tuple[bytes, ...], complete: bool) -> list[bytes]:
    """SUBPROOF(m, D[n], b), as RFC 6962 §2.1.4.1 defines it.

    `complete` is the RFC's boolean `b`: whether the old tree is a complete
    subtree of the current one, and therefore whether its root is a hash the
    verifier already holds and the log may omit.
    """
    if m == len(entries):
        return [] if complete else [ref_mth(entries)]
    k = split(len(entries))
    if m <= k:
        return [*ref_subproof(m, entries[:k], complete), ref_mth(entries[k:])]
    return [*ref_subproof(m - k, entries[k:], False), ref_mth(entries[:k])]


def ref_proof(m: int, entries: tuple[bytes, ...]) -> list[bytes]:
    """PROOF(m, D[n]) = SUBPROOF(m, D[n], true)."""
    return ref_subproof(m, entries, True)


def test_the_module_hashes_leaves_and_nodes_the_way_the_published_vectors_do():
    """The two primitives, pinned straight to external known answers.

    Neither of these goes through the reference generator, so a prefix that was
    transcribed wrong in *both* places still fails here. `MTH({""})` and
    `MTH({"", "00"})` are the first two published roots, and they are reachable
    with one call to each primitive.
    """
    assert leaf_hash(KAT_ENTRIES[0]).hex() == KAT_ROOT_HEX[1]
    assert node_hash(leaf_hash(KAT_ENTRIES[0]), leaf_hash(KAT_ENTRIES[1])).hex() == KAT_ROOT_HEX[2]
    assert empty_tree_root().hex() == KAT_ROOT_HEX[0]
    assert merkle.LEAF_PREFIX == b"\x00"
    assert merkle.NODE_PREFIX == b"\x01"


def test_the_reference_generator_reproduces_the_published_roots():
    """A known answer for the instrument the sweeps depend on, before any sweep runs.

    The generator is what turns 72 sweep rows into evidence. Unvalidated, it
    would turn them into 72 restatements of its own opinion, and a checker that
    agreed with a wrong generator would look identical to one that was right.
    """
    for n, expected in enumerate(KAT_ROOT_HEX):
        assert ref_mth(KAT_ENTRIES[:n]).hex() == expected, f"MTH of the first {n} entries"


def test_the_reference_generator_and_the_module_agree_on_hashing():
    """Two transcriptions of one definition, compared on every KAT subtree."""
    for n in range(1, len(KAT_ENTRIES) + 1):
        assert ref_leaf(KAT_ENTRIES[n - 1]) == leaf_hash(KAT_ENTRIES[n - 1])
    assert ref_node(ref_leaf(b"a"), ref_leaf(b"b")) == node_hash(leaf_hash(b"a"), leaf_hash(b"b"))


# ============================================================================
# Full inclusion sweep -- every (index, n) in the KAT range
# ============================================================================


def inclusion_case(index: int, n: int, entries: tuple[bytes, ...] = KAT_ENTRIES) -> dict:
    """A valid inclusion argument set for leaf `index` of the first `n` entries."""
    tree = entries[:n]
    return {
        "leaf": ref_leaf(tree[index]),
        "leaf_index": index,
        "tree_size": n,
        "path": ref_path(index, tree),
        "root": ref_mth(tree),
    }


KAT_INCLUSION = [(index, n) for n in range(1, len(KAT_ENTRIES) + 1) for index in range(n)]


@pytest.mark.parametrize(("index", "n"), KAT_INCLUSION, ids=lambda v: str(v))
def test_every_inclusion_proof_in_the_kat_range_verifies(index: int, n: int):
    """The full inclusion sweep, one node id per (index, n).

    Parametrized rather than looped so a single broken shape -- the ragged right
    edge of an odd tree is where these algorithms actually go wrong -- names
    itself instead of hiding inside one failing assertion.
    """
    result = verify_inclusion(**inclusion_case(index, n))

    assert result.outcome is Outcome.PASS, result.render()
    assert result.computed_root == ref_mth(KAT_ENTRIES[:n])


def test_the_inclusion_sweep_continues_past_the_kat_range():
    """Sizes 1..17, so the KAT range's shapes are not the only ones ever seen.

    Eight entries never exercises a tree whose right subtree is itself ragged
    at two levels; 11, 13 and 17 do.
    """
    for n in range(1, len(WIDE_ENTRIES) + 1):
        for index in range(n):
            result = verify_inclusion(**inclusion_case(index, n, WIDE_ENTRIES))
            assert result.outcome is Outcome.PASS, f"leaf {index} of {n}: {result.render()}"


# ============================================================================
# Full consistency sweep -- every (m, n) in the KAT range
# ============================================================================


def consistency_case(m: int, n: int, entries: tuple[bytes, ...] = KAT_ENTRIES) -> dict:
    """A valid consistency argument set between the first m and the first n entries."""
    return {
        "first_size": m,
        "first_root": ref_mth(entries[:m]),
        "second_size": n,
        "second_root": ref_mth(entries[:n]),
        "path": [] if m == n else ref_proof(m, entries[:n]),
    }


KAT_CONSISTENCY = [(m, n) for n in range(1, len(KAT_ENTRIES) + 1) for m in range(1, n + 1)]


@pytest.mark.parametrize(("m", "n"), KAT_CONSISTENCY, ids=lambda v: str(v))
def test_every_consistency_proof_in_the_kat_range_verifies(m: int, n: int):
    """The full consistency sweep, including every m == n."""
    result = verify_consistency(**consistency_case(m, n))

    assert result.outcome is Outcome.PASS, result.render()
    assert result.computed_root == ref_mth(KAT_ENTRIES[:n])


def test_the_consistency_sweep_continues_past_the_kat_range():
    """Sizes 1..17 in both positions, for the same reason as the inclusion sweep."""
    for n in range(1, len(WIDE_ENTRIES) + 1):
        for m in range(1, n + 1):
            result = verify_consistency(**consistency_case(m, n, WIDE_ENTRIES))
            assert result.outcome is Outcome.PASS, f"{m} -> {n}: {result.render()}"


# ============================================================================
# Negative cases -- swept, not sampled
# ============================================================================


def corrupt(node: bytes) -> bytes:
    """One flipped bit. A checker that tolerates this tolerates a forged proof."""
    return bytes([node[0] ^ 0x01]) + node[1:]


@pytest.mark.parametrize(("index", "n"), KAT_INCLUSION, ids=lambda v: str(v))
def test_a_corrupted_node_anywhere_in_an_inclusion_path_fails(index: int, n: int):
    """Every position in every path, because "somewhere in the middle" is where
    a real forgery would sit -- the ends are the positions a spot check reaches."""
    case = inclusion_case(index, n)
    for position in range(len(case["path"])):
        broken = dict(case)
        broken["path"] = list(case["path"])
        broken["path"][position] = corrupt(broken["path"][position])
        result = verify_inclusion(**broken)
        assert result.outcome is Outcome.FAIL, f"node {position} of {index}/{n}: {result.render()}"


@pytest.mark.parametrize(("index", "n"), KAT_INCLUSION, ids=lambda v: str(v))
def test_a_dropped_node_anywhere_in_an_inclusion_path_fails(index: int, n: int):
    """A short path must never be accepted as a proof of a smaller tree.

    This is the failure mode with teeth: truncating a path is the cheapest
    forgery attempt there is, and an implementation that walks only as far as
    the nodes it was given will happily confirm a leaf's inclusion in a subtree
    the checkpoint does not commit to.
    """
    case = inclusion_case(index, n)
    for position in range(len(case["path"])):
        broken = dict(case)
        broken["path"] = [node for i, node in enumerate(case["path"]) if i != position]
        result = verify_inclusion(**broken)
        assert result.outcome is Outcome.FAIL, (
            f"dropped {position} of {index}/{n}: {result.render()}"
        )


@pytest.mark.parametrize(("index", "n"), KAT_INCLUSION, ids=lambda v: str(v))
def test_a_duplicated_node_anywhere_in_an_inclusion_path_fails(index: int, n: int):
    """A path one node too long is a proof for a tree twice as tall.

    RFC 9162's `sn == 0` arm is what refuses it. Without that arm the extra hash
    is folded in and the walk keeps going, which turns a valid proof into a
    valid-looking proof of something else.
    """
    case = inclusion_case(index, n)
    for position in range(len(case["path"])):
        broken = dict(case)
        broken["path"] = list(case["path"])
        broken["path"].insert(position, broken["path"][position])
        result = verify_inclusion(**broken)
        assert result.outcome is Outcome.FAIL, (
            f"duplicated {position} of {index}/{n}: {result.render()}"
        )


@pytest.mark.parametrize(("index", "n"), KAT_INCLUSION, ids=lambda v: str(v))
def test_a_path_longer_than_the_tree_admits_is_refused_as_that(index: int, n: int):
    """The over-long arm has to be pinned by its *classification*, not its verdict.

    Found by mutation testing: removing the `sn == 0` arm turned no test red,
    because folding an extra hash in and then missing the root also produces
    `fail`, and every test here asserted only the verdict. The arm survived a
    mutation that removed it.

    It is worth having on its own terms. "The proof carries nodes the signed root
    does not commit to" and "the proof reproduces the wrong root" are different
    findings about the log -- the first is a malformed receipt, the second is a
    receipt for another tree -- and a verification report that renders both as
    "fail: root mismatch" has thrown away the difference. The guard also bounds
    the work: without it a proof with a million nodes is a million hashes before
    the answer comes back.
    """
    case = inclusion_case(index, n)
    longer = [*case["path"], ref_leaf(b"an extra node the tree has no room for")]

    result = verify_inclusion(**{**case, "path": longer})

    assert result.outcome is Outcome.FAIL, result.render()
    assert "admits only" in result.reason, result.render()


@pytest.mark.parametrize(("m", "n"), KAT_CONSISTENCY, ids=lambda v: str(v))
def test_a_consistency_proof_longer_than_the_trees_admit_is_refused_as_that(m: int, n: int):
    """The same arm on the other function: the sweep across siblings closes, or it does not.

    Both loops carry the RFC's `sn == 0` guard and only one of them had a test
    that could tell it was there.
    """
    case = consistency_case(m, n)
    longer = [*case["path"], ref_leaf(b"an extra node neither tree has room for")]

    result = verify_consistency(**{**case, "path": longer})

    assert result.outcome is Outcome.FAIL, result.render()
    expected = "defines that proof as empty" if m == n else "more than trees of"
    assert expected in result.reason, result.render()


@pytest.mark.parametrize(("index", "n"), KAT_INCLUSION, ids=lambda v: str(v))
def test_a_reordered_inclusion_path_fails(index: int, n: int):
    """Order carries the shape of the tree; a path is not a set of hashes.

    Every adjacent transposition, plus the full reversal for paths long enough
    for the two to differ. An implementation that hashed a sorted or unordered
    path would pass every positive sweep above and fail here.
    """
    case = inclusion_case(index, n)
    path = list(case["path"])
    variants = [[*path[:i], path[i + 1], path[i], *path[i + 2 :]] for i in range(len(path) - 1)]
    if len(path) > 2:
        variants.append(list(reversed(path)))
    for variant in variants:
        result = verify_inclusion(**{**case, "path": variant})
        assert result.outcome is Outcome.FAIL, f"reordered {index}/{n}: {result.render()}"


@pytest.mark.parametrize("n", range(1, len(KAT_ENTRIES) + 1))
def test_a_leaf_index_outside_the_tree_fails(n: int):
    """A receipt may not claim a leaf the signed checkpoint does not cover.

    `n` itself and `n + 1` are the off-by-one a size check is written wrong for;
    a negative index is the one a size check written as `index > size` misses
    entirely.
    """
    case = inclusion_case(0, n)
    for outside in (n, n + 1, 2 * n + 3):
        result = verify_inclusion(**{**case, "leaf_index": outside})
        assert result.outcome is Outcome.FAIL, f"index {outside} of {n}: {result.render()}"
        assert "outside a tree" in result.reason

    negative = verify_inclusion(**{**case, "leaf_index": -1})
    assert negative.outcome is Outcome.FAIL, negative.render()
    assert "negative" in negative.reason


def test_an_empty_tree_includes_nothing():
    """`tree_size: 0` is not a special case to skip; it is a claim to refuse."""
    result = verify_inclusion(
        leaf=ref_leaf(b""), leaf_index=0, tree_size=0, path=[], root=empty_tree_root()
    )

    assert result.outcome is Outcome.FAIL, result.render()
    assert "outside a tree of 0 leaves" in result.reason


@pytest.mark.parametrize(("index", "n"), KAT_INCLUSION, ids=lambda v: str(v))
def test_a_valid_path_for_the_wrong_leaf_fails(index: int, n: int):
    """The path is real, the root is real, and the leaf belongs to another entry.

    This is the shape of a log substituting one entry for another after the
    fact: everything else about the receipt still checks out.
    """
    case = inclusion_case(index, n)
    other = (index + 1) % len(KAT_ENTRIES)
    result = verify_inclusion(**{**case, "leaf": ref_leaf(KAT_ENTRIES[other])})

    assert result.outcome is Outcome.FAIL, result.render()
    assert "does not reproduce the checkpoint root" in result.reason


@pytest.mark.parametrize(("index", "n"), KAT_INCLUSION, ids=lambda v: str(v))
def test_a_valid_path_against_a_corrupted_root_fails(index: int, n: int):
    """One bit of the checkpoint root, which is the value the signature covers."""
    case = inclusion_case(index, n)
    result = verify_inclusion(**{**case, "root": corrupt(case["root"])})

    assert result.outcome is Outcome.FAIL, result.render()
    assert result.computed_root == case["root"]


CLAIMED_SIZES = range(1, 2 * len(KAT_ENTRIES) + 4)


@pytest.mark.parametrize(("index", "n"), KAT_INCLUSION, ids=lambda v: str(v))
def test_no_claimed_tree_size_makes_a_forged_root_verify(index: int, n: int):
    """The property `tree_size` actually has to carry, swept over every size.

    `tree_size` steers the walk, so a forger who controls it gets to try every
    tree shape the algorithm can be talked into. None of them may reproduce a
    root the log did not sign -- if one did, the size field would be a way to
    launder a forged checkpoint through a genuine path.
    """
    case = inclusion_case(index, n)
    forged = corrupt(case["root"])
    for claimed in CLAIMED_SIZES:
        result = verify_inclusion(**{**case, "tree_size": claimed, "root": forged})
        assert result.outcome is Outcome.FAIL, f"{index}/{n} as {claimed}: {result.render()}"


def test_a_tree_size_that_changes_the_proof_shape_fails():
    """The sizes that do move the walk are refused, in both directions."""
    case = inclusion_case(0, 8)
    for claimed in (1, 2, 3, 4, 9, 10, 11):
        result = verify_inclusion(**{**case, "tree_size": claimed})
        assert result.outcome is Outcome.FAIL, f"leaf 0 of 8 as {claimed}: {result.render()}"


def test_a_tree_size_that_does_not_change_the_proof_shape_is_invisible_to_the_path():
    """A **stated limit** of path checking, pinned so nobody rediscovers it as a bug.

    RFC 6962 gives leaf 0 the same three-node path in every tree of 5 to 8
    leaves -- the left subtree is complete and identical in all four -- so the
    walk is bit-for-bit the same and the same root comes out. Presenting a
    size-8 receipt as size 5 therefore verifies, and *correctly*: the path
    genuinely proves that leaf is under that root, which is the only question
    this function is asked.

    What binds `tree_size` to `root` is the service's signature over the
    checkpoint carrying both, not the path. The consequence for the
    receipt-level check above this module: take `tree_size` and `root` from the
    *verified* checkpoint, never from fields a caller can vary independently,
    and check that signature. A receipt checker that reported "included in a
    tree of N" on the strength of the path alone would be over-claiming, and
    this test exists so that the over-claim is a known boundary rather than a
    surprise.
    """
    case = inclusion_case(0, 8)
    for claimed in (5, 6, 7):
        result = verify_inclusion(**{**case, "tree_size": claimed})
        assert result.outcome is Outcome.PASS, f"leaf 0 of 8 as {claimed}: {result.render()}"
        assert result.computed_root == case["root"]


@pytest.mark.parametrize(("m", "n"), KAT_CONSISTENCY, ids=lambda v: str(v))
def test_a_tampered_consistency_path_fails(m: int, n: int):
    """Corrupt, drop, duplicate and reorder, at every position, for every (m, n).

    A consistency proof is the only thing standing between an append-only claim
    and a log that quietly rewrote an old entry, so every way of breaking one
    gets the same sweep the inclusion paths get.
    """
    case = consistency_case(m, n)
    path = list(case["path"])
    variants: list[list[bytes]] = []
    for position in range(len(path)):
        variants.append([*path[:position], corrupt(path[position]), *path[position + 1 :]])
        variants.append([node for i, node in enumerate(path) if i != position])
        variants.append([*path[:position], path[position], *path[position:]])
    variants.extend([*path[:i], path[i + 1], path[i], *path[i + 2 :]] for i in range(len(path) - 1))
    if not path:
        # m == n: the RFC's proof is empty, so the only tampering available is
        # to add a node. A checker that ignored the length would accept it.
        variants.append([ref_mth(KAT_ENTRIES[:n])])

    for variant in variants:
        result = verify_consistency(**{**case, "path": variant})
        assert result.outcome is Outcome.FAIL, f"{m} -> {n} as {len(variant)}: {result.render()}"


@pytest.mark.parametrize(("m", "n"), KAT_CONSISTENCY, ids=lambda v: str(v))
def test_a_consistency_proof_against_a_corrupted_root_fails(m: int, n: int):
    """Either root, corrupted, must break the proof -- and say which one broke."""
    case = consistency_case(m, n)

    old = verify_consistency(**{**case, "first_root": corrupt(case["first_root"])})
    assert old.outcome is Outcome.FAIL, old.render()

    new = verify_consistency(**{**case, "second_root": corrupt(case["second_root"])})
    assert new.outcome is Outcome.FAIL, new.render()


def test_a_log_whose_tree_shrank_fails():
    """Sizes in the wrong order is a rollback, not a malformed request.

    An append-only log's size never decreases. Reporting this as an argument
    error would leave the one interesting reading -- somebody is showing two
    checkpoints that cannot both be honest -- classified as operator clumsiness.
    """
    case = consistency_case(3, 7)
    result = verify_consistency(
        first_size=7,
        first_root=case["second_root"],
        second_size=3,
        second_root=case["first_root"],
        path=case["path"],
    )

    assert result.outcome is Outcome.FAIL, result.render()
    assert "shrank" in result.reason


def test_two_different_roots_at_one_tree_size_is_a_split_view():
    """The equivocation case, which is the reason consistency queries exist."""
    result = verify_consistency(
        first_size=4,
        first_root=ref_mth(KAT_ENTRIES[:4]),
        second_size=4,
        second_root=ref_mth(WIDE_ENTRIES[:4]),
        path=[],
    )

    assert result.outcome is Outcome.FAIL, result.render()
    assert "split view" in result.reason


def test_an_empty_consistency_proof_between_different_sizes_fails():
    """RFC 9162 §2.1.4.2 step 1. A log that proves nothing has proven nothing."""
    result = verify_consistency(**{**consistency_case(3, 7), "path": []})

    assert result.outcome is Outcome.FAIL, result.render()
    assert "empty" in result.reason


def test_consistency_against_the_empty_tree_is_not_applicable():
    """The fourth value, and the only place in this module that reaches it.

    Every tree extends the empty tree, so there is nothing to disprove -- but
    there is also no proof object, and RFC 6962 defines none. Returning `pass`
    would hand the verification report a confirmation nobody earned; the honest
    word for a question that does not arise is `not_applicable`.
    """
    result = verify_consistency(
        first_size=0,
        first_root=empty_tree_root(),
        second_size=5,
        second_root=ref_mth(KAT_ENTRIES[:5]),
        path=[],
    )

    assert result.outcome is Outcome.NOT_APPLICABLE, result.render()
    assert result.computed_root is None


def test_the_proof_list_the_caller_passed_is_not_mutated():
    """The power-of-two prepend must not edit the caller's receipt.

    RFC 9162 step 2 says "prepend first_hash to the consistency_path array". Do
    that in place and the caller is left holding a path with an extra node --
    which then gets archived, or re-checked, or written back to disk as what the
    log sent. It is not.
    """
    case = consistency_case(4, 7)
    handed_over = list(case["path"])

    verify_consistency(**{**case, "path": handed_over})

    assert handed_over == case["path"]


# ============================================================================
# The four-valued contract (SPEC.md §4 Honesty rule)
# ============================================================================


def test_there_are_exactly_four_outcomes():
    """Pinned as a set, because a fifth value is a new state every renderer,
    report and corpus row would have to learn about at once."""
    assert {o.value for o in Outcome} == {"pass", "fail", "not_applicable", "could_not_check"}


def test_a_result_refuses_to_be_a_boolean():
    """`if check:` is the mistake the four-valued rule exists to prevent.

    A truthy result object makes `could_not_check` indistinguishable from `pass`
    at every call site, silently, which is the commonest way a verifier lies,
    reintroduced through the type system.
    """
    unchecked = verify_inclusion(leaf=None, leaf_index=None, tree_size=None, path=None, root=None)
    assert unchecked.outcome is Outcome.COULD_NOT_CHECK

    with pytest.raises(TypeError, match="four-valued"):
        bool(unchecked)
    with pytest.raises(TypeError, match="four-valued"):
        if unchecked:
            pass

    passing = verify_inclusion(**inclusion_case(2, 5))
    with pytest.raises(TypeError, match="four-valued"):
        bool(passing)


def test_every_outcome_renders_visibly_differently():
    """"Checked and found nothing" and "could not check" must be visually and
    structurally different in every rendering.

    Structurally they are different enum members. Visually they are different
    words of different lengths in different cases, and this asserts all four
    marks are distinct rather than trusting the table to stay that way.
    """
    marks = [MerkleCheck(outcome, "reason").mark for outcome in Outcome]

    assert len(set(marks)) == len(Outcome)
    assert MerkleCheck(Outcome.PASS, "r").mark != MerkleCheck(Outcome.COULD_NOT_CHECK, "r").mark
    for outcome in Outcome:
        rendered = MerkleCheck(outcome, "the reason it came out this way").render()
        assert rendered.startswith(MerkleCheck(outcome, "").mark)
        assert "the reason it came out this way" in rendered


@pytest.mark.parametrize("absent", ["leaf", "leaf_index", "tree_size", "path", "root"])
def test_any_absent_inclusion_input_is_a_could_not_check_that_names_itself(absent: str):
    """Each of the five, one at a time, with the reason naming the missing field.

    A `could_not_check` whose reason does not say what was missing is a shrug,
    and a shrug in a verification report reads as "nothing to see here".
    """
    result = verify_inclusion(**{**inclusion_case(3, 6), absent: None})

    assert result.outcome is Outcome.COULD_NOT_CHECK, result.render()
    assert result.computed_root is None
    wire_name = "inclusion_path" if absent == "path" else absent
    assert wire_name in result.reason


@pytest.mark.parametrize(
    "absent", ["first_size", "first_root", "second_size", "second_root", "path"]
)
def test_any_absent_consistency_input_is_a_could_not_check_that_names_itself(absent: str):
    result = verify_consistency(**{**consistency_case(3, 7), absent: None})

    assert result.outcome is Outcome.COULD_NOT_CHECK, result.render()
    wire_name = "consistency_path" if absent == "path" else absent
    assert wire_name in result.reason


def test_an_absent_path_and_an_empty_path_are_different_questions():
    """The headline distinction, on the tree where it is invisible: size 1.

    `[]` is the complete proof for the only leaf of a one-leaf tree, so it gets
    checked -- and it can still *fail*, against a root that is not the leaf.
    `None` is a receipt with a field missing, and nothing about it was checked.
    Collapse them and every one-leaf receipt with a dropped field verifies.
    """
    leaf = ref_leaf(b"the only entry")

    checked = verify_inclusion(leaf=leaf, leaf_index=0, tree_size=1, path=[], root=leaf)
    assert checked.outcome is Outcome.PASS, checked.render()

    checked_and_wrong = verify_inclusion(
        leaf=leaf, leaf_index=0, tree_size=1, path=[], root=corrupt(leaf)
    )
    assert checked_and_wrong.outcome is Outcome.FAIL, checked_and_wrong.render()

    not_checked = verify_inclusion(leaf=leaf, leaf_index=0, tree_size=1, path=None, root=leaf)
    assert not_checked.outcome is Outcome.COULD_NOT_CHECK, not_checked.render()

    assert checked.outcome is not not_checked.outcome
    assert checked.mark != not_checked.mark


# ============================================================================
# Malformed inputs are findings about the log, not gaps in the check
# ============================================================================


@pytest.mark.parametrize("truthy", [True, False])
def test_a_boolean_leaf_index_or_tree_size_is_refused(truthy: bool):
    """A boolean size, on the surface where it would matter most.

    `True == 1` in Python, so a JSON `true` in `leaf_index` would silently mean
    leaf 1 -- and against a real leaf-1 proof it would *verify*, attesting a
    receipt field nobody set. v1's ledger shipped this exact construct and v1's
    log guarded the same two fields in its request schema. This is the third
    sibling, checked because a finding closes only when the sweep across its
    siblings is done.
    """
    case = inclusion_case(1, 2)

    index = verify_inclusion(**{**case, "leaf_index": truthy})
    assert index.outcome is Outcome.FAIL, index.render()
    assert "not an integer" in index.reason

    size = verify_inclusion(**{**case, "tree_size": truthy})
    assert size.outcome is Outcome.FAIL, size.render()
    assert "not an integer" in size.reason


def test_a_boolean_tree_size_is_refused_by_the_consistency_check_too():
    """The same sweep on the other function, for the same reason."""
    case = consistency_case(1, 2)

    assert verify_consistency(**{**case, "first_size": True}).outcome is Outcome.FAIL
    assert verify_consistency(**{**case, "second_size": True}).outcome is Outcome.FAIL


@pytest.mark.parametrize("field", ["leaf", "root"])
@pytest.mark.parametrize(
    "value", [b"", b"\x00" * 31, b"\x00" * 33, "sha256:" + "00" * 32, 0, [b"\x00" * 32]]
)
def test_a_digest_of_the_wrong_shape_is_refused(field: str, value: object):
    """Wrong width and wrong type both. A 31-byte "digest" is not a near miss:
    it is a value some decoder produced by truncating, and hashing it would give
    an answer that looks like a real one."""
    result = verify_inclusion(**{**inclusion_case(2, 4), field: value})

    assert result.outcome is Outcome.FAIL, result.render()
    assert "well-formed inclusion proof" in result.reason


def test_a_path_that_is_not_a_list_of_digests_is_refused():
    """`bytes` is a `Sequence`, so a path handed over as raw bytes would iterate
    as integers and produce a confident-looking stream of nonsense."""
    case = inclusion_case(2, 4)

    as_bytes = verify_inclusion(**{**case, "path": b"\x00" * 64})
    assert as_bytes.outcome is Outcome.FAIL, as_bytes.render()
    assert "not a sequence of digests" in as_bytes.reason

    as_string = verify_inclusion(**{**case, "path": "sha256:" + "00" * 32})
    assert as_string.outcome is Outcome.FAIL, as_string.render()

    as_number = verify_inclusion(**{**case, "path": 3})
    assert as_number.outcome is Outcome.FAIL, as_number.render()

    with_a_bad_node = verify_inclusion(**{**case, "path": [b"\x00" * 31, *case["path"][1:]]})
    assert with_a_bad_node.outcome is Outcome.FAIL, with_a_bad_node.render()
    assert "node 0" in with_a_bad_node.reason


def test_a_malformed_consistency_proof_is_refused_the_same_way():
    case = consistency_case(3, 7)

    assert verify_consistency(**{**case, "first_root": b"short"}).outcome is Outcome.FAIL
    assert verify_consistency(**{**case, "second_size": -2}).outcome is Outcome.FAIL
    assert verify_consistency(**{**case, "path": "not a path"}).outcome is Outcome.FAIL

    bad_node = verify_consistency(**{**case, "path": [*case["path"][:-1], b"\x00" * 20]})
    assert bad_node.outcome is Outcome.FAIL, bad_node.render()
    assert "well-formed consistency proof" in bad_node.reason


@pytest.mark.parametrize("field", ["first_root", "second_root"])
@pytest.mark.parametrize("value", [b"", b"\x00" * 31, b"\x00" * 33, "sha256:" + "00" * 32, 0])
def test_the_same_size_arm_refuses_roots_that_are_not_digests(field: str, value: object):
    """The equal-size arm is the only one that compares the two roots *directly*.

    Every other arm walks a path and would refuse a malformed root by accident,
    when the rebuilt value fails to match it -- which is why the pre-existing
    coverage held with the shape check removed. Here there is no walk: RFC 6962
    defines the proof between two checkpoints of one size as empty, so the check
    is `first_root != second_root` and nothing else. Take the width check away
    and two values of the same wrong shape compare equal and return `pass`.

    That defect was found in v1 exactly: two zero-length "roots" compared equal
    and returned `pass` -- and `b""` is in the parameters because it is the
    shape a decoder produces from an absent field, not a shape an attacker has
    to construct.
    """
    case = {
        "first_size": 2,
        "first_root": b"\x11" * HASH_SIZE,
        "second_size": 2,
        "second_root": b"\x11" * HASH_SIZE,
        "path": [],
    }
    result = verify_consistency(**{**case, field: value})

    assert result.outcome is Outcome.FAIL, result.render()
    assert "well-formed consistency proof" in result.reason


def test_the_consistency_shape_check_is_the_reason_two_empty_roots_are_refused():
    """Both roots wrong at once, which is the only way the equal-size arm passes.

    Parameterizing one field at a time cannot see this: with the shape check
    removed, a single malformed root still fails the `first_root != second_root`
    comparison against a well-formed one. It is the *pair* that compares equal
    and walks out as evidence that the log did not rewrite history. The rendered
    root in that pass reads `sha256:` with no hex after it, which is what a
    report would have carried.

    `verify_inclusion`'s side of the symmetry is asserted here too, so the claim
    the two functions make the same demand is one assertion rather than an
    inference across two test functions -- the defect was a *divergence* between
    them, and a divergence is only visible when both are in view.
    """
    empty_pair = verify_consistency(
        first_size=2, first_root=b"", second_size=2, second_root=b"", path=[]
    )
    assert empty_pair.outcome is Outcome.FAIL, empty_pair.render()
    assert "0 bytes wide" in empty_pair.reason

    short_pair = verify_consistency(
        first_size=2, first_root=b"\x77" * 20, second_size=2, second_root=b"\x77" * 20, path=[]
    )
    assert short_pair.outcome is Outcome.FAIL, short_pair.render()
    assert "20 bytes wide" in short_pair.reason

    inclusion = verify_inclusion(leaf=b"", leaf_index=0, tree_size=1, path=[], root=b"")
    assert inclusion.outcome is Outcome.FAIL, inclusion.render()
    assert "0 bytes wide" in inclusion.reason


def test_the_hashing_primitives_refuse_what_they_cannot_hash():
    """These raise rather than returning a four-valued result: they are
    primitives over bytes with no notion of a receipt, and a `TypeError` at the
    call site is louder than a `fail` two layers up. `verify_inclusion` never
    reaches them with bad input because it validates first."""
    with pytest.raises(TypeError, match="entry bytes must be bytes"):
        leaf_hash("not bytes")
    with pytest.raises(ValueError, match="left is 3 bytes wide"):
        node_hash(b"abc", b"\x00" * HASH_SIZE)
    with pytest.raises(ValueError, match="right is str"):
        node_hash(b"\x00" * HASH_SIZE, "not bytes")


def test_a_bytearray_digest_is_accepted_and_compares_equal():
    """Decoders return `bytearray` often enough that refusing it would be a
    false positive, and comparing it wrongly would be a false negative."""
    case = inclusion_case(3, 6)
    result = verify_inclusion(
        leaf=bytearray(case["leaf"]),
        leaf_index=case["leaf_index"],
        tree_size=case["tree_size"],
        path=[bytearray(node) for node in case["path"]],
        root=bytearray(case["root"]),
    )

    assert result.outcome is Outcome.PASS, result.render()
    assert isinstance(result.computed_root, bytes)


# ============================================================================
# Independence, enforced
# ============================================================================


def verify_modules() -> list[Path]:
    """Every shipped module of `crucible_verify`, found on disk.

    Discovered rather than listed: the import rule is about the package, and a
    module added tomorrow is exactly the one an inclusion list would miss.
    """
    return sorted(VERIFY_SOURCE.rglob("*.py"))


def test_no_module_in_crucible_verify_imports_the_service():
    """The builder/checker split, asserted over the whole package rather than over this file.

    A checker built from the log's own code inherits the log's bugs and then
    agrees with them forever -- the corpus cannot tell the difference, because
    both sides were built from the same misunderstanding. Parsed rather than
    grepped so that a mention in a docstring (there are several, deliberately)
    is not confused with an import.
    """
    assert verify_modules(), f"no modules found under {VERIFY_SOURCE}"

    offenders: list[str] = []
    for path in verify_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                if name == "crucible_service" or name.startswith("crucible_service."):
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno} imports {name}")

    assert offenders == [], f"`verify` imports nothing from `crucible_service`. {offenders}"


def test_importing_the_checker_does_not_load_the_service():
    """The joint, not the node.

    The AST test reads source; this one runs the import in a fresh interpreter
    and asks what actually got loaded. A transitive import through `core` or
    `chain`, or a lazy import inside a function, would satisfy the source scan
    and fail here -- and "no service module is in memory" is the property that
    actually makes the check independent at runtime.
    """
    probe = (
        "import sys, crucible_verify.merkle;"
        "print([m for m in sys.modules if m.startswith('crucible_service')])"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]", result.stdout


def test_the_checker_does_not_ship_a_tree_builder():
    """Checking only: `verify` has one leaf and one path, never the log's data.

    Discovered from the module's own AST rather than from a list of forbidden
    names. The property that distinguishes a checker from a builder is that no
    function here recurses -- every RFC 6962 tree construction is defined
    recursively, and the two verification algorithms are flat loops. A recursive
    function appearing in this module is the first sign it has started rebuilding
    what the log already built.
    """
    tree = ast.parse((VERIFY_SOURCE / "merkle.py").read_text(encoding="utf-8"))
    functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    assert functions, "the module defines no functions; the parse found nothing"

    recursive = [
        function.name
        for function in functions
        if any(
            isinstance(call.func, ast.Name) and call.func.id == function.name
            for call in ast.walk(function)
            if isinstance(call, ast.Call)
        )
    ]
    assert recursive == [], f"these recurse, which is how a tree gets built: {recursive}"
