"""An independent RFC 6962 path checker (SPEC.md §7 Verification).

`crucible-verify` checks receipts against checkpoints. This module is the part
that walks a Merkle path, and it carries one demand that no amount of care
about the arithmetic can substitute for:

    Its Merkle path checking is a **fresh implementation** validated against the
    published RFC 6962 known-answer vectors, plus full inclusion/consistency
    sweeps for all (m, n) pairs in the KAT range.

So this file imports nothing from `crucible_service` and was written from the
specifications rather than from the log's source: RFC 6962 §2.1 for the tree
hash and the two proof definitions, RFC 9162 §2.1.3.2 and §2.1.4.2 for the two
verification algorithms. Merkle code is kept out of `crucible_core` for exactly
this reason: anything in core is shared by the log and its checker.

**Why independence is the whole point.** A checker derived from the log's own
code inherits whatever the log got wrong and then agrees with it forever. The
log's proofs verify, its bugs verify with them, and no corpus can tell the
difference because both sides were built from the same misunderstanding. The
independence that matters for a transparency log is between the party making
the proof and the party checking it.

**Checking only.** There is no tree builder here and there must not be one. A
verifier that can compute what the root *should* be from a list of entries is
holding the log's data and doing the log's job. What a third party actually
holds -- years later, offline, with the service gone -- is one leaf, one path,
and a signed root, and that is exactly the input these functions take.

## The result model (SPEC.md §4 Honesty rule)

Every check returns exactly one of `pass`, `fail`, `not_applicable(reason)` or
`could_not_check(reason)`. Booleans are forbidden: `MerkleCheck.__bool__` raises
rather than answering, because `if verify_inclusion(...)` reads as a question
about the proof and would silently answer "yes" to a check that never ran. The
commonest way a verifier lies is a could-not-check reported as health, and a
truthy result object is the cheapest possible way to add another.

Which value applies is decided by one rule, stated here so callers can rely on
it rather than infer it:

- an **absent** input (`None`) is `could_not_check`. Nothing was walked, and the
  caller must not read the answer as health;
- an input that is **present but not proof-shaped** -- a hash of the wrong
  width, a boolean where an integer belongs, a leaf index outside the tree -- is
  `fail`. A receipt of the wrong shape is a broken receipt, and the party that
  produced it is the log. "The log handed me garbage" is a finding, not a gap;
- a proof-shaped input whose arithmetic does not work out is `fail`;
- a question outside the check's domain -- consistency against the empty tree --
  is `not_applicable`.

**An absent path is not an empty one, and this is not pedantry.** `[]` is the
correct and complete inclusion proof for the only leaf of a one-leaf tree, which
is the shape of the first receipt any log issues. A receipt that omits
`inclusion_path` entirely is a receipt nobody can check. Collapse the two and
every single-leaf receipt with a missing field verifies as `pass` -- silence
rendered as a pass, which the honesty rule forbids. `None` and `[]` are
therefore different arguments with different outcomes, and the tests pin both.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

#: RFC 6962 §2.1 domain separation. A leaf and an interior node hash the same
#: bytes under different prefixes so that no leaf can ever be presented as an
#: interior node -- without this, a log could hand out a "leaf" that is really a
#: subtree root and prove inclusion of entries it never committed to.
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

#: SHA-256 output width. Every leaf, node and root in a path is exactly this
#: wide, and a value that is not is not a hash.
HASH_SIZE = 32


class Outcome(StrEnum):
    """The four results, and there are exactly four (SPEC.md §4 Honesty rule)."""

    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    COULD_NOT_CHECK = "could_not_check"


#: How each outcome renders. "Checked and found nothing" and "could not check"
#: must be *visually* as well as structurally different in every rendering, so
#: these four differ in word, width and case -- no reader skimming a column of
#: them can mistake `UNCHECKED` for `pass`, and no renderer downstream has to
#: invent its own vocabulary and get it wrong.
_MARKS = {
    Outcome.PASS: "pass",
    Outcome.FAIL: "FAIL",
    Outcome.NOT_APPLICABLE: "n/a",
    Outcome.COULD_NOT_CHECK: "UNCHECKED",
}


@dataclass(frozen=True)
class MerkleCheck:
    """One four-valued answer about one path, with the reason it came out that way."""

    outcome: Outcome
    #: Always populated, including on `pass`. A report that prints reasons only
    #: for failures teaches its readers that a bare line means success, and then
    #: an empty reason on a `could_not_check` reads as success too.
    reason: str
    #: The root this walk actually computed, when it got far enough to compute
    #: one; `None` when the input was refused before any hashing happened.
    #: Exposed because a checker that reports `pass` without having computed
    #: anything is indistinguishable, from the outside, from one that did the
    #: work -- and a known answer can only be planted against output that can be
    #: seen (SPEC.md §8 rule 4). For a consistency check this is the recomputed
    #: *second* root.
    computed_root: bytes | None = None

    def __bool__(self) -> bool:
        """Refuse to be a boolean.

        `if check:` is the natural thing to write and it is exactly the mistake
        the four-valued rule exists to prevent: a `could_not_check` is truthy,
        so the branch that handles "the proof is good" runs for a proof nobody
        looked at. Raising here turns that into a loud failure at the first test
        that makes it, rather than a quiet wrong answer in a verification report.
        """
        raise TypeError(
            f"a {type(self).__name__} is four-valued and must not be used as a boolean: "
            f"compare `.outcome` against one of {', '.join(o.value for o in Outcome)}. "
            f"This one is {self.outcome.value}: {self.reason}"
        )

    @property
    def mark(self) -> str:
        """The short, visually distinct label for this outcome."""
        return _MARKS[self.outcome]

    def render(self) -> str:
        """One human-readable line, outcome first so a column of them scans."""
        return f"{self.mark:<9}  {self.reason}"


def _passed(reason: str, computed_root: bytes) -> MerkleCheck:
    return MerkleCheck(Outcome.PASS, reason, computed_root)


def _failed(reason: str, computed_root: bytes | None = None) -> MerkleCheck:
    return MerkleCheck(Outcome.FAIL, reason, computed_root)


def _not_applicable(reason: str) -> MerkleCheck:
    return MerkleCheck(Outcome.NOT_APPLICABLE, reason)


def _could_not_check(reason: str) -> MerkleCheck:
    return MerkleCheck(Outcome.COULD_NOT_CHECK, reason)


# --- hashing (RFC 6962 §2.1) ------------------------------------------------


def leaf_hash(entry_bytes: bytes) -> bytes:
    """MTH({d}) = HASH(0x00 || d) -- the leaf hash of one log entry's bytes.

    `entry_bytes` is the log entry's canonical (RFC 8785) serialization, which
    the receipt has to carry for this to be recomputed at all. A receipt
    without its entry can only be checked by taking the log's word for what it
    committed to.
    """
    if not isinstance(entry_bytes, bytes | bytearray):
        raise TypeError(f"entry bytes must be bytes, not {type(entry_bytes).__name__}")
    return hashlib.sha256(LEAF_PREFIX + entry_bytes).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """MTH(D[n]) = HASH(0x01 || left || right) -- one interior node.

    Both halves must be full-width digests. A short operand would let two
    different (left, right) pairs concatenate to the same string, which is the
    length-extension ambiguity the fixed width exists to remove.
    """
    for name, value in (("left", left), ("right", right)):
        problem = _hash_problem(name, value)
        if problem is not None:
            raise ValueError(f"cannot hash an interior node: {problem}")
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def empty_tree_root() -> bytes:
    """MTH({}) = HASH() -- the root of a tree with no entries.

    Exported so a caller comparing a `tree_size: 0` checkpoint has the answer
    from the RFC rather than from a guess. Nothing is ever included in it.
    """
    return hashlib.sha256(b"").digest()


# --- shape checks -----------------------------------------------------------


def _hash_problem(name: str, value: object) -> str | None:
    """The reason `value` is not a SHA-256 digest, or `None` if it is one."""
    if not isinstance(value, bytes | bytearray):
        return f"{name} is {type(value).__name__}, not {HASH_SIZE} raw bytes"
    if len(value) != HASH_SIZE:
        return f"{name} is {len(value)} bytes wide; a SHA-256 digest is {HASH_SIZE}"
    return None


def _size_problem(name: str, value: object) -> str | None:
    """The reason `value` is not a tree size or index, or `None` if it is one.

    The `bool` arm is not defensive padding. In Python `True == 1`, so a JSON
    `true` arriving in `leaf_index` would silently mean leaf 1 and a receipt
    would verify against a field nobody set -- v1's ledger shipped exactly this
    construct, and v1's log guarded `tree_size` and `leaf_index` in its request
    schema for the same reason. Checked before `isinstance(value, int)` because
    `bool` *is* a subclass of `int`.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return f"{name} is {value!r} ({type(value).__name__}), not an integer"
    if value < 0:
        return f"{name} is negative ({value})"
    return None


def _path_problems(name: str, path: object) -> list[str]:
    """Every reason `path` is not a list of digests. Empty list means it is one.

    `str`/`bytes` are excluded explicitly because both are `Sequence`s: a
    `bytes` path would iterate as integers and produce a stream of confusing
    per-node complaints instead of one accurate one.
    """
    if isinstance(path, str | bytes | bytearray) or not isinstance(path, Sequence):
        return [f"{name} is {type(path).__name__}, not a sequence of digests"]
    problems = [_hash_problem(f"{name} node {i}", node) for i, node in enumerate(path)]
    return [problem for problem in problems if problem is not None]


def _hex(value: bytes) -> str:
    return "sha256:" + value.hex()


# --- inclusion (RFC 9162 §2.1.3.2) ------------------------------------------


def verify_inclusion(
    *,
    leaf: bytes | None,
    leaf_index: int | None,
    tree_size: int | None,
    path: Sequence[bytes] | None,
    root: bytes | None,
) -> MerkleCheck:
    """Check that `leaf` sits at `leaf_index` of a `tree_size`-leaf tree with `root`.

    `leaf` is the leaf *hash* (see `leaf_hash`), not the entry bytes: the caller
    recomputes it from the receipt's `entry` so that the log's claim about what
    it committed to is never taken on trust.

    Keyword-only on purpose. Four of the five arguments are same-shaped values
    and two of them are digests; a transposed `leaf` and `root` on a one-leaf
    tree compares the same two values either way and *passes*, which is the
    worst kind of wrong answer -- a positional mistake that verifies. Naming
    them removes the whole class.

    `None` for any argument means the caller could not supply it, and yields
    `could_not_check`. An empty `path` is not `None`: it is the complete and
    correct proof for the single leaf of a one-leaf tree, and it gets checked.
    """
    absent = [
        name
        for name, value in (
            ("leaf", leaf),
            ("leaf_index", leaf_index),
            ("tree_size", tree_size),
            ("inclusion_path", path),
            ("root", root),
        )
        if value is None
    ]
    if absent:
        return _could_not_check(
            f"no inclusion check was performed: {', '.join(absent)} was not supplied. "
            f"This is not a proof that failed and not a proof that held -- an absent "
            f"inclusion_path in particular is not an empty one, which is the valid "
            f"proof for leaf 0 of a one-leaf tree"
        )

    problems = [
        problem
        for problem in (
            _hash_problem("the leaf hash", leaf),
            _hash_problem("the checkpoint root", root),
            _size_problem("leaf_index", leaf_index),
            _size_problem("tree_size", tree_size),
        )
        if problem is not None
    ]
    problems.extend(_path_problems("the inclusion path", path))
    if problems:
        return _failed(
            f"this is not a well-formed inclusion proof, so the log did not produce "
            f"one: {'; '.join(problems)}"
        )

    # Everything below runs on values the block above proved are proof-shaped.
    # No `assert` restates that: an assertion that can never fire is a branch
    # that can never be exercised, and an unexercised arm should be visible
    # rather than decorative.
    #
    # Normalized once, so the walk compares bytes with bytes and a `bytearray`
    # arriving from a decoder cannot make an equality read differently here than
    # it reads anywhere else.
    root = bytes(root)
    nodes = [bytes(node) for node in path]

    # RFC 9162 step 1. Also catches `tree_size == 0`: an empty tree includes
    # nothing, and a receipt claiming otherwise is claiming a leaf the signed
    # checkpoint does not cover.
    if leaf_index >= tree_size:
        return _failed(
            f"leaf {leaf_index} is outside a tree of {tree_size} leaves, so the "
            f"checkpoint the log signed does not cover the entry this receipt is for"
        )

    # RFC 9162 steps 2-4. `fn` walks the leaf's index and `sn` the last index of
    # the tree; comparing them is how the algorithm tells an interior node from
    # the ragged right edge, which is why no tree has to be built to check a path.
    fn, sn = leaf_index, tree_size - 1
    computed = bytes(leaf)
    for depth, node in enumerate(nodes):
        if sn == 0:
            return _failed(
                f"the inclusion path has {len(nodes)} nodes but a tree of {tree_size} "
                f"leaves admits only {depth}; the extra nodes are hashes the signed "
                f"root does not commit to",
                computed,
            )
        if fn & 1 or fn == sn:
            computed = node_hash(node, computed)
            if not fn & 1:
                while fn != 0 and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            computed = node_hash(computed, node)
        fn >>= 1
        sn >>= 1

    # RFC 9162 step 5, split so the two ways it fails read differently: a path
    # that ran out is a truncated proof, and a path that reached the top with
    # the wrong value is a proof for some other tree.
    if sn != 0:
        return _failed(
            f"the inclusion path has {len(nodes)} nodes, fewer than a tree of "
            f"{tree_size} leaves requires; the walk never reached the root",
            computed,
        )
    if computed != root:
        return _failed(
            f"the inclusion path does not reproduce the checkpoint root: it computes "
            f"{_hex(computed)} where the signed checkpoint says {_hex(root)}. "
            f"The log has not shown this entry is in the tree it published",
            computed,
        )
    return _passed(
        f"leaf {leaf_index} of {tree_size} is committed to by {_hex(computed)}, "
        f"which is the root the checkpoint signs",
        computed,
    )


# --- consistency (RFC 9162 §2.1.4.2) ----------------------------------------


def verify_consistency(
    *,
    first_size: int | None,
    first_root: bytes | None,
    second_size: int | None,
    second_root: bytes | None,
    path: Sequence[bytes] | None,
) -> MerkleCheck:
    """Check that the `first_size`-leaf tree is a prefix of the `second_size`-leaf one.

    This is the check that catches a log rewriting its own history: inclusion
    proofs only ever say "this entry is in *a* tree", and a log that quietly
    replaced an old entry can still issue perfectly valid inclusion proofs
    against its new root. Consistency is what makes append-only enforceable by
    someone who kept an old checkpoint.

    Keyword-only for the same reason as `verify_inclusion`, with the same worst
    case: swapping the two (size, root) pairs turns "did the log append?" into
    "did the log truncate?", and the arithmetic answers the question it was
    given without complaint.
    """
    absent = [
        name
        for name, value in (
            ("first_size", first_size),
            ("first_root", first_root),
            ("second_size", second_size),
            ("second_root", second_root),
            ("consistency_path", path),
        )
        if value is None
    ]
    if absent:
        return _could_not_check(
            f"no consistency check was performed: {', '.join(absent)} was not supplied. "
            f"Nothing here says the log appended and nothing says it did not -- an "
            f"unchecked consistency proof is precisely the state a log rewriting its "
            f"history would like a verifier to be in"
        )

    problems = [
        problem
        for problem in (
            _hash_problem("the first root", first_root),
            _hash_problem("the second root", second_root),
            _size_problem("first_size", first_size),
            _size_problem("second_size", second_size),
        )
        if problem is not None
    ]
    problems.extend(_path_problems("the consistency path", path))
    if problems:
        return _failed(
            f"this is not a well-formed consistency proof, so the log did not produce "
            f"one: {'; '.join(problems)}"
        )

    # Normalized once, so the walk below compares bytes with bytes and a
    # `bytearray` node arriving from a decoder cannot make an equality read
    # differently here than it would in the verification report.
    first_root = bytes(first_root)
    second_root = bytes(second_root)
    nodes = [bytes(node) for node in path]

    if first_size == 0:
        # RFC 6962 defines PROOF(m, D[n]) for 0 < m, so there is no proof object
        # to check here. Every tree extends the empty tree, so the answer is not
        # `pass` either: nothing was verified, and the honest word for a question
        # that does not arise is `not_applicable` rather than a free `pass` the
        # verification report would count as evidence.
        return _not_applicable(
            f"a tree of {second_size} leaves trivially extends the empty tree; RFC 6962 "
            f"defines no consistency proof for first_size 0, so none was checked"
        )
    if first_size > second_size:
        return _failed(
            f"the log's tree shrank from {first_size} leaves to {second_size}: an "
            f"append-only log's size never decreases, so this pair of checkpoints "
            f"cannot both be honest"
        )
    if first_size == second_size:
        # RFC 6962: SUBPROOF(m, D[m], true) = {}. The proof is empty because
        # there is nothing to prove -- but the roots still have to match, and
        # when they do not the log has signed two different trees at one size,
        # which is equivocation rather than a bad proof.
        if len(nodes) != 0:
            return _failed(
                f"the consistency proof between two checkpoints of {first_size} leaves "
                f"carries {len(nodes)} nodes; RFC 6962 defines that proof as empty, and "
                f"a proof of a shape this checker cannot interpret is not one it accepts"
            )
        if first_root != second_root:
            return _failed(
                f"the log published two different roots for tree size {first_size}: "
                f"{_hex(first_root)} and {_hex(second_root)}. That is a split view -- "
                f"two readers of this log were shown different histories"
            )
        return _passed(
            f"both checkpoints are tree size {first_size} with root "
            f"{_hex(second_root)}; RFC 6962 defines the proof between them as empty "
            f"and it was empty",
            second_root,
        )

    # RFC 9162 step 1. Every PROOF(m, D[n]) with 0 < m < n appends at least one
    # subtree hash, so an empty path here is a log declining to prove anything.
    if len(nodes) == 0:
        return _failed(
            f"the consistency proof between {first_size} and {second_size} leaves is "
            f"empty; RFC 6962 never produces an empty proof between different sizes, "
            f"so nothing links the old root to the new one"
        )

    # RFC 9162 step 2. When `first_size` is a power of two the old tree is a
    # complete subtree, so the log omits its root from the proof -- the verifier
    # already holds it. Prepended to a copy: mutating the caller's list would
    # leave a "proof" in the caller's hands that is no longer what the log sent.
    supplied = len(nodes)
    if first_size & (first_size - 1) == 0:
        nodes = [first_root, *nodes]

    # RFC 9162 steps 3-4.
    fn, sn = first_size - 1, second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    # RFC 9162 steps 5-6. `fr` rebuilds the old root and `sr` the new one from
    # the same nodes; that they are built together is the point, because it is
    # the shared prefix that makes them one proof rather than two.
    first_computed = second_computed = nodes[0]
    for depth, node in enumerate(nodes[1:], start=1):
        if sn == 0:
            return _failed(
                f"the consistency proof has {supplied} nodes, more than trees of "
                f"{first_size} and {second_size} leaves admit; the walk reached the "
                f"root with {len(nodes) - depth} nodes left over",
                second_computed,
            )
        if fn & 1 or fn == sn:
            first_computed = node_hash(node, first_computed)
            second_computed = node_hash(node, second_computed)
            if not fn & 1:
                while fn != 0 and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            second_computed = node_hash(second_computed, node)
        fn >>= 1
        sn >>= 1

    # RFC 9162 step 7, split three ways because the three failures mean
    # different things to whoever reads the verification report.
    if sn != 0:
        return _failed(
            f"the consistency proof has {supplied} nodes, fewer than trees of "
            f"{first_size} and {second_size} leaves require; the walk never reached "
            f"the root",
            second_computed,
        )
    if first_computed != first_root:
        return _failed(
            f"the proof does not rebuild the old root: it computes "
            f"{_hex(first_computed)} where the checkpoint at {first_size} leaves says "
            f"{_hex(first_root)}. The old tree is not a prefix of the new one, which "
            f"is what a log rewriting history looks like from outside",
            second_computed,
        )
    if second_computed != second_root:
        return _failed(
            f"the proof does not rebuild the new root: it computes "
            f"{_hex(second_computed)} where the checkpoint at {second_size} leaves says "
            f"{_hex(second_root)}",
            second_computed,
        )
    return _passed(
        f"the tree of {first_size} leaves rooted at {_hex(first_root)} is a prefix of "
        f"the tree of {second_size} leaves rooted at {_hex(second_computed)}",
        second_computed,
    )
