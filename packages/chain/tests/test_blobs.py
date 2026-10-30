"""Content-addressed blob store (ported from v1's crucible_ledger).

The layout is ``blobs/sha256/...``. The blob store is where a digest an event
commits to is redeemable (SPEC.md §4 Containment). If the store can hand back
bytes that do not hash to the name they were fetched under, every downstream
"verify" is checking a promise the store has already broken.
"""

from __future__ import annotations

import random
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from crucible_core.canonical import CanonicalizationError, canonicalize, digest, sha256_bytes
from crucible_chain.blobs import BlobError, BlobStore

#: Frozen: the digest of zero bytes. An empty artifact is a legitimate artifact
#: (an empty stdout, a zero-row export), and it has to be nameable like any other.
EMPTY_DIGEST = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.fixture
def store(tmp_path) -> BlobStore:
    """A store rooted at ``<home>/blobs``."""
    return BlobStore(tmp_path / "blobs")


def _stored_files(store: BlobStore) -> list[Path]:
    return sorted(p for p in store.root.rglob("*") if p.is_file())


# --- put_bytes -------------------------------------------------------------


def test_put_bytes_returns_the_content_digest(store):
    payload = b"hillslope curvature, 30 m DEM"
    assert store.put_bytes(payload) == sha256_bytes(payload)


def test_put_bytes_is_idempotent_and_stores_one_copy(store):
    """Re-ingesting the same file must not fork it into two on-disk objects.

    A workflow that reads the same dataset in twenty steps calls put_bytes
    twenty times; the name is the content, so the second write has nothing new
    to say and must not double the store's size or churn the mtime.
    """
    payload = b"identical bytes"
    first = store.put_bytes(payload)
    second = store.put_bytes(payload)
    assert first == second
    assert len(_stored_files(store)) == 1


def test_put_bytes_keeps_distinct_content_distinct(store):
    a = store.put_bytes(b"claim A")
    b = store.put_bytes(b"claim B")
    assert a != b
    assert len(_stored_files(store)) == 2
    assert store.get(a) == b"claim A"
    assert store.get(b) == b"claim B"


def test_empty_bytes_are_storable_and_retrievable(store):
    dgst = store.put_bytes(b"")
    assert dgst == EMPTY_DIGEST
    assert store.has(dgst)
    assert store.get(dgst) == b""
    assert store.size(dgst) == 0


# --- on-disk layout --------------------------------------------------------


def test_the_on_disk_path_is_sha256_two_hex_then_the_rest(store, tmp_path):
    """The layout is normative, not an implementation detail.

    An archive handed to a third party has to be navigable from the spec alone:
    given `sha256:ab<62 more>` in an event, the reader must know to open
    `blobs/sha256/ab/<62 more>` without asking us how we shard.
    """
    dgst = store.put_bytes(b"anchor me")
    hexd = dgst.removeprefix("sha256:")
    expected = tmp_path / "blobs" / "sha256" / hexd[:2] / hexd[2:]

    assert store.path_for(dgst) == expected
    assert expected.is_file()
    assert len(hexd[:2]) == 2
    assert len(hexd[2:]) == 62
    assert _stored_files(store) == [expected]


def test_path_for_answers_for_content_that_was_never_stored(store):
    """`path_for` is a naming function, so callers can test `has` without try/except."""
    dgst = sha256_bytes(b"never stored")
    assert not store.path_for(dgst).exists()
    assert not store.has(dgst)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "genesis",
        "deadbeef",
        "sha256:",
        "sha256:" + "0" * 63,
        "sha256:" + "0" * 65,
        "sha256:" + "A" * 64,  # uppercase hex is a different string for the same content
        "sha512:" + "0" * 64,
        "../../etc/passwd",
        None,
        123,
    ],
)
def test_path_for_rejects_anything_that_is_not_a_digest(store, bad):
    """Unvalidated names would let a caller-supplied string escape the store root."""
    with pytest.raises(BlobError, match="not a digest"):
        store.path_for(bad)


# --- put_file --------------------------------------------------------------


def test_put_file_stores_a_multi_megabyte_file_identically_to_put_bytes(store, tmp_path):
    """Datasets are the reason this store exists, and they do not fit in a chunk.

    The digest is computed by streaming and the bytes are copied by streaming;
    a mismatch between those two paths would let a large dataset be filed under
    the hash of its first megabyte.
    """
    payload = random.Random(1234).randbytes(3 * 1024 * 1024 + 7)  # spans several read chunks
    src = tmp_path / "dem.tif"
    src.write_bytes(payload)

    from_file = store.put_file(src)
    assert from_file == sha256_bytes(payload)
    assert store.size(from_file) == len(payload)
    assert store.get(from_file) == payload

    # The two entry points are interchangeable, so neither re-stores the other's work.
    assert store.put_bytes(payload) == from_file
    assert len(_stored_files(store)) == 1


def test_put_file_is_idempotent(store, tmp_path):
    src = tmp_path / "notebook.ipynb"
    src.write_bytes(b'{"cells": []}')
    assert store.put_file(src) == store.put_file(src)
    assert len(_stored_files(store)) == 1


def test_put_file_on_an_empty_file(store, tmp_path):
    src = tmp_path / "stdout.txt"
    src.write_bytes(b"")
    assert store.put_file(src) == EMPTY_DIGEST
    assert store.get(EMPTY_DIGEST) == b""


@pytest.mark.parametrize("kind", ["missing", "directory"])
def test_put_file_refuses_anything_that_is_not_a_file(store, tmp_path, kind):
    target = tmp_path / "subject"
    if kind == "directory":
        target.mkdir()
    with pytest.raises(BlobError, match="not a file"):
        store.put_file(target)


# --- put_json --------------------------------------------------------------


def test_put_json_canonicalizes_so_key_order_cannot_fork_a_blob(store):
    """Two processes serializing the same object must land on the same name.

    Python dict order follows insertion, so a hook that builds a body in a
    different order than the verifier would otherwise commit to a different
    hash for a logically identical object -- an integrity failure invented
    entirely by serialization.
    """
    first = store.put_json({"a": 1, "b": {"y": 2, "x": 3}})
    second = store.put_json({"b": {"x": 3, "y": 2}, "a": 1})

    assert first == second
    assert len(_stored_files(store)) == 1
    assert store.get(first) == canonicalize({"a": 1, "b": {"x": 3, "y": 2}})


def test_put_json_agrees_with_the_core_digest_function(store):
    value = {"tool": "Bash", "exit_code": 0, "files_written": []}
    assert store.put_json(value) == digest(value)


@pytest.mark.parametrize("value", [b"bytes", {1: "int key"}, {"x": float("nan")}, {"s": {1, 2}}])
def test_put_json_refuses_values_JCS_cannot_represent(store, value):
    """Better to fail the append than to store bytes no other implementation can reproduce."""
    with pytest.raises(CanonicalizationError):
        store.put_json(value)
    assert _stored_files(store) == []


# --- get: re-verification --------------------------------------------------


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param(lambda old: b"z" * len(old), id="substituted-same-length"),
        pytest.param(lambda old: old[:-1], id="truncated"),
        pytest.param(lambda old: old + b"\n", id="appended"),
        pytest.param(lambda old: b"", id="emptied"),
    ],
)
def test_get_detects_a_tampered_blob_instead_of_returning_it(store, tamper):
    """Silently returning corrupt bytes is strictly worse than raising.

    A caller that gets an exception knows its evidence is gone and can re-fetch
    or fail the verification. A caller that gets wrong bytes back under the
    right name gets a *confident* answer computed from something nobody ever
    signed -- and every check downstream still passes, because the chain only
    ever committed to the digest, and the digest is exactly what the store just
    lied about. The whole point of content addressing is that this class of
    failure is detectable for free; declining to detect it wastes the guarantee.
    """
    original = b"declared result: slope-area exponent 0.48"
    dgst = store.put_bytes(original)
    store.path_for(dgst).write_bytes(tamper(original))

    with pytest.raises(BlobError, match="corruption"):
        store.get(dgst)


def test_the_corruption_message_names_both_digests(store):
    """The operator needs to know which artifact rotted and what it now contains."""
    dgst = store.put_bytes(b"original")
    store.path_for(dgst).write_bytes(b"swapped")

    with pytest.raises(BlobError) as excinfo:
        store.get(dgst)
    message = str(excinfo.value)
    assert dgst in message
    assert sha256_bytes(b"swapped") in message


def test_open_streams_without_re_verifying(store):
    """Documented gap: streaming skips the hash check, so large readers must fsck.

    Pinned deliberately -- if this ever starts raising, callers that stream
    gigabyte datasets are silently paying a full re-hash per read, and if it
    ever stops being documented, callers will assume a guarantee they lack.
    """
    dgst = store.put_bytes(b"original")
    store.path_for(dgst).write_bytes(b"swapped")

    with store.open(dgst) as fh:
        assert fh.read() == b"swapped"


def test_open_returns_the_real_bytes_for_a_healthy_blob(store):
    payload = random.Random(7).randbytes(200_000)
    dgst = store.put_bytes(payload)
    with store.open(dgst) as fh:
        assert fh.read() == payload


@pytest.mark.parametrize("method", ["get", "open", "size"])
def test_reading_a_digest_that_was_never_stored_raises(store, method):
    """A missing artifact must never read as an empty one."""
    dgst = sha256_bytes(b"never stored")
    with pytest.raises(BlobError, match="no blob"):
        getattr(store, method)(dgst)


@pytest.mark.parametrize("method", ["get", "open", "size", "has"])
def test_reading_a_malformed_digest_raises_before_touching_the_disk(store, method):
    with pytest.raises(BlobError, match="not a digest"):
        getattr(store, method)("not-a-digest")


# --- iter_digests ----------------------------------------------------------


def test_iter_digests_yields_exactly_what_was_put(store):
    expected = {store.put_bytes(f"artifact {i}".encode()) for i in range(12)}
    assert set(store.iter_digests()) == expected
    assert len(list(store.iter_digests())) == len(expected)


def test_iter_digests_is_empty_before_anything_is_stored(store):
    assert list(store.iter_digests()) == []


def test_iter_digests_skips_temp_files_left_by_a_crashed_writer(store):
    """A half-written `.tmp-` file is not evidence and must not be named as such.

    Its filename is not hex, so yielding it would mint a bogus digest string
    that fsck then reports as corruption -- a crash during ingest would look
    like tampering forever after.
    """
    dgst = store.put_bytes(b"real artifact")
    droppings = store.path_for(dgst).parent / ".tmp-abcdef"
    droppings.write_bytes(b"half a dataset")

    assert list(store.iter_digests()) == [dgst]
    assert store.fsck() == []


def test_iter_digests_ignores_stray_files_at_the_shard_level(store):
    """Backup tools and editors leave litter beside the shard directories."""
    dgst = store.put_bytes(b"real artifact")
    (store.root / "sha256" / "README").write_text("do not edit by hand\n")

    assert list(store.iter_digests()) == [dgst]


# --- fsck ------------------------------------------------------------------


def test_fsck_reports_nothing_on_a_healthy_store(store):
    for i in range(8):
        store.put_bytes(f"artifact {i}".encode())
    assert store.fsck() == []


def test_fsck_names_the_corrupted_blob_and_only_that_one(store):
    """Bit rot has to be attributable: the operator re-fetches one artifact, not all of them."""
    digests = [store.put_bytes(f"artifact {i}".encode()) for i in range(5)]
    rotted = digests[2]
    store.path_for(rotted).write_bytes(b"cosmic ray")

    assert store.fsck() == [rotted]


def test_fsck_finds_every_corrupted_blob_not_just_the_first(store):
    digests = [store.put_bytes(f"artifact {i}".encode()) for i in range(5)]
    for bad in (digests[0], digests[4]):
        store.path_for(bad).write_bytes(b"garbage")

    assert sorted(store.fsck()) == sorted([digests[0], digests[4]])


# --- concurrency -----------------------------------------------------------

_THREADS = 16


def test_concurrent_put_bytes_of_the_same_content_converges_on_one_blob(store):
    """Hooks fire from parallel tool calls; two writers can race on the same artifact.

    Writes go through a temp file plus a rename, so the loser of the race
    replaces a file whose contents are already identical. What must never
    happen is a reader observing a partially written blob, or the store
    accumulating `.tmp-` files that iter_digests would then have to defend
    against.
    """
    payload = random.Random(99).randbytes(512 * 1024)
    barrier = threading.Barrier(_THREADS)

    def put() -> str:
        barrier.wait(timeout=30)
        return store.put_bytes(payload)

    with ThreadPoolExecutor(max_workers=_THREADS) as pool:
        results = [f.result() for f in [pool.submit(put) for _ in range(_THREADS)]]

    assert set(results) == {sha256_bytes(payload)}
    assert len(_stored_files(store)) == 1
    assert store.get(results[0]) == payload
    assert store.fsck() == []
    assert list(store.root.rglob(".tmp-*")) == []


def test_concurrent_put_bytes_of_distinct_content_stores_all_of_it(store):
    """Distinct artifacts sharing a shard directory race on the same mkdir."""
    payloads = [f"parallel artifact {i}".encode() for i in range(_THREADS)]
    barrier = threading.Barrier(_THREADS)

    def put(data: bytes) -> str:
        barrier.wait(timeout=30)
        return store.put_bytes(data)

    with ThreadPoolExecutor(max_workers=_THREADS) as pool:
        results = list(pool.map(put, payloads))

    assert results == [sha256_bytes(p) for p in payloads]
    assert set(store.iter_digests()) == set(results)
    assert [store.get(d) for d in results] == payloads
    assert store.fsck() == []
    assert list(store.root.rglob(".tmp-*")) == []
