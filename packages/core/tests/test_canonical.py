"""JCS canonicalization and content addressing.

Build-plan §4.1: "JCS canonicalization goldens so the same logical event hashes
identically across platforms and Python versions."
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from crucible_core.canonical import (
    CanonicalizationError,
    DuplicateJSONKeyError,
    canonicalize,
    digest,
    digest_hex,
    is_digest,
    loads_one_reading,
    sha256_bytes,
    sha256_file,
)

# --- goldens ---------------------------------------------------------------
# Frozen bytes. A change here is a protocol break, not a refactor: every chain
# ever produced would rehash differently. If one of these fails, the fix is
# never to update the expectation.

GOLDENS = [
    ({}, b"{}"),
    ({"a": 1, "b": 2}, b'{"a":1,"b":2}'),
    ({"b": 2, "a": 1}, b'{"a":1,"b":2}'),  # key order is normalized
    ({"n": None, "t": True, "f": False}, b'{"f":false,"n":null,"t":true}'),
    ({"x": [3, 2, 1]}, b'{"x":[3,2,1]}'),  # array order is significant
    ({"s": "é"}, b'{"s":"\xc3\xa9"}'),  # UTF-8, not \u escapes
    ({"s": 'a"b\\c'}, b'{"s":"a\\"b\\\\c"}'),
    ({"s": "\n\t"}, b'{"s":"\\n\\t"}'),
    ({"z": 1, "å": 2, "a": 3}, b'{"a":3,"z":1,"\xc3\xa5":2}'),  # UTF-16 code-unit order
    ({"i": 1.0}, b'{"i":1}'),  # integral floats serialize as integers
    ({"neg": -0.0}, b'{"neg":0}'),
]

#: Digest of the empty JSON object, the cheapest cross-implementation check.
EMPTY_OBJECT_DIGEST = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"


@pytest.mark.parametrize(("value", "expected"), GOLDENS, ids=range(len(GOLDENS)))
def test_canonicalization_goldens(value, expected):
    assert canonicalize(value) == expected


def test_empty_object_digest_is_frozen():
    assert digest({}) == EMPTY_OBJECT_DIGEST
    assert sha256_bytes(b"{}") == EMPTY_OBJECT_DIGEST


def test_nested_key_order_normalizes_at_every_depth():
    a = {"outer": {"z": 1, "a": {"y": 2, "b": 3}}}
    b = {"outer": {"a": {"b": 3, "y": 2}, "z": 1}}
    assert canonicalize(a) == canonicalize(b)
    assert digest(a) == digest(b)


def test_array_order_is_significant():
    assert digest({"x": [1, 2]}) != digest({"x": [2, 1]})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_floats_are_rejected(value):
    with pytest.raises(CanonicalizationError):
        canonicalize({"x": value})


@pytest.mark.parametrize("value", [{1: "int key"}, {(1, 2): "tuple key"}])
def test_non_string_keys_are_rejected(value):
    with pytest.raises(CanonicalizationError):
        canonicalize(value)


@pytest.mark.parametrize("value", [{"x": b"bytes"}, {"x": {1, 2}}, {"x": object()}])
def test_unrepresentable_values_are_rejected(value):
    with pytest.raises(CanonicalizationError):
        canonicalize(value)


# --- digest strings --------------------------------------------------------


def test_digest_shape():
    d = digest({"a": 1})
    assert d.startswith("sha256:")
    assert len(d) == len("sha256:") + 64
    assert is_digest(d)
    assert len(digest_hex(d)) == 32


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "sha256:",
        "deadbeef",
        "sha256:" + "0" * 63,
        "sha256:" + "0" * 65,
        "sha256:" + "A" * 64,  # uppercase hex is not canonical
        "sha512:" + "0" * 64,
        "genesis",  # not a digest, whatever a chain calls its first link
        None,
        123,
    ],
)
def test_is_digest_rejects_malformed(bad):
    assert not is_digest(bad)
    if isinstance(bad, str):
        with pytest.raises(ValueError):
            digest_hex(bad)


def test_sha256_file_matches_sha256_bytes(tmp_path):
    payload = b"x" * (3 * 1024 * 1024 + 7)  # spans several read chunks
    path = tmp_path / "blob.bin"
    path.write_bytes(payload)
    assert sha256_file(path) == sha256_bytes(payload)


def test_sha256_file_on_empty_file(tmp_path):
    path = tmp_path / "empty"
    path.write_bytes(b"")
    assert sha256_file(path) == sha256_bytes(b"")


# --- properties ------------------------------------------------------------

_json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1)
    | st.text(max_size=40),
    lambda children: (
        st.lists(children, max_size=5) | st.dictionaries(st.text(max_size=12), children, max_size=5)
    ),
    max_leaves=25,
)


@settings(max_examples=250, deadline=None)
@given(_json_values)
def test_canonicalization_is_idempotent_through_json(value):
    """Canonical bytes reparse to a value with the same canonical bytes."""
    once = canonicalize(value)
    assert canonicalize(json.loads(once)) == once


@settings(max_examples=250, deadline=None)
@given(_json_values)
def test_digest_agrees_with_canonicalize(value):
    assert digest(value) == sha256_bytes(canonicalize(value))


@settings(max_examples=200, deadline=None)
@given(_json_values, _json_values)
def test_equal_values_hash_equal_and_unequal_values_hash_unequal(a, b):
    if canonicalize(a) == canonicalize(b):
        assert digest(a) == digest(b)
    else:
        assert digest(a) != digest(b)


# --- one encoding, one reading -------------------------------------------------


def test_json_loads_keeps_the_last_duplicate_which_is_why_this_reader_exists():
    """The premise, asserted rather than assumed.

    Everything below is only worth doing because the standard library resolves a
    repeated key silently and in a direction an attacker chooses. Pinning it here
    means that if a future Python ever changed that, the reason this reader
    exists would be re-read rather than the reader quietly kept.
    """
    assert json.loads('{"leaf_index": 4096, "leaf_index": 9}') == {"leaf_index": 9}


@pytest.mark.parametrize(
    "text",
    [
        '{"leaf_index": 4096, "leaf_index": 9}',
        '{"a": 1, "b": {"kind": "statement", "kind": "receipt"}}',
        '[{"ok": true}, {"chain_id": "audited", "chain_id": "other"}]',
        '{"a": {"b": [{"x": 1, "x": 2}]}}',
    ],
)
def test_a_repeated_key_is_refused_wherever_it_sits(text: str):
    """Top level, nested in an object, inside an array, three deep.

    A reader that only checked the outermost object would be a reader an attacker
    indents past.
    """
    with pytest.raises(DuplicateJSONKeyError, match="more than once"):
        loads_one_reading(text)


def test_the_reader_is_otherwise_json_loads():
    """The other half: a guard that refused everything would pass the test
    above and be useless. Ordinary documents decode identically, including the
    two shapes a naive duplicate check gets wrong -- repeated keys in *sibling*
    objects, and a key repeated as a *value*."""
    for text in (
        '{"leaf_index": 9, "log_id": "L"}',
        '[{"x": 1}, {"x": 2}]',
        '{"a": {"x": 1}, "b": {"x": 2}}',
        '{"x": "x"}',
        "null",
        "[1, 2, 3]",
        '"a string"',
    ):
        assert loads_one_reading(text) == json.loads(text)

    assert isinstance(DuplicateJSONKeyError("x"), ValueError), (
        "every reader in this repository already writes `except ValueError` and turns the "
        "failure into a counted unreadable record; a new exception family would escape those "
        "arms as a traceback from a checker"
    )


def test_bytes_in_and_a_syntax_error_out_still_behave():
    assert loads_one_reading(b'{"a": 1}') == {"a": 1}
    with pytest.raises(json.JSONDecodeError):
        loads_one_reading("{not json")


# --- RFC 8785's safe integer domain (verification-002 §5, robustness) --------


@pytest.mark.parametrize(
    "value",
    [
        2**53,
        2**53 + 1,
        -(2**53) - 1,
        2**63,
        -(2**63) - 1,
        10**30,
    ],
)
def test_an_integer_outside_the_safe_domain_is_refused(value: int):
    """A robustness defect found in another canonicalizer, checked against this one.

    RFC 8785 serializes numbers as ES6 doubles, so an integer a double cannot
    hold exactly has no canonical form -- a conforming implementation refuses it
    rather than emitting something a second implementation would read as a
    different number. That canonicalizer accepted them; this one does
    not, and the boundary is pinned here because nothing else pins it: the
    hypothesis strategy above draws integers only up to `2**53 - 1`, so the edge
    was never exercised and a `rfc8785` version that relaxed the check would have
    landed green.

    It is not academic. A `leaf_index`, `tree_size` or `size` past the boundary
    would otherwise be hashed into a leaf whose digest no other implementation
    could reproduce, and the receipt would verify only against the code that
    wrote it.
    """
    with pytest.raises(CanonicalizationError, match="not JCS-serializable"):
        canonicalize(value)


@pytest.mark.parametrize("value", [2**53 - 1, -(2**53) + 1, 0, 1, -1])
def test_the_edge_of_the_safe_domain_is_still_inside_it(value: int):
    """The other half: the refusal must stop exactly where the RFC does.

    A canonicalizer that refused one integer too many would break every honest
    document carrying a large `size`, and a test that only checked refusals could
    not tell the two mistakes apart.
    """
    assert canonicalize(value) == str(value).encode("ascii")
