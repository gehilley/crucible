"""COSE_Sign1 envelopes.

The critical properties, per build-plan §4.1 and amendment AM-2:

* signing is deterministic, so goldens are byte-stable;
* the envelope digest -- not the payload digest -- is the chain link;
* any byte flip anywhere flips verification.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pycose.algorithms import EdDSA
from pycose.headers import KID, Algorithm

from crucible_core import cose
from crucible_core.canonical import canonicalize, sha256_bytes
from crucible_core.cose import SignatureError, decode, envelope_digest, sign, verify
from crucible_core.keys import PrivateKey, compute_key_id


def key_from_seed(seed: bytes, role: str = "researcher") -> PrivateKey:
    """Build a PrivateKey from raw seed bytes, deriving its key_id."""
    stub = PrivateKey(role=role, key_id="", private_bytes=seed)
    return PrivateKey(role=role, key_id=compute_key_id(stub.public_bytes), private_bytes=seed)


def test_round_trip(researcher_key):
    payload = {"hello": "world", "seq": 0}
    raw = sign(payload, researcher_key)
    env = verify(raw, researcher_key.public())
    assert env.payload() == payload
    assert env.key_id == researcher_key.key_id
    assert env.payload_bytes == canonicalize(payload)


def test_signing_is_deterministic(researcher_key):
    """Ed25519 + canonical CBOR headers => byte-identical envelopes.

    Goldens depend on this. A pycose or cbor2 regression that broke it would
    otherwise show up as mysteriously unstable digests.
    """
    payload = {"b": [1, 2, 3], "a": "x"}
    first = sign(payload, researcher_key)
    second = sign(payload, researcher_key)
    assert first == second
    # ...and it is insensitive to the input dict's key order, because the
    # payload is canonicalized before it is signed.
    assert sign({"a": "x", "b": [1, 2, 3]}, researcher_key) == first


def test_envelope_digest_is_over_envelope_not_payload(researcher_key):
    payload = {"a": 1}
    raw = sign(payload, researcher_key)
    assert envelope_digest(raw) == sha256_bytes(raw)
    assert envelope_digest(raw) != sha256_bytes(canonicalize(payload))


def test_resigning_same_payload_under_a_different_key_changes_the_link(researcher_key):
    """AM-2: key substitution must be a chain discontinuity, not a silent swap."""
    other = PrivateKey.generate("researcher", label="impostor")
    payload = {"a": 1}
    assert envelope_digest(sign(payload, researcher_key)) != envelope_digest(sign(payload, other))


def test_verify_rejects_a_foreign_key(researcher_key):
    raw = sign({"a": 1}, researcher_key)
    other = PrivateKey.generate("researcher")
    with pytest.raises(SignatureError, match="does not match key"):
        verify(raw, other.public())


def test_verify_rejects_a_swapped_signature(researcher_key):
    """A valid signature from the right key over *different* bytes still fails."""
    a = sign({"a": 1}, researcher_key)
    b = sign({"a": 2}, researcher_key)
    # Splice b's signature onto a's body: same length, same key, wrong message.
    import cbor2

    tag_a = cbor2.loads(a)
    tag_b = cbor2.loads(b)
    tag_a.value[3] = tag_b.value[3]
    spliced = cbor2.dumps(tag_a)
    with pytest.raises(SignatureError):
        verify(spliced, researcher_key.public())


@pytest.mark.parametrize(
    "raw",
    [b"", b"not cbor at all", b"\x84\x00\x00\x00\x00"],
)
def test_decode_rejects_non_envelopes(raw):
    with pytest.raises(SignatureError):
        decode(raw)


def test_decode_rejects_non_bytes():
    with pytest.raises(SignatureError, match="must be bytes"):
        decode("a string")  # type: ignore[arg-type]


def test_decode_rejects_missing_kid(researcher_key):
    import cbor2
    from pycose.algorithms import EdDSA
    from pycose.headers import Algorithm
    from pycose.messages import Sign1Message

    from crucible_core.cose import _sign_key

    msg = Sign1Message(phdr={Algorithm: EdDSA}, payload=b"{}")
    msg.key = _sign_key(researcher_key)
    raw = msg.encode(tag=True)
    assert cbor2.loads(raw).tag == 18
    with pytest.raises(SignatureError, match="no kid"):
        decode(raw)


def test_byte_flip_anywhere_breaks_verification(researcher_key):
    """Build-plan §4.1: any byte flip anywhere flips verify.

    Exhaustive over every byte position, one flipped bit each. Positions inside
    the payload change the payload; positions inside the signature or headers
    break the signature or the parse. Nothing survives.
    """
    raw = sign({"type": "SessionStart", "seq": 0, "body": {"model": "opus"}}, researcher_key)
    pub = researcher_key.public()
    survivors = []
    for i in range(len(raw)):
        mutated = bytearray(raw)
        mutated[i] ^= 0x01
        candidate = bytes(mutated)
        if candidate == raw:  # pragma: no cover - defensive
            continue
        try:
            env = verify(candidate, pub)
        except Exception:
            continue
        survivors.append((i, env.payload_bytes))
    assert survivors == [], f"byte flips survived verification at {[s[0] for s in survivors]}"


@settings(max_examples=60, deadline=None)
@given(
    st.dictionaries(
        st.text(min_size=1, max_size=10), st.integers(min_value=-1000, max_value=1000), max_size=6
    )
)
def test_round_trip_property(payload):
    key = key_from_seed(bytes(range(32)))
    raw = sign(payload, key)
    assert verify(raw, key.public()).payload() == payload


def test_content_type_is_recorded(researcher_key):
    from pycose.headers import ContentType
    from pycose.messages import Sign1Message

    raw = sign({"a": 1}, researcher_key)
    msg = Sign1Message.decode(raw)
    assert msg.phdr[ContentType] == cose.CONTENT_TYPE


# --- allocation before authentication -----------------------------------------


def test_an_integer_kid_is_refused_and_never_reaches_an_allocation():
    """A robustness defect found in another decoder, checked against this parser.

    That decoder read the protected header's `kid` and turned it into
    bytes *before* any signature was checked, so a 9-byte CBOR integer could ask
    for ~100 GB from an unauthenticated document. This parser cannot: `pycose`
    refuses a non-bytestring `kid` while decoding the header, and `decode` wraps
    that in `SignatureError` -- which is the four-valued-friendly answer, because
    a caller's `except SignatureError` files it as a fact about the envelope
    instead of letting an `AttributeError` out of a checker.

    Pinned rather than assumed. The refusal is a property of a third-party
    decoder, and a dependency bump that relaxed it would otherwise be silent.
    """
    import cbor2

    protected = cbor2.dumps({1: -8, 4: 99_999_999_999, 3: "application/crucible+json"})
    envelope = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, b'{"a":1}', b"\x00" * 64]))
    assert len(envelope) < 200, "a 9-byte field is what asks for 100 GB; keep the input tiny"

    with pytest.raises(SignatureError, match="not a COSE_Sign1 envelope"):
        decode(envelope)


def test_a_declared_length_larger_than_the_input_is_refused_by_reading_not_by_reserving():
    """The same attack one layer down: a length header, not a `kid` value.

    An 8-byte CBOR length prefix declaring a 100 GB byte string, followed by four
    actual bytes. A decoder that reserved the declared size before reading would
    take the machine down on a document nobody has authenticated. `cbor2` streams
    and reports what it did not receive, so the answer is a refusal in
    microseconds.

    The declared size is enormous and the *input* is 90 bytes: nothing here
    allocates, which is the whole point of the test.
    """
    import cbor2

    huge = (100 * 1024**3).to_bytes(8, "big")
    protected_inner = b"\xa3" + b"\x01\x27" + b"\x04" + b"\x5b" + huge + b"AAAA"
    raw = (
        b"\xd2\x84"
        + cbor2.dumps(protected_inner)
        + b"\xa0"
        + cbor2.dumps(b"{}")
        + cbor2.dumps(b"\x00" * 64)
    )
    assert len(raw) < 200

    with pytest.raises(SignatureError, match="premature end of stream"):
        decode(raw)


def test_a_non_bytestring_kid_that_got_past_the_dependency_is_still_a_signature_error(
    monkeypatch,
):
    """R4: the guard the repository was relying on is not the repository's.

    The two tests above prove `pycose` and `cbor2` refuse the allocation attack
    today. Neither proves anything about *this* code, and the refutation pass
    showed what happens when the inherited guard goes: relaxing only `pycose`'s
    non-bytestring `kid` refusal made `decode` raise

        AttributeError("'int' object has no attribute 'decode'")

    out of `kid.decode("ascii")` -- an uncaught exception escaping a checker,
    past every `except SignatureError` a caller writes, which is the
    instrument-exception rule's own scenario. `not_applicable(refused by the
    dependency)` was the right verdict about the *class* and no verdict at all
    about the failure mode.

    The dependency bump is simulated rather than waited for: `Sign1Message.decode`
    is replaced with one that hands back an integer `kid`, which is exactly the
    state of the world after the regression and cannot be produced any other way
    while the dependency is correct.
    """

    class RelaxedMessage:
        phdr: ClassVar[dict] = {KID: 99_999_999_999, Algorithm: EdDSA}
        payload = b'{"a":1}'

    monkeypatch.setattr(cose.Sign1Message, "decode", staticmethod(lambda raw: RelaxedMessage()))

    with pytest.raises(SignatureError, match="kid is not a byte string"):
        decode(b"\x00" * 16)


# --- signing through an external signer (a KMS key in production) -------------


def test_sign_with_an_external_signer_is_byte_identical_to_sign(researcher_key):
    """`sign_with` assembles COSE_Sign1 itself and asks a callable for the
    Ed25519 signature, which is how a KMS-held key signs. Ed25519 is
    deterministic, so for the same key bytes the envelope must equal pycose's
    byte for byte."""
    from crucible_core.cose import sign_with

    for payload in ({"a": 1}, {"tree_size": 7, "root": "sha256:" + "ab" * 32}, {"nested": {"x": [1, 2, {"y": None}]}}):
        expected = sign(payload, researcher_key)
        got = sign_with(payload, researcher_key.key_id, researcher_key.obj.sign)
        assert got == expected
        verify(got, researcher_key.public())


def test_sign_with_a_signer_for_another_key_does_not_verify(researcher_key):
    from crucible_core.cose import sign_with

    other = PrivateKey.generate("researcher")
    forged = sign_with({"a": 1}, researcher_key.key_id, other.obj.sign)
    with pytest.raises(SignatureError):
        verify(forged, researcher_key.public())
