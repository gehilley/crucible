"""Local Ed25519 identities (build-plan A3)."""

from __future__ import annotations

import json
import os
import stat

import pytest

from crucible_core.keys import (
    ROLES,
    KeyError_,
    PrivateKey,
    PublicKey,
    b64u,
    b64u_decode,
    compute_key_id,
)


@pytest.mark.parametrize("role", ROLES)
def test_generate_produces_a_usable_identity(role):
    key = PrivateKey.generate(role, label="lab")
    assert key.role == role
    assert key.label == "lab"
    assert len(key.private_bytes) == 32
    assert len(key.public_bytes) == 32
    assert key.key_id == compute_key_id(key.public_bytes)


def test_generate_rejects_unknown_roles():
    with pytest.raises(KeyError_, match="unknown key role"):
        PrivateKey.generate("agent")  # type: ignore[arg-type]


def test_key_id_is_derivable_from_the_public_half_alone(researcher_key):
    pub = researcher_key.public()
    assert compute_key_id(pub.public_bytes) == researcher_key.key_id
    assert PublicKey.from_dict(pub.to_dict()).key_id == researcher_key.key_id


def test_key_id_is_stable_across_runs(researcher_key):
    """The fixture seed is fixed, so this digest is frozen for the goldens."""
    assert researcher_key.key_id.startswith("sha256:")
    assert researcher_key.key_id == compute_key_id(researcher_key.public_bytes)
    # Independently derived from the seed, not from the fixture.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = (
        Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    assert researcher_key.key_id == compute_key_id(pub)


def test_compute_key_id_rejects_wrong_length():
    with pytest.raises(KeyError_, match="32 bytes"):
        compute_key_id(b"short")


# --- file format -----------------------------------------------------------


def test_private_key_file_round_trip(tmp_path, researcher_key):
    path = tmp_path / "researcher.key.json"
    researcher_key.write(path)
    loaded = PrivateKey.read(path)
    assert loaded == researcher_key


def test_public_key_file_round_trip(tmp_path, researcher_key):
    path = tmp_path / "researcher.pub.json"
    researcher_key.public().write(path)
    loaded = PublicKey.read(path)
    assert loaded == researcher_key.public()


def test_private_key_file_is_0600(tmp_path, researcher_key):
    path = tmp_path / "k.json"
    researcher_key.write(path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"private key mode is {mode:o}, expected 600"


def test_private_key_write_refuses_to_clobber(tmp_path, researcher_key):
    path = tmp_path / "k.json"
    researcher_key.write(path)
    with pytest.raises(KeyError_, match="refusing to overwrite"):
        researcher_key.write(path)


def test_public_key_file_never_contains_the_private_half(tmp_path, researcher_key):
    path = tmp_path / "researcher.pub.json"
    researcher_key.public().write(path)
    data = json.loads(path.read_text())
    assert "d" not in data
    assert b64u(researcher_key.private_bytes) not in path.read_text()


def write_key_file(path, data):
    """Write a key file the way a real one exists on disk: 0600.

    `keys._load` refuses a private key file that grants group or world access,
    and it refuses *before* the shape checks these fixtures are about get a
    chance to speak. A private key at the umask's mode is a state no minted key
    is ever in — `PrivateKey.write` chmods 0600 and refuses to clobber — so the
    fixture writes 0600 and each assertion below stays the one its test names.
    The mode refusal has its own two-sided plant (`test_key_mode.py`).
    """
    path.write_text(json.dumps(data))
    os.chmod(path, 0o600)
    return path


def test_read_rejects_a_forged_key_id(tmp_path, researcher_key):
    path = tmp_path / "k.json"
    d = researcher_key.to_dict()
    d["key_id"] = "sha256:" + "0" * 64
    write_key_file(path, d)
    with pytest.raises(KeyError_, match="does not match public key"):
        PrivateKey.read(path)


def test_read_rejects_a_mismatched_private_half(tmp_path, researcher_key):
    """A file whose `d` does not generate its `x` is a substitution attempt."""
    other = PrivateKey.generate("researcher")
    d = researcher_key.to_dict()
    d["d"] = b64u(other.private_bytes)
    path = tmp_path / "k.json"
    write_key_file(path, d)
    with pytest.raises(KeyError_, match="does not match the recorded public key"):
        PrivateKey.read(path)


def test_read_rejects_a_short_private_key(tmp_path, researcher_key):
    d = researcher_key.to_dict()
    d["d"] = b64u(b"\x00" * 16)
    path = tmp_path / "k.json"
    write_key_file(path, d)
    with pytest.raises(KeyError_, match="32 bytes"):
        PrivateKey.read(path)


def test_read_rejects_non_ed25519(tmp_path, researcher_key):
    d = researcher_key.to_dict()
    d["crv"] = "P-256"
    path = tmp_path / "k.json"
    write_key_file(path, d)
    with pytest.raises(KeyError_, match="only Ed25519"):
        PrivateKey.read(path)


def test_read_rejects_unknown_role(tmp_path, researcher_key):
    d = researcher_key.to_dict()
    d["role"] = "auditor"
    path = tmp_path / "k.json"
    write_key_file(path, d)
    with pytest.raises(KeyError_, match="unknown key role"):
        PrivateKey.read(path)


@pytest.mark.parametrize("missing", ["role", "key_id", "x"])
def test_read_rejects_missing_fields(tmp_path, researcher_key, missing):
    d = researcher_key.to_dict()
    del d[missing]
    path = tmp_path / "k.json"
    write_key_file(path, d)
    with pytest.raises(KeyError_, match="missing fields"):
        PrivateKey.read(path)


def test_read_reports_a_missing_file(tmp_path):
    with pytest.raises(KeyError_, match="no key file"):
        PrivateKey.read(tmp_path / "absent.json")


@pytest.mark.parametrize("content", ["not json", "[1,2,3]", '"a string"'])
def test_read_rejects_malformed_files(tmp_path, content):
    path = tmp_path / "k.json"
    path.write_text(content)
    with pytest.raises(KeyError_):
        PrivateKey.read(path)


# --- base64url helpers -----------------------------------------------------


@pytest.mark.parametrize("raw", [b"", b"\x00", b"\xff" * 32, bytes(range(32)), b"\xfb\xef"])
def test_b64u_round_trip(raw):
    encoded = b64u(raw)
    assert "=" not in encoded
    assert "+" not in encoded and "/" not in encoded
    assert b64u_decode(encoded) == raw


def test_a_key_file_with_a_duplicate_field_is_refused(tmp_path):
    """019 §4: the trust anchor is parsed like every other security boundary.

    Found by the phase-4 refutation pass, outside the audit's own sweep. The
    verifier had learned to refuse duplicate JSON keys in receipts and
    checkpoints — because `json.loads` silently keeps the last, so what a reader
    sees and what a checker verifies can differ — and then loaded **the public
    key it verifies everything against** with a bare `json.loads`.

    The forgery: a `service.pub.json` whose visible text names one key and whose
    parsed value is another. A reviewer opens it, reads the fingerprint they
    expect, and the tool verifies every signature against a key they never saw.
    That is the same class as the receipt case and strictly worse in position —
    it is the root of trust rather than a leaf of it.
    """
    forged = tmp_path / "service.pub.json"
    honest = PrivateKey.generate("service", label="honest").public()
    attacker = PrivateKey.generate("service", label="attacker").public()
    a, b = honest.to_dict(), attacker.to_dict()
    # BOTH `x` and `key_id` are duplicated, and that is what makes this the real
    # attack rather than a strawman. Swapping `x` alone is already caught, by a
    # different guard: `key_id` is derived from the public half, so a mismatched
    # pair fails the binding check with a bare `json.loads` and no duplicate-key
    # rule at all. The forgery only works if it is *internally consistent* —
    # attacker key with attacker fingerprint — so that every check downstream of
    # the parse agrees, and the only disagreement left is between what the file
    # SHOWS a reader and what the parser HANDS the tool.
    body = ",\n".join(f"  {json.dumps(k)}: {json.dumps(v)}" for k, v in a.items())
    forged.write_text(
        "{\n"
        + body
        + f',\n  "x": {json.dumps(b["x"])}'
        + f',\n  "key_id": {json.dumps(b["key_id"])}\n'
        + "}\n"
    )

    # The file a human reads names the honest key on its first `key_id` line.
    assert a["key_id"] in forged.read_text()

    with pytest.raises(KeyError_) as caught:
        PublicKey.read(forged)
    assert "does not have one reading" in str(caught.value)
    assert "more than once" in str(caught.value)


def test_an_ordinary_key_file_still_loads(tmp_path):
    """The other direction, so the refusal cannot be a blanket one."""
    path = tmp_path / "service.pub.json"
    key = PrivateKey.generate("service", label="ordinary").public()
    key.write(path)
    assert PublicKey.read(path).key_id == key.key_id


# --- keys nobody holds -------------------------------------------------------------

_SMALL_ORDER = [
    "0100000000000000000000000000000000000000000000000000000000000000",  # identity, order 1
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # order 2
    "0000000000000000000000000000000000000000000000000000000000000000",  # order 4
    "0000000000000000000000000000000000000000000000000000000000000080",  # order 4, negative zero x
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y = p: not reduced
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y = p + 1
]


@pytest.mark.parametrize("hexkey", _SMALL_ORDER)
def test_a_public_key_nobody_can_hold_is_refused(hexkey):
    from crucible_core.keys import PublicKey, b64u, compute_key_id

    pub = bytes.fromhex(hexkey)
    data = {"role": "researcher", "key_id": compute_key_id(pub), "x": b64u(pub)}
    with pytest.raises(KeyError_, match="usable Ed25519"):
        PublicKey.from_dict(data)


def test_the_identity_key_really_does_verify_a_signature_nobody_made():
    """Why the check exists: with A = O, (R = O, S = 0) verifies any message."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    identity = bytes.fromhex(_SMALL_ORDER[0])
    try:
        Ed25519PublicKey.from_public_bytes(identity).verify(identity + bytes(32), b"anything")
    except Exception:
        pytest.skip("this cryptography build already refuses small-order keys")


def test_real_keys_are_accepted():
    from crucible_core.keys import PrivateKey, PublicKey

    for _ in range(200):
        k = PrivateKey.generate("researcher").public()
        assert PublicKey.from_dict(k.to_dict()) == k


@pytest.mark.parametrize("data", [[1, 2], "abc", None, {"role": "researcher", "key_id": "x", "x": 5}])
def test_a_key_that_is_not_a_key_object_is_a_key_error(data):
    from crucible_core.keys import PublicKey

    with pytest.raises(KeyError_):
        PublicKey.from_dict(data)
