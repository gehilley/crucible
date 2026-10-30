"""A private key file anyone but its owner can reach is refused at load.

Ported from v1's harness suite (``test_key_material_mode_gate.py``), keeping the
tests of the check itself, which lives in ``crucible_core.keys._load``.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from crucible_core.keys import KeyError_, PrivateKey, PublicKey

GROUP_WORLD = stat.S_IRWXG | stat.S_IRWXO


@pytest.fixture
def minted(tmp_path: Path, researcher_key: PrivateKey) -> Path:
    """A private key on disk at its minted 0600, ready to be widened."""
    path = tmp_path / "researcher.key.json"
    researcher_key.write(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600, "PrivateKey.write no longer mints 0600"
    return path


def test_a_protected_private_key_still_loads(minted, researcher_key):
    """The other side of the check. A 0600 key is exactly what must keep working."""
    assert PrivateKey.read(minted) == researcher_key


@pytest.mark.parametrize("mode", [0o400, 0o500, 0o700])
def test_a_tighter_mode_is_not_refused(minted, researcher_key, mode):
    """Tighter is not widened: a check keyed on `!= 0o600` would refuse a key
    someone had deliberately hardened."""
    os.chmod(minted, mode)
    assert PrivateKey.read(minted) == researcher_key


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o666, 0o606])
def test_a_widened_private_key_is_refused_at_load(minted, mode):
    """Any group or world bit, read or write, refuses, and the message names the
    observed mode and the exact remediation."""
    os.chmod(minted, mode)
    with pytest.raises(KeyError_) as caught:
        PrivateKey.read(minted)
    message = str(caught.value)
    assert f"{mode:#o}" in message, f"the refusal does not name the observed mode: {message}"
    assert f"chmod 600 {minted}" in message, f"the refusal does not carry the remediation: {message}"


def test_the_refusal_is_at_the_shared_chokepoint_not_at_one_call_site(minted):
    """`PublicKey.read` of a *private* key file refuses too: the check keys on
    the file holding private material, not on which reader was called."""
    os.chmod(minted, 0o644)
    with pytest.raises(KeyError_):
        PublicKey.read(minted)


def test_a_public_key_file_is_not_refused_for_being_readable(tmp_path, researcher_key):
    """The discriminator that keeps the check from being `refuse everything`:
    a public key is published material."""
    path = tmp_path / "researcher.pub.json"
    researcher_key.public().write(path)
    os.chmod(path, 0o644)
    assert stat.S_IMODE(path.stat().st_mode) & GROUP_WORLD
    assert PublicKey.read(path) == researcher_key.public()
