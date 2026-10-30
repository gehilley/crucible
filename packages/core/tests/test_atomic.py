"""File replacement never leaves a file half-replaced.

Ported from v1's harness suite (``test_atomic_config_writes.py``), keeping the
tests of ``crucible_core.atomic`` and ``PrivateKey.write`` themselves.
"""

from __future__ import annotations

import io
import os
import stat
from pathlib import Path

import pytest

from crucible_core import atomic
from crucible_core.keys import PrivateKey


class KilledMidWrite(Exception):
    pass


class _KilledAfterTruncate:
    """A file handle whose first `write` dies the way a signal does: the target
    was opened for writing and the new bytes never landed."""

    def __init__(self, handle: io.IOBase) -> None:
        self._handle = handle

    def write(self, data):
        raise KilledMidWrite("terminated between the truncate and the bytes")

    def __getattr__(self, name):
        return getattr(self._handle, name)

    def __enter__(self):
        self._handle.__enter__()
        return self

    def __exit__(self, *exc):
        return self._handle.__exit__(*exc)


@pytest.fixture
def kill_the_first_write(monkeypatch):
    """Make the first write under ``root`` die, and only there.

    Patched at `io.open`, the funnel `Path.write_text`, `Path.open` and
    `os.fdopen` all reach by name at call time. A write through a descriptor
    from `mkstemp` arrives as an `int`, which counts as under ``root``: refusing
    it would make the atomic path look like a pass by not being measured.
    """
    real_open = io.open

    def install(root: Path):
        armed = [True]

        def patched(file, mode="r", *args, **kwargs):
            handle = real_open(file, mode, *args, **kwargs)
            writing = any(flag in mode for flag in ("w", "a", "+", "x"))
            ours = isinstance(file, int) or str(file).startswith(str(root))
            if armed[0] and writing and ours:
                armed[0] = False
                return _KilledAfterTruncate(handle)
            return handle

        monkeypatch.setattr(io, "open", patched)

    return install


def test_a_killed_private_key_write_leaves_no_stub_that_blocks_recovery(tmp_path, kill_the_first_write):
    """`write` refuses to clobber, so a zero-byte stub left by a killed write
    would make every later attempt fail with a message about a key that is not
    there."""
    root = tmp_path / "tree"
    root.mkdir()
    target = root / "researcher.key.json"

    kill_the_first_write(root)
    with pytest.raises(KilledMidWrite):
        PrivateKey.generate("researcher", label="interrupted").write(target)

    assert not target.exists(), "a killed write left a stub at the key path"
    survivor = PrivateKey.generate("researcher", label="second attempt")
    survivor.write(target)
    assert PrivateKey.read(target).label == "second attempt"


def test_the_private_key_no_clobber_promise_holds(tmp_path):
    """`os.link` refuses in place of an `exists()` check with a window after it."""
    target = tmp_path / "researcher.key.json"
    first = PrivateKey.generate("researcher", label="the real one")
    first.write(target)
    with pytest.raises(Exception, match="refusing to overwrite"):
        PrivateKey.generate("researcher", label="the impostor").write(target)
    assert PrivateKey.read(target).label == "the real one"
    assert oct(target.stat().st_mode & 0o777) == "0o600"


def _text_writer(root: Path):
    target = root / "settings.json"
    atomic.write_json(target, {"before": True})
    return target, lambda: atomic.write_json(target, {"after": True})


def _public_key_writer(root: Path):
    target = root / "researcher.pub.json"
    PrivateKey.generate("researcher", label="before").public().write(target)
    return target, lambda: PrivateKey.generate("researcher", label="after").public().write(target)


WRITERS = {"write_json": _text_writer, "public key": _public_key_writer}


@pytest.mark.parametrize("name", sorted(WRITERS))
def test_a_write_that_dies_mid_flight_leaves_the_previous_file_intact(name, tmp_path, kill_the_first_write):
    root = tmp_path / "tree"
    root.mkdir()
    target, rewrite = WRITERS[name](root)
    before = target.read_bytes()
    assert before

    kill_the_first_write(root)
    with pytest.raises(KilledMidWrite):
        rewrite()

    assert target.read_bytes() == before, f"{name} was destroyed by a write that did not finish"
    assert [p.name for p in root.iterdir()] == [target.name], "a killed write left a temp sibling"


def test_an_existing_file_keeps_its_mode(tmp_path):
    target = tmp_path / "public.json"
    target.write_text("{}")
    os.chmod(target, 0o644)
    atomic.write_text(target, "{\"a\": 1}")
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


def test_an_explicit_mode_applies_from_birth(tmp_path):
    target = tmp_path / "secret.json"
    atomic.write_text(target, "s", mode=0o600)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_text() == "s"
