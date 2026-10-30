"""Replace a file without ever leaving it half-replaced.

`Path.write_text` is `open(mode="w")` followed by `write`. The truncate is a
separate syscall from the bytes, so a process that dies between them leaves the
target **empty** — and being killed is ordinary, not exceptional (timeouts and
impatient people are weather).
There is no `finally` that helps here; a signal does not unwind, and even one
that did would be unwinding after the truncate had already happened. The only
answer is an ordering the kernel enforces: write a sibling, then `os.replace`,
which is atomic. What a kill leaves behind is then either the old file or the
new one, plus at worst a `.tmp` sibling nobody reads.

Written down once here so that every file the client replaces -- its own
configuration, the Claude Code settings it installs hooks into, key files --
goes through one implementation rather than private copies of the pattern.

**The mode is preserved deliberately.** `mkstemp` creates 0600 and
`Path.write_text` creates 0666 & ~umask, so a naive port would silently change
the permissions of every file it touched — including making a world-readable
public key private, which reads as a corrupted key to anything running as
another user. An existing file keeps the mode it had; a new one gets what
`open()` would have given it.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

__all__ = ["fsync_dir", "write_json", "write_text"]


def _mode_for(path: Path) -> int:
    """The mode the replacement should carry: the file's own, or `open()`'s."""
    try:
        return os.stat(path).st_mode & 0o7777
    except OSError:
        # No file yet (or an unreadable parent, which the write is about to
        # fail on anyway). Match what `open(path, "w")` would have created.
        umask = os.umask(0)
        os.umask(umask)
        return 0o666 & ~umask


def write_text(
    path: Path | str, text: str, *, encoding: str = "utf-8", mode: int | None = None
) -> Path:
    """Replace ``path`` with ``text``. Returns the path.

    `newline=""` so the bytes on disk are the bytes given, on every platform: a
    document this rewrites in place is one somebody diffs, and a silent
    translation of every `\\n` would show up as a whole-file change.

    ``mode`` is the permission bits the replacement lands under. Left ``None``
    it is `_mode_for(path)` -- the file's own mode, or what `open()` would give
    a new one -- which is right for the public artifacts this helper was built
    for. A caller writing a secret (a salt, a plaintext question) passes an
    explicit ``mode`` such as ``0o600`` so the bytes are private *from birth*,
    the way `keys.PrivateKey.write` already is: the mode is set on the temp file
    before the atomic `os.replace`, so there is no window in which the secret
    exists at a wider mode.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = _mode_for(path) if mode is None else mode
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(name)
    try:
        # `os.fdopen`, not `open(tmp, ...)`: the descriptor `mkstemp` returned is
        # the one that is guaranteed not to have collided with anything.
        with os.fdopen(fd, "w", encoding=encoding, newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        # BaseException, not Exception: a KeyboardInterrupt (Ctrl-C, or a SIGTERM
        # handler that raises one) must take the temp file with it rather than
        # leaving a `.tmp` sibling for every interrupted run.
        tmp.unlink(missing_ok=True)
        raise
    fsync_dir(path.parent)
    return path


def write_json(
    path: Path | str,
    data: object,
    *,
    indent: int = 2,
    sort_keys: bool = False,
    mode: int | None = None,
) -> Path:
    """Replace ``path`` with ``data`` as JSON plus a trailing newline.

    Serialized *before* anything on disk is touched, so a value that cannot be
    encoded raises with the previous file still in place. ``mode`` is forwarded
    to `write_text`: pass ``0o600`` for a secret-bearing record.
    """
    return write_text(path, json.dumps(data, indent=indent, sort_keys=sort_keys) + "\n", mode=mode)


def fsync_dir(path: Path | str) -> None:
    """Persist a directory entry.

    POSIX does not promise a rename survives a crash until the containing
    directory is itself synced. Without it a machine that loses power just after
    a successful install can come back with the *previous* settings.json and a
    configuration that disagrees with it.
    """
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:  # platforms that cannot open a directory (Windows)
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - filesystem-dependent
        pass
    finally:
        os.close(fd)
