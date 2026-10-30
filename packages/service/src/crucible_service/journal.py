"""The journal: an append-only object store, the service's log of record.

SPEC.md §5 Scale: "the journal is an append-only object store rather than a
local file, ingest is stateless behind the journal". The store has one write,
`create`, which writes a key only if it does not already exist. Creating the
object for leaf N *is* appending leaf N, so any number of stateless ingest
processes can share a journal without forking it: exactly one create of a given
key succeeds, and a loser reloads and tries the next position.

Two implementations:

* `DirStore`, a directory, for tests and local runs. A create writes a temp
  file and ``os.link``s it into place, which the kernel refuses if the name
  exists, so a create can never clobber.
* An S3 store with ``If-None-Match: *`` on every PutObject, in a bucket under
  Object Lock (step 9 of the phase 0 plan).

Nothing here updates or deletes. A store that has changed under the service is
the service's to detect (`log.TransparencyLog` re-checks every signed
checkpoint against the leaves on start), not the store's to permit.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Protocol

from crucible_core.atomic import fsync_dir

_KEY_RE = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")


class JournalError(Exception):
    """The journal could not be read or written. The service answers 503."""


class ObjectStore(Protocol):
    def create(self, key: str, data: bytes) -> bool:
        """Write ``data`` at ``key`` if nothing is there. True if this call created it."""

    def get(self, key: str) -> bytes | None:
        """The bytes at ``key``, or None if absent."""

    def list(self, prefix: str) -> list[str]:
        """Every key starting with ``prefix``, sorted."""


def check_key(key: str) -> str:
    if not (isinstance(key, str) and _KEY_RE.fullmatch(key)) or ".." in key.split("/"):
        raise JournalError(f"not a journal key: {key!r}")
    return key


class DirStore:
    """An `ObjectStore` on a local directory."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    @property
    def identity(self) -> str:
        """Which journal this is, as a genesis claim records it."""
        return f"dir:{self.root.resolve()}"

    def _path(self, key: str) -> Path:
        return self.root / check_key(key)

    def create(self, key: str, data: bytes) -> bool:
        target = self._path(key)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
            tmp = Path(name)
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                try:
                    os.link(tmp, target)
                except FileExistsError:
                    return False
            finally:
                tmp.unlink(missing_ok=True)
            fsync_dir(target.parent)
            return True
        except OSError as exc:
            raise JournalError(f"cannot create {key}: {exc}") from exc

    def get(self, key: str) -> bytes | None:
        try:
            return self._path(key).read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise JournalError(f"cannot read {key}: {exc}") from exc

    def list(self, prefix: str) -> list[str]:
        base = self.root
        under = base / prefix.rpartition("/")[0]  # the deepest directory the prefix names
        try:
            keys = [
                p.relative_to(base).as_posix()
                for p in (under.rglob("*") if under.is_dir() else ())
                if p.is_file() and not p.name.startswith(".")
            ]
        except OSError as exc:
            raise JournalError(f"cannot list {prefix}: {exc}") from exc
        return sorted(k for k in keys if k.startswith(prefix))


__all__ = ["DirStore", "JournalError", "ObjectStore", "check_key"]
