"""Content-addressed blob store.

Layout::

    blobs/sha256/<first two hex>/<remaining hex>

Writes are atomic (temp file + `os.replace`) and idempotent: putting bytes that
are already stored is a no-op that returns the same digest. Nothing is ever
overwritten, because the name *is* the content -- if the digest matches, the
bytes match.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from crucible_core.atomic import fsync_dir
from crucible_core.canonical import canonicalize, digest_hex, is_digest, sha256_bytes, sha256_file


class BlobError(Exception):
    """Raised for a missing blob or a corrupt store."""


class BlobStore:
    """A directory of content-addressed bytes."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"BlobStore({str(self.root)!r})"

    def path_for(self, dgst: str) -> Path:
        """Where ``dgst`` lives, whether or not it is stored."""
        if not is_digest(dgst):
            raise BlobError(f"not a digest: {dgst!r}")
        hexd = digest_hex(dgst).hex()
        return self.root / "sha256" / hexd[:2] / hexd[2:]

    def has(self, dgst: str) -> bool:
        return self.path_for(dgst).exists()

    def put_bytes(self, data: bytes) -> str:
        """Store ``data``, returning its digest. Idempotent."""
        dgst = sha256_bytes(data)
        target = self.path_for(dgst)
        if target.exists():
            return dgst
        self._atomic_write(target, data)
        return dgst

    def put_json(self, value: object) -> str:
        """Store a JSON value in its canonical form."""
        return self.put_bytes(canonicalize(value))

    def put_file(self, path: Path | str) -> str:
        """Copy a file into the store without loading it whole.

        The source is read twice -- once to hash, once to copy -- so the copy is
        re-hashed before it is published. An instrument still appending, an
        editor rewriting in place, or a concurrent ingest of a downloading file
        would otherwise leave the store permanently holding bytes under a digest
        that is not their hash: silent, and fatal to every later integrity check.
        """
        path = Path(path)
        if not path.is_file():
            raise BlobError(f"not a file: {path}")
        dgst = sha256_file(path)
        target = self.path_for(dgst)
        if target.exists():
            return dgst
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".tmp-")
        os.close(fd)
        try:
            shutil.copyfile(path, tmp)
            actual = sha256_file(tmp)
            if actual != dgst:
                raise BlobError(
                    f"{path} changed while being stored: hashed {dgst}, copied {actual}"
                )
            with open(tmp, "rb") as fh:
                os.fsync(fh.fileno())
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        fsync_dir(target.parent)
        return dgst

    def get(self, dgst: str) -> bytes:
        """Read a blob back, re-verifying its digest.

        Re-verification is not paranoia: a blob store that silently returns
        corrupted bytes would let a chain "verify" against artifacts that are no
        longer what was committed.
        """
        target = self.path_for(dgst)
        if not target.exists():
            raise BlobError(f"no blob {dgst}")
        data = target.read_bytes()
        actual = sha256_bytes(data)
        if actual != dgst:
            raise BlobError(f"blob store corruption: {target} contains {actual}, expected {dgst}")
        return data

    def open(self, dgst: str):
        """Open a blob for streaming reads. Digest is *not* re-verified."""
        target = self.path_for(dgst)
        if not target.exists():
            raise BlobError(f"no blob {dgst}")
        return target.open("rb")

    def size(self, dgst: str) -> int:
        target = self.path_for(dgst)
        if not target.exists():
            raise BlobError(f"no blob {dgst}")
        return target.stat().st_size

    def _entries(self):
        """Every file under ``sha256/``, as (digest or None, path)."""
        base = self.root / "sha256"
        if not base.is_dir():
            return
        for prefix_dir in sorted(base.iterdir()):
            if not prefix_dir.is_dir():
                yield None, prefix_dir
                continue
            for blob in sorted(prefix_dir.iterdir()):
                if blob.name.startswith(".tmp-"):
                    continue
                name = f"sha256:{prefix_dir.name}{blob.name}"
                filed = blob.is_file() and is_digest(name) and self.path_for(name) == blob
                yield (name if filed else None), blob

    def iter_digests(self):
        """Yield every stored digest. Order is unspecified. A file whose name is
        not a digest is not a blob, and is not yielded (`fsck` reports it)."""
        for dgst, _ in self._entries():
            if dgst is not None:
                yield dgst

    def fsck(self) -> list[str]:
        """Re-hash every blob by streaming; return digests whose contents disagree,
        and the paths of any files that are not blobs at all.

        Routed through `get` this would call ``read_bytes`` on each blob, and a
        research dataset can legitimately be tens of gigabytes in one object.
        """
        bad = []
        for dgst, target in self._entries():
            if dgst is None:
                # A stray file is corruption to report, not a reason to stop.
                bad.append(str(target.relative_to(self.root)))
                continue
            try:
                if sha256_file(target) != dgst:
                    bad.append(dgst)
            except OSError:
                bad.append(dgst)
        return bad

    def _atomic_write(self, target: Path, data: bytes) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        fsync_dir(target.parent)
