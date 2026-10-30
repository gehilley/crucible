"""Local Ed25519 keypairs.

There are two roles:

``researcher``
    the client's identity: generated at install, registered with the service,
    and used to sign the event batches the client sends (SPEC.md §3).
``service``
    signs the service's checkpoints, and through them its receipts (SPEC.md §5).

A model is deliberately *not* a key. It is named as an event's actor
(``model:<id>``, SPEC.md §4), not given an identity of its own.

Key files are JSON so they diff and archive cleanly. Private key files are
written 0600. The ``key_id`` is derived from the public key, so it is stable and
verifiable from the public half alone::

    key_id = "sha256:<hex>"  over  JCS({"alg": "EdDSA", "crv": "Ed25519",
                                        "kty": "OKP", "x": <b64u pubkey>})
"""

from __future__ import annotations

import base64
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import atomic
from .canonical import (
    CanonicalizationError,
    DuplicateJSONKeyError,
    digest,
    loads_one_reading,
)

Role = Literal["researcher", "service"]
ROLES: tuple[Role, ...] = ("researcher", "service")

_KEY_FILE_VERSION = 0


class KeyError_(Exception):
    """Raised for malformed, missing, or role-mismatched key material."""


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


_P = 2**255 - 19
_D = -121665 * pow(121666, -1, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _weak_point(public_bytes: bytes) -> str | None:
    """Why ``public_bytes`` is not a usable Ed25519 public key, or None.

    Refuses a non-canonical encoding (y >= p, or a negative zero x), a point
    not on the curve, and a point of small order ([8]A is the identity). A
    small-order key verifies signatures that anyone can write without a private
    key, so registering one would let a batch be "signed" by nobody.
    """
    y = int.from_bytes(public_bytes, "little") & ((1 << 255) - 1)
    sign = public_bytes[31] >> 7
    if y >= _P:
        return "the point's y coordinate is not reduced"
    u, v = (y * y - 1) % _P, (_D * y * y + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P) % _P  # RFC 8032 §5.1.3
    if v * x * x % _P == (-u) % _P:
        x = x * _SQRT_M1 % _P
    if v * x * x % _P != u:
        return "the point is not on the curve"
    if x == 0 and sign:
        return "the point's encoding is not canonical"
    if x & 1 != sign:
        x = _P - x
    # [8]A in extended coordinates (three doublings); the identity is X = 0, Y = Z.
    X, Y, Z, T = x, y, 1, x * y % _P
    for _ in range(3):
        A, B = X * X % _P, Y * Y % _P
        C = 2 * Z * Z % _P
        H = (A + B) % _P
        E = (H - (X + Y) * (X + Y)) % _P
        G = (A - B) % _P
        F = (C + G) % _P
        X, Y, Z, T = E * F % _P, G * H % _P, F * G % _P, E * H % _P
    if X == 0 and Y == Z:
        return "the point has small order"
    return None


MAX_LABEL = 256
PUBLIC_FIELDS = frozenset({"v", "role", "key_id", "alg", "crv", "kty", "x", "label"})


def compute_key_id(public_bytes: bytes) -> str:
    """Derive the stable ``key_id`` for an Ed25519 public key."""
    if len(public_bytes) != 32:
        raise KeyError_("Ed25519 public key must be 32 bytes")
    return digest({"alg": "EdDSA", "crv": "Ed25519", "kty": "OKP", "x": b64u(public_bytes)})


@dataclass(frozen=True)
class PublicKey:
    """The public half of a Crucible identity."""

    role: Role
    key_id: str
    public_bytes: bytes
    label: str = ""

    @property
    def obj(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(self.public_bytes)

    def to_dict(self) -> dict:
        return {
            "v": _KEY_FILE_VERSION,
            "role": self.role,
            "key_id": self.key_id,
            "alg": "EdDSA",
            "crv": "Ed25519",
            "kty": "OKP",
            "x": b64u(self.public_bytes),
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, data: dict) -> PublicKey:
        _require(data, {"role", "key_id", "x"})
        if data.get("crv", "Ed25519") != "Ed25519" or data.get("kty", "OKP") != "OKP":
            raise KeyError_("only Ed25519/OKP keys are supported")
        if not isinstance(data["x"], str):
            raise KeyError_("x must be a base64url string")
        try:
            pub = b64u_decode(data["x"])
        except ValueError as exc:
            raise KeyError_(f"x is not base64url: {exc}") from exc
        expected = compute_key_id(pub)
        weak = _weak_point(pub)
        if weak is not None:
            raise KeyError_(f"not a usable Ed25519 public key: {weak}")
        if data["key_id"] != expected:
            raise KeyError_(
                f"key_id does not match public key: file says {data['key_id']}, derived {expected}"
            )
        role = data["role"]
        if role not in ROLES:
            raise KeyError_(f"unknown key role {role!r}")
        label = data.get("label", "")
        if not (isinstance(label, str) and len(label) <= MAX_LABEL):
            raise KeyError_(f"a key's label is a string of at most {MAX_LABEL} characters")
        if unknown := set(data) - PUBLIC_FIELDS:
            raise KeyError_(f"unknown key field(s) {sorted(unknown)[:5]}")
        return cls(role=role, key_id=expected, public_bytes=pub, label=label)

    def write(self, path: Path) -> Path:
        """Replace ``path`` with this key, atomically.

        A truncating write killed between the truncate and the bytes leaves an
        empty `*.pub.json`, and `read` then rejects it as not-JSON: nothing
        signed by the key can be verified, and the file that says why looks like
        a corruption of the key rather than an interrupted write.
        """
        return atomic.write_json(path, self.to_dict(), sort_keys=True)

    @classmethod
    def read(cls, path: Path) -> PublicKey:
        return cls.from_dict(_load(path))


@dataclass(frozen=True)
class PrivateKey:
    """A Crucible signing identity. Never serialize this into a record."""

    role: Role
    key_id: str
    private_bytes: bytes
    label: str = ""

    @property
    def obj(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(self.private_bytes)

    @property
    def public_bytes(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        return self.obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def public(self) -> PublicKey:
        return PublicKey(
            role=self.role, key_id=self.key_id, public_bytes=self.public_bytes, label=self.label
        )

    @classmethod
    def generate(cls, role: Role, label: str = "") -> PrivateKey:
        if role not in ROLES:
            raise KeyError_(f"unknown key role {role!r}")
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        sk = Ed25519PrivateKey.generate()
        raw = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cls(role=role, key_id=compute_key_id(pub), private_bytes=raw, label=label)

    def to_dict(self) -> dict:
        d = self.public().to_dict()
        d["d"] = b64u(self.private_bytes)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> PrivateKey:
        _require(data, {"role", "key_id", "x", "d"})
        pub = PublicKey.from_dict({k: v for k, v in data.items() if k != "d"})
        priv = b64u_decode(data["d"])
        if len(priv) != 32:
            raise KeyError_("Ed25519 private key must be 32 bytes")
        derived = Ed25519PrivateKey.from_private_bytes(priv)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        if derived.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) != pub.public_bytes:
            raise KeyError_("private key does not match the recorded public key")
        return cls(role=pub.role, key_id=pub.key_id, private_bytes=priv, label=pub.label)

    def write(self, path: Path) -> Path:
        """Write 0600, atomically. Refuses to clobber an existing key file.

        Both properties at once, which is why this is not `atomic.write_json`.
        Creating the destination with `O_EXCL` and *then* writing it means a
        process killed between the two leaves a **zero-byte private key** at the
        path. The key material itself is gone either way, having only ever been
        in memory. What the stub adds is that it cannot be replaced: `write`
        refuses to overwrite an existing key file, so every later install fails
        with a message saying a key already exists, when what is there is a
        hole.

        A full file is built beside the destination and `os.link`ed into place.
        `link` is atomic and fails with `EEXIST` rather than clobbering, so the
        no-overwrite guarantee is now the kernel's rather than a `path.exists()`
        check with a window after it.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"
        fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        tmp = Path(name)
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "w") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.link(tmp, path)
            except FileExistsError:
                raise KeyError_(f"refusing to overwrite existing private key at {path}") from None
        finally:
            # `finally`, not `except`: the link leaves two names for one inode
            # and the temp one must go on the success path too. There is no
            # signal-shaped hole behind this one -- a kill here leaves either the
            # key or a 0600 `.tmp` sibling, and neither is a stub that blocks the
            # next attempt.
            tmp.unlink(missing_ok=True)
        atomic.fsync_dir(path.parent)
        return path

    @classmethod
    def read(cls, path: Path) -> PrivateKey:
        return cls.from_dict(_load(path))


def _load(path: Path) -> dict:
    path = Path(path)
    if not path.exists():
        raise KeyError_(f"no key file at {path}")
    # `loads_one_reading`, not `json.loads`: this is the trust anchor.
    # `json.loads` resolves a duplicate key by silently keeping the last, so a
    # key file can SHOW a reader one fingerprint and HAND the tool another. Every
    # signature this process verifies is checked against whatever comes out of
    # this function, which makes it the root of trust rather than a leaf of it.
    #
    # Swapping `x` alone is already caught, by `key_id`'s binding to the public
    # half. The forgery that works is the internally consistent one -- attacker
    # key AND attacker fingerprint, both duplicated -- where every downstream
    # check agrees and the only disagreement left is between the bytes a human
    # reads and the value the parser returns. That is precisely the disagreement
    # one-reading parsing exists to refuse.
    try:
        data = loads_one_reading(path.read_text())
    except (CanonicalizationError, DuplicateJSONKeyError) as exc:
        raise KeyError_(f"key file {path} does not have one reading: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise KeyError_(f"key file {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise KeyError_(f"key file {path} must contain a JSON object")
    _refuse_widened_private_key(path, data)
    return data


#: The bits that put a key file within reach of anybody but its owner -- group
#: and world, read, write and execute alike. A *tighter* mode has none of them
#: set, so `0400`, `0500` and `0700` are not refused: someone who hardened their
#: own key further must not be told the tool is broken.
_GROUP_WORLD_BITS = stat.S_IRWXG | stat.S_IRWXO


def _refuse_widened_private_key(path: Path, data: dict) -> None:
    """Refuse a private key file that anyone but its owner can reach.

    Checked at every load, not only at mint: a key widened after it was written
    -- an archive restore, `cp` without `-p`, `unzip`, a `git checkout`, which
    records only the +x bit -- would otherwise go on being used with no
    diagnostic. Every use of the private half reaches this function, so one stat
    here is the at-use check at all of them.

    It fires on the presence of `d` (the private half) rather than on which
    `read` classmethod was called, so `PublicKey.read` pointed at a private key
    file refuses too. A **public** key file is published material and is never
    refused for being readable.

    A mode that cannot be read is a refusal too: a guard that cannot establish
    its property must not claim it. The branch is unreachable in practice --
    `path.exists()` above has already stat-ed the file -- so the strict side
    costs a message nobody sees, and the other side would cost a silent
    unprotected key.
    """
    if "d" not in data:
        return
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise KeyError_(
            f"the mode of the private key at {path} could not be read "
            f"({type(exc).__name__}: {exc}), so it cannot be established that the key is "
            f"unreadable by anyone but its owner -- and a key whose protection is "
            f"could_not_check is not one this tool will sign with. "
            f"Check it, and if it is not already 0600: chmod 600 {path}"
        ) from exc
    if mode & _GROUP_WORLD_BITS:
        raise KeyError_(
            f"refusing to use the private key at {path}: its mode is {mode:#o}, which grants "
            f"access beyond its owner. It was minted 0600; a mode widened after mint (an "
            f"archive restore, `cp` without `-p`, `unzip`, a `git checkout`) means anything "
            f"signed with this key from now on carries an identity somebody else could have "
            f"used, and no signature already made can be told apart from one that was. "
            f"Restore the protection: chmod 600 {path}"
        )


def _require(data: dict, fields: set[str]) -> None:
    if not isinstance(data, dict):
        raise KeyError_(f"a key is a JSON object, not {type(data).__name__}")
    missing = fields - data.keys()
    if missing:
        raise KeyError_(f"key file missing fields: {sorted(missing)}")
