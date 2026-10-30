"""The service's Merkle log, kept in the journal (SPEC.md §5 Ingest, Scale).

Journal layout (one journal holds one log)::

    leaf/<index:012d>            JCS({"entry": entry, "signature": <base64 COSE_Sign1>});
                                 creating it is the append
    checkpoint/<size:012d>       COSE_Sign1 over {v, kind: "checkpoint", service, log_id, tree_size, root, ts}
    object/<sha256 hex>          content-addressed bytes (the clients' signed batches)
    claim/<log_id>               JCS({v, kind: "claim", log_id, service, key_id, journal}): genesis
                                 records it before it binds a KMS key to log_id (`create`)

An entry is ``{"v": 2, "kind": ..., "ts": <server microseconds>, "payload": {...}}``.
Leaf 0 is the ``service`` entry that names the service, the log's id, and its
key; creating it is genesis, so a log either exists whole or not at all. Each
stored leaf carries the service key's signature over ``{v, kind: "leaf",
log_id, index, entry_hash}``, made before the leaf is created. Leaves are
hashed into an RFC 6962 tree (`merkle`), and a checkpoint is signed at every
tree size. The receipt for leaf i is always against the checkpoint at size
i + 1, the one signed when it was appended, so asking again returns the same
bytes (see `crucible_verify.receipts` for the receipt format, which this module
produces and that module checks with its own code). A checkpoint's time is
never earlier than any entry it signs.

**Stateless.** Nothing here holds state the journal cannot rebuild. `open`
reads every leaf and re-checks every signed checkpoint against them; `append`
tries to create the next leaf and, if another process got there first, reads
the leaves it missed and builds again from the new state. The create-if-absent
rule is what makes two processes unable to fork the log.

**Startup is a check.** A journal whose leaves no longer hash to a root its
signed checkpoints vouch for, or with a hole in its leaf numbering, refuses to
open. An empty journal opens only through `create`, and `create` refuses a
journal that already holds a leaf, so a lost cache can never mint a second
genesis over an existing record.

**Nothing is signed over unchecked.** A leaf this process did not write, and
that no verified checkpoint covers, must carry the service key's signature for
its index and entry -- so a leaf planted by someone who can create journal
objects but does not hold the key is refused, whatever it says, its server
time included -- and is then offered to the admission check its owner attaches
(`attach`; the service re-runs ingest's checks) before it is adopted. Every
signature is verified before what it signs is written, and a stored checkpoint
before it is handed out.

**What startup cannot see.** A journal whose last leaves *and* their
checkpoints were deleted looks like a shorter, intact log, and the next append
would sign that tree size again over a different leaf. Only the store can
prevent that: the journal is write-once (Object Lock in production), and
immutability rests on it.
"""

from __future__ import annotations

import base64
import json
import re
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from crucible_core.canonical import CanonicalizationError, canonicalize, sha256_bytes
from crucible_core.cose import SignatureError, verify

from . import merkle
from .journal import JournalError, ObjectStore
from .signer import Signer

PROTOCOL_VERSION = 2
OBJECT_CACHE = 64 * 1024 * 1024
MAX_DEPTH = 64  # the deepest an entry may nest; far below any parser's limit
MAX_SAFE_INT = 2**53 - 1


def _too_deep(value: object, limit: int = MAX_DEPTH) -> bool:
    stack = [(value, 1)]
    while stack:
        v, depth = stack.pop()
        if isinstance(v, (dict, list)):
            if depth > limit:
                return True
            stack.extend((c, depth + 1) for c in (v.values() if isinstance(v, dict) else v))
    return False


class LogError(Exception):
    """The journal does not hold a log this service can open, or was tampered with."""


class SignerError(JournalError):
    """The signing key could not be reached, or returned something that does not verify."""


class ReceiptPending(Exception):
    """The leaf was appended, but its checkpoint could not be signed yet. A resend
    of the same request returns its receipt once the signer answers."""

    def __init__(self, index: int, detail: str) -> None:
        super().__init__(detail)
        self.index, self.detail = index, detail


class Refusal(Exception):
    """An append the log's current state does not allow. Carries what the client needs."""

    def __init__(self, code: str, detail: str, status: int = 409, **extra) -> None:
        super().__init__(detail)
        self.code, self.detail, self.status, self.extra = code, detail, status, extra


def now_us() -> int:
    return time.time_ns() // 1000


def leaf_key(index: int) -> str:
    return f"leaf/{index:012d}"


def checkpoint_key(size: int) -> str:
    return f"checkpoint/{size:012d}"


def claim_key(log_id: str) -> str:
    """Where genesis records, before it binds the key, that this journal is starting ``log_id``."""
    return f"claim/{log_id}"


def object_key(digest: str) -> str:
    return f"object/{digest.removeprefix('sha256:')}"


@dataclass(frozen=True)
class Appended:
    index: int
    entry: dict


class TransparencyLog:
    """The log in one journal. Build with `create` (genesis) or `open`."""

    def __init__(self, store: ObjectStore, signer: Signer, *, log_id: str, service: str,
                 clock: Callable[[], int] = now_us) -> None:
        self.store = store
        self.signer = signer
        self.log_id = log_id
        self.service = service
        self.clock = clock
        self.leaves: list[bytes] = []  # canonical entry bytes, by index
        self.leaf_signatures: list[str] = []  # the service's signature over each leaf, as stored
        self.leaf_hashes: list[bytes] = []  # RFC 6962 leaf hashes, which the tree is built from
        self.entries: list[dict] = []
        self.latest_ts: list[int] = []  # latest_ts[i]: the latest entry time in leaves 0..i
        self.by_hash: dict[str, int] = {}
        self.vouched = 0  # leaves 0..vouched-1 are covered by a checkpoint verified or signed here
        self._checked: dict[int, bytes] = {}  # tree size -> its verified checkpoint envelope
        self._objects: OrderedDict[str, bytes] = OrderedDict()  # checked objects, least recently used first
        self._object_bytes = 0
        self._observers: list[Callable[[int, dict], None]] = []
        self._admit: Callable[[int, dict], None] | None = None
        self._lock = threading.RLock()

    # --- construction -----------------------------------------------------------
    @classmethod
    def create(cls, store: ObjectStore, signer: Signer, *, service: str, genesis_payload: dict | None = None,
               clock: Callable[[], int] = now_us, log_id: str | None = None,
               claim: Callable[[str], None] | None = None, claimed: str | None = None) -> TransparencyLog:
        """Start a new log in an empty journal. Refuses a journal that holds any leaf.

        ``claim(log_id)`` binds the key to the new log. It runs once leaf 0 is
        known to be canonical and signable, and once this journal has recorded
        the claim (``claim/<log_id>``, which also shows the journal takes
        writes), and before leaf 0 is written. ``claimed`` is the log the key is
        already bound to: genesis then resumes that log, but only in the journal
        that recorded the claim, so a genesis that failed after binding can be
        run again, and the key still never starts a second log anywhere else."""
        refused = "the journal already holds a log; open it instead of starting a new one"
        if store.list("leaf/"):
            raise LogError(refused)
        def claim_of(log_id: str) -> bytes:
            journal = getattr(store, "identity", None) or type(store).__name__
            return canonicalize({"v": PROTOCOL_VERSION, "kind": "claim", "log_id": log_id, "service": service,
                                 "key_id": signer.key_id, "journal": journal})

        if claimed is not None:
            # Only this journal's own claim, for this service and key, resumes: a claim copied or
            # planted elsewhere names another journal (or is not one at all), and is refused.
            if store.get(claim_key(claimed)) != claim_of(claimed):
                raise JournalError(f"the key already signs log {claimed}, which this journal did not start; "
                                   "one key signs one log")
            log_id = claimed
        log = cls(store, signer, log_id=log_id or str(uuid.uuid4()), service=service, clock=clock)
        payload = {
            **(genesis_payload or {}),
            "service": service,
            "log_id": log.log_id,
            "key_id": signer.key_id,
            "public_key": signer.public().to_dict(),
        }

        def genesis(current: TransparencyLog) -> dict:
            if current.size:  # another process created leaf 0 first
                raise LogError(refused)
            return {"kind": "service", "payload": payload}

        log._wrap(0, {"v": PROTOCOL_VERSION, "kind": "service", "ts": 0, "payload": payload})  # a trial: nothing is written
        if claim is not None and claimed is None:
            store.create(claim_key(log.log_id), claim_of(log.log_id))
            claim(log.log_id)
        log.append(genesis)
        return log

    @classmethod
    def open(cls, store: ObjectStore, signer: Signer, *, clock: Callable[[], int] = now_us) -> TransparencyLog:
        raw = store.get(leaf_key(0))
        if raw is None:
            raise LogError("the journal holds no log; start one with --genesis")
        try:
            first = _parse_leaf(0, raw)[0]
            payload = first["payload"]
            meta = {k: payload[k] for k in ("service", "log_id", "key_id")}
        except (KeyError, TypeError, LogError) as exc:
            raise LogError(f"the log's first leaf is not its service entry: {exc}") from exc
        if first.get("kind") != "service" or not all(isinstance(v, str) for v in meta.values()):
            raise LogError("the log's first leaf is not its service entry")
        if meta["key_id"] != signer.key_id:
            raise LogError(f"this log is signed by {meta['key_id']}; refusing to sign it with {signer.key_id}")
        log = cls(store, signer, log_id=meta["log_id"], service=meta["service"], clock=clock)
        log._load()
        return log

    def attach(self, admit: Callable[[int, dict], None] | None, observe: Callable[[int, dict], None]) -> None:
        """Check and observe every leaf, now and as leaves arrive.

        ``admit(index, entry)`` runs, in order, for every leaf no verified
        checkpoint covers and this process did not write; it raises `LogError`
        to refuse one. ``observe(index, entry)`` runs for every leaf.
        """
        with self._lock:
            self._admit = admit
            self._observers.append(observe)
            for i, e in enumerate(self.entries):
                if admit is not None and i >= self.vouched:
                    admit(i, e)
                observe(i, e)

    # --- reading the journal --------------------------------------------------------
    def refresh(self, *, _signed: bool = True) -> None:
        """Read leaves created since the last read (by this or any process).

        Leaves are created in order, each by a process that had read the one
        before, so reading forward until the first absent index finds them all.
        """
        with self._lock:
            while (raw := self.store.get(leaf_key(self.size))) is not None:
                self._apply(self.size, raw, check_signature=_signed)

    def _load(self) -> None:
        """Read the whole journal on open, and check it.

        The listings are taken first: every checkpoint listed was signed after
        its leaves existed, so the forward read that follows reaches them. A
        listing taken while other processes append may show a leaf without the
        one before it (a directory lists in no particular order), so growth is
        not judged by the listing's shape: only a listed leaf the forward read
        cannot reach -- one with a hole below it -- refuses to open, rather
        than being filled by the next append. Signatures are checked for the
        leaves no verified checkpoint covers.
        """
        with self._lock:
            checkpoints = self.store.list("checkpoint/")
            listed = self.store.list("leaf/")
            indices = []
            for key in listed:
                if not re.fullmatch(r"leaf/\d{12}", key):
                    raise LogError(f"{key} is not a leaf this log writes; the journal was altered")
                indices.append(int(key.rsplit("/", 1)[1]))
            self.refresh(_signed=False)
            if indices and max(indices) >= self.size:
                raise LogError(f"{leaf_key(max(indices))} is listed but {leaf_key(self.size)} is missing; the journal was altered")
            self._verify_checkpoints(checkpoints)
            for i in range(self.vouched, self.size):
                self._check_leaf_signature(i, self.leaves[i], self.leaf_signatures[i], LogError)

    def _leaf_statement(self, index: int, raw: bytes) -> dict:
        return {"v": PROTOCOL_VERSION, "kind": "leaf", "log_id": self.log_id, "index": index, "entry_hash": sha256_bytes(raw)}

    def _check_leaf_signature(self, index: int, raw: bytes, signature: str, error: type[Exception]) -> None:
        try:
            env = base64.b64decode(signature, validate=True)
            payload = json.loads(verify(env, self.signer.public()).payload_bytes)
        except (ValueError, SignatureError, TypeError) as exc:
            raise error(f"leaf {index} is not signed by this log's key: {exc}") from exc
        if payload != self._leaf_statement(index, raw):
            raise error(f"leaf {index}'s signature is for another index or entry")

    def _wrap(self, index: int, entry: dict) -> bytes:
        """The stored form of ``entry`` at ``index``: the entry and the service's signature over it."""
        try:
            raw = canonicalize(entry)
            if _too_deep(entry) or canonicalize(json.loads(raw)) != raw:
                raise CanonicalizationError("it nests too deep, or does not survive a JCS round trip")
        except (CanonicalizationError, ValueError, RecursionError) as exc:
            raise LogError(f"refusing to write an entry this log could not read back: {exc}") from exc
        try:
            env = self.signer.sign(self._leaf_statement(index, raw))
        except Exception as exc:  # a key service's own errors
            raise SignerError(f"the signer failed: {type(exc).__name__}: {exc}") from exc
        signature = base64.b64encode(env).decode("ascii")
        self._check_leaf_signature(index, raw, signature, SignerError)
        return canonicalize({"entry": entry, "signature": signature})

    def _apply(self, index: int, stored: bytes, *, own: bool = False, check_signature: bool = True) -> None:
        entry, raw, signature = _parse_leaf(index, stored)
        if not own and index >= self.vouched:
            if check_signature:
                self._check_leaf_signature(index, raw, signature, LogError)
            if self._admit is not None:
                self._admit(index, entry)  # raises LogError; nothing is adopted
        self.leaves.append(raw)
        self.leaf_signatures.append(signature)
        self.leaf_hashes.append(merkle.leaf_hash(raw))
        self.entries.append(entry)
        ts = entry.get("ts")
        ts = ts if isinstance(ts, int) and not isinstance(ts, bool) else 0
        self.latest_ts.append(max(ts, self.latest_ts[-1] if self.latest_ts else 0))
        self.by_hash[sha256_bytes(raw)] = index
        for fn in self._observers:
            fn(index, entry)

    def _verify_checkpoints(self, keys: list[str]) -> None:
        roots = merkle.prefix_roots(self.leaf_hashes)
        for key in keys:
            if not re.fullmatch(r"checkpoint/\d{12}", key):
                raise LogError(f"{key} is not a checkpoint this log writes; the journal was altered")
            size = int(key.rsplit("/", 1)[1])
            if not 1 <= size <= self.size:
                raise LogError(f"checkpoint {size} vouches for leaves the journal does not hold")
            self._check_checkpoint(self.store.get(key), size, roots[size - 1], LogError)

    def _check_checkpoint(self, env: bytes | None, size: int, root: bytes, error: type[Exception], *, held: bool = True) -> bytes:
        """``env`` if it is this log's checkpoint at ``size`` over ``root``, signed by its key.
        ``held``: it is the one in the journal, so it is remembered as that size's checkpoint."""
        try:
            payload = json.loads(verify(env or b"", self.signer.public()).payload_bytes)
        except (SignatureError, ValueError) as exc:
            raise error(f"checkpoint {size} is not signed by this log's key: {exc}") from exc
        expected = {"v": PROTOCOL_VERSION, "kind": "checkpoint", "service": self.service, "log_id": self.log_id, "tree_size": size}
        if not isinstance(payload, dict) or any(payload.get(k) != v for k, v in expected.items()):
            raise error(f"checkpoint {size} does not describe this log at that size")
        if payload.get("root") != "sha256:" + root.hex():
            raise error(f"the journal's first {size} leaves do not hash to checkpoint {size}'s root; it was altered")
        if held:
            self._checked[size] = env
            self.vouched = max(self.vouched, size)
        return env

    @property
    def size(self) -> int:
        return len(self.leaves)

    # --- appending --------------------------------------------------------------------
    def append(self, build: Callable[[TransparencyLog], dict | Appended]) -> Appended:
        """Append the entry ``build`` returns for the current state.

        ``build`` sees the log as of the latest leaf, and may raise `Refusal`,
        or return an `Appended` to answer with an existing entry (an exact
        resend). If another process creates the next leaf first, the log
        reloads and ``build`` runs again against the new state.
        """
        with self._lock:
            for _ in range(1000):
                self.refresh()
                built = build(self)
                if isinstance(built, Appended):
                    return built
                index = self.size
                entry = {"v": PROTOCOL_VERSION, "kind": built["kind"], "ts": self.clock(), "payload": built["payload"]}
                stored = self._wrap(index, entry)  # signed and checked before anything is written
                if self.store.create(leaf_key(index), stored):
                    self._apply(index, stored, own=True)
                    try:
                        self._sign_checkpoint(index + 1)
                    except (JournalError, LogError) as exc:
                        raise ReceiptPending(
                            index, f"the entry was appended at leaf {index}, but its checkpoint could not be signed: {exc}"
                        ) from exc
                    return Appended(index, json.loads(self.leaves[index]))
            raise JournalError("could not append after 1000 lost races")

    def _sign_checkpoint(self, size: int) -> bytes:
        root = merkle.root(self.leaf_hashes[:size])
        payload = {
            "v": PROTOCOL_VERSION,
            "kind": "checkpoint",
            "service": self.service,
            "log_id": self.log_id,
            "tree_size": size,
            "root": "sha256:" + root.hex(),
            "ts": max(self.clock(), self.latest_ts[size - 1]),
        }
        try:
            env = self.signer.sign(payload)
        except Exception as exc:  # a key service's own errors
            raise SignerError(f"the signer failed: {type(exc).__name__}: {exc}") from exc
        # Verified before it is written: the journal is write-once, and a bad
        # signature there would stop the log from ever opening again. It is
        # remembered only once it is the journal's: a create that fails leaves
        # nothing handed out that another process could contradict.
        self._check_checkpoint(env, size, root, SignerError, held=False)
        if self.store.create(checkpoint_key(size), env):
            return self._check_checkpoint(env, size, root, SignerError)
        return self._check_checkpoint(self.store.get(checkpoint_key(size)), size, root, LogError)  # another process signed it first

    def checkpoint(self, size: int | None = None) -> tuple[int, bytes]:
        """The signed checkpoint at ``size`` (default: the latest), signing it if missing."""
        with self._lock:
            size = self.size if size is None else size
            if not 1 <= size <= self.size:
                raise Refusal("bad_range", f"no checkpoint at size {size}; the log has {self.size} leaves", 404)
            if size in self._checked:
                return size, self._checked[size]
            env = self.store.get(checkpoint_key(size))
            if env is None:
                return size, self._sign_checkpoint(size)
            return size, self._check_checkpoint(env, size, merkle.root(self.leaf_hashes[:size]), LogError)

    def receipt(self, index: int, *, consistency_from: int | None = None) -> dict:
        """The receipt for leaf ``index``, against the checkpoint at size ``index + 1``.

        ``consistency_from``, a smaller tree size (the session's previous
        receipt's), adds the proof that that tree is a prefix of this one.
        """
        with self._lock:
            if not 0 <= index < self.size:
                raise Refusal("unknown_entry", f"leaf {index} is not in a log of {self.size} leaves", 404)
            size, env = self.checkpoint(index + 1)
            consistency = None
            if consistency_from is not None:
                if not 0 < consistency_from < size:
                    raise LogError(f"no consistency proof from size {consistency_from} to {size}")
                path = merkle.consistency_proof(consistency_from, self.leaf_hashes[:size])
                consistency = {"from_size": consistency_from, "path": ["sha256:" + p.hex() for p in path]}
            return {
                "v": PROTOCOL_VERSION,
                "service": self.service,
                "log_id": self.log_id,
                "entry": json.loads(self.leaves[index]),  # a copy: the cache is not the caller's to edit
                "entry_hash": sha256_bytes(self.leaves[index]),
                "leaf_index": index,
                "inclusion_path": ["sha256:" + p.hex() for p in merkle.inclusion_proof(index, self.leaf_hashes[:size])],
                "checkpoint": base64.b64encode(env).decode("ascii"),
                "consistency": consistency,
            }

    def consistency(self, first: int, second: int) -> list[str]:
        with self._lock:
            if not 1 <= first <= second <= self.size:
                raise Refusal("bad_range", f"no consistency proof from {first} to {second} in a log of {self.size}", 404)
            return ["sha256:" + p.hex() for p in merkle.consistency_proof(first, self.leaf_hashes[:second])]

    # --- content-addressed objects ---------------------------------------------------
    def put_object(self, data: bytes) -> str:
        digest = sha256_bytes(data)
        if not self.store.create(object_key(digest), data):
            held = self.store.get(object_key(digest))
            if held != data:
                raise LogError(f"object {digest} in the journal does not hash to its name; it was altered")
        return digest

    def get_object(self, digest: str) -> bytes | None:
        """The object named ``digest``, checked against its name. Checked objects
        are kept in memory, a bounded amount: they never change."""
        with self._lock:
            if digest in self._objects:
                self._objects.move_to_end(digest)
                return self._objects[digest]
        data = self.store.get(object_key(digest))
        if data is not None and sha256_bytes(data) != digest:
            raise LogError(f"object {digest} in the journal does not hash to its name; it was altered")
        if data is not None and len(data) <= OBJECT_CACHE // 16:
            with self._lock:
                self._objects[digest] = data
                self._object_bytes += len(data)
                while self._object_bytes > OBJECT_CACHE:
                    _, old = self._objects.popitem(last=False)
                    self._object_bytes -= len(old)
        return data


def _parse_leaf(index: int, stored: bytes) -> tuple[dict, bytes, str]:
    """(entry, canonical entry bytes, signature) from a stored leaf; LogError if it is not one."""
    try:
        obj = json.loads(stored)
        if not (isinstance(obj, dict) and set(obj) == {"entry", "signature"} and canonicalize(obj) == stored):
            raise ValueError("not a canonical {entry, signature} object")
        entry, signature = obj["entry"], obj["signature"]
        if not (isinstance(entry, dict) and isinstance(signature, str)) or _too_deep(entry):
            raise ValueError("its entry is not an object, or nests too deep")
        return entry, canonicalize(entry), signature
    except (ValueError, RecursionError, CanonicalizationError) as exc:
        raise LogError(f"leaf {index} is not a leaf this log writes: {exc}") from exc


__all__ = [
    "Appended",
    "LogError",
    "ReceiptPending",
    "Refusal",
    "SignerError",
    "TransparencyLog",
    "checkpoint_key",
    "leaf_key",
    "now_us",
    "object_key",
]
