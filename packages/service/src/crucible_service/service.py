"""Registration and ingest (SPEC.md §3 Installation, §5 Ingest).

**Registration.** A client registers its researcher public key by sending a
COSE_Sign1, signed by that key, whose payload carries the key. Signing with the
key being registered is the proof of possession; a key of small order, which
"verifies" signatures nobody made, is refused. The signed registration is
stored, content-addressed, and the service appends a ``register`` entry naming
it and returns its receipt; registering again returns the original receipt.

**Ingest.** A client sends a batch of events, signed by its registered key::

    COSE_Sign1(JCS({"v": 2, "kind": "batch", "session": s,
                    "from_seq": a, "to_seq": b,
                    "prev_head": h_{a-1} or GENESIS, "head": h_b,
                    "events": [event_a, ..., event_b],
                    "heads": [h_a, ..., h_b]}))

The service accepts it only if: the signer is registered; the session is new
(and then ``a == 0`` and ``prev_head`` is GENESIS) or belongs to that signer and
continues exactly where the stored head is; every event is a valid §4 event of
that session at its position, later than the one before; and the events chain
from ``prev_head`` through every one of ``heads`` to ``head``. Otherwise it
refuses and says why, naming the event at which the batch breaks the chain. It
never accepts a rewrite: a position is held once.

An accepted batch is stored whole, content-addressed, in the journal, and a
``batch`` entry -- session, signer, span, head, the last event's timestamp, the
batch's digest, and the server timestamp -- is appended to the log. The receipt for that entry is the
signed receipt SPEC.md §5 requires: it binds the new head to a server
timestamp under the service's key. Sending the identical batch again returns
the original receipt; a different batch at a held position is refused.

**Stateless.** Every piece of state below -- keys, session heads, accepted
batches -- is derived from the log's leaves, so any process can rebuild it from
the journal, and `append`'s create-if-absent decides every race. A leaf no
verified checkpoint covers, written by another process, is admitted only if it
passes the checks ingest would have made on it (`_admit`), so a leaf planted in
the journal by someone without the service key is refused, not signed over.

**Session ids** are one namespace, and a session belongs to the key that sent
its event 0. Clients name sessions with unguessable ids (Claude Code's session
UUIDs), so taking one first needs the id before its owner's first batch lands.
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from crucible_chain.chain import GENESIS, replay
from crucible_chain.export import FORMAT, dumps, loads
from crucible_core.canonical import CanonicalizationError, canonicalize, is_digest, sha256_bytes
from crucible_core.cose import SignatureError, decode, verify
from crucible_core.keys import KeyError_, PublicKey

from crucible_verify.report import Report, verify_record

from .journal import JournalError
from .log import Appended, LogError, ReceiptPending, Refusal, TransparencyLog

BATCH_FIELDS = frozenset({"v", "kind", "session", "from_seq", "to_seq", "prev_head", "head", "events", "heads"})
BATCH_LEAF_FIELDS = frozenset({"session", "key_id", "from_seq", "to_seq", "head", "last_ts", "batch"})
REGISTER_LEAF_FIELDS = frozenset({"key_id", "public_key", "registration"})
ENTRY_FIELDS = frozenset({"v", "kind", "ts", "payload"})
MAX_FACTS = 32
MAX_FACT = 256
MAX_BATCH_EVENTS = 1000


@dataclass(frozen=True)
class SessionRecord:
    """A session as the journal holds it: its events, the receipts for its
    batches, and the count and head its last batch entry declares."""

    session: str
    records: list[dict]
    receipts: list[dict]
    count: int
    head: str

    def export(self) -> str:
        """The record in crucible-chain/2 form, for any verifier to re-run."""
        header = {"kind": "header", "format": FORMAT, "session": self.session, "count": self.count, "head": self.head}
        lines = [{"to_seq": rc["entry"]["payload"]["to_seq"], "receipt": rc} for rc in self.receipts]
        return dumps(self.session, self.records, lines, header=header)

    def verify(self, service_key: PublicKey) -> Report:
        """SPEC.md §7 over this record's export, read back as ``crucible-verify`` reads it,
        so the service's verdict and the CLI's are over the same bytes."""
        ex = loads(self.export())
        return verify_record(ex.records, [x["receipt"] for x in ex.receipts], service_key=service_key,
                             session=ex.header["session"], declared_count=ex.header["count"], declared_head=ex.header["head"])


@dataclass
class SessionState:
    key_id: str
    next_seq: int
    head: str
    last_ts: int


def _int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _b64(text: object, what: str) -> bytes:
    if not isinstance(text, str):
        raise Refusal("malformed_request", f"{what} must be a base64 string", 400)
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Refusal("malformed_request", f"{what} is not base64: {exc}", 400) from exc


MAX_DEPTH = 64
#: A batch holds its events two levels down ({..., "events": [event, ...]}), so it
#: may nest two deeper than an event may (crucible_chain.events.MAX_DEPTH).
BATCH_DEPTH = MAX_DEPTH + 2
#: About 5.5 kB a receipt at 1,500 leaves, growing with log n (some 90 MB when full); a session
#: of more batches than this rebuilds its receipts per read.
RECEIPT_CACHE = 16384


def _nests_deeper(data: bytes, limit: int = MAX_DEPTH) -> bool:
    """Whether JSON text nests deeper than ``limit``, decided without parsing it, so the
    answer does not depend on how deep the caller's stack already is."""
    depth, in_string, escaped = 0, False, False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # quote
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):  # [ {
            depth += 1
            if depth > limit:
                return True
        elif byte in (0x5D, 0x7D):
            depth -= 1
    return False


def _release_payload(p: object) -> bool:
    return (isinstance(p, dict) and set(p) == {"tag", "digest"} and isinstance(p["tag"], str)
            and 0 < len(p["tag"]) <= 128 and is_digest(p["digest"]))


def _host_payload(p: object) -> bool:
    facts = p.get("facts") if isinstance(p, dict) else None
    return (isinstance(p, dict) and set(p) == {"facts"} and isinstance(facts, dict) and len(facts) <= MAX_FACTS
            and all(isinstance(k, str) and 0 < len(k) <= 64 and isinstance(v, str) and len(v) <= MAX_FACT
                    for k, v in facts.items()))


def _signed_payload(raw: bytes, key: PublicKey, what: str) -> dict:
    try:
        env = verify(raw, key)
    except SignatureError as exc:
        raise Refusal("bad_signature", f"the {what} is not signed by key {key.key_id}: {exc}", 401) from exc
    limit = BATCH_DEPTH if what == "batch" else MAX_DEPTH
    if _nests_deeper(env.payload_bytes, limit):
        raise Refusal("malformed_request", f"the signed {what} nests deeper than {limit} levels", 400)
    try:
        payload = json.loads(env.payload_bytes)
        canonical = canonicalize(payload)
    except (ValueError, CanonicalizationError, RecursionError) as exc:
        raise Refusal("malformed_request", f"the signed {what} is not JSON: {exc}", 400) from exc
    if canonical != env.payload_bytes:
        raise Refusal("malformed_request", f"the signed {what} is not in canonical form", 400)
    if not isinstance(payload, dict):
        raise Refusal("malformed_request", f"the signed {what} is not an object", 400)
    return payload


class Service:
    """The ingest state machine over one log."""

    def __init__(self, log: TransparencyLog) -> None:
        self.log = log
        self.keys: dict[str, PublicKey] = {}
        self.key_leaf: dict[str, int] = {}
        self.sessions: dict[str, SessionState] = {}
        self.batches: dict[str, int] = {}
        self.session_batches: dict[str, list[int]] = {}
        self._receipts: OrderedDict[int, dict] = OrderedDict()  # least recently used first
        self.latest_release: dict | None = None
        self.latest_host: dict | None = None
        log.attach(self._admit, self._observe)

    def _observe(self, index: int, entry: dict) -> None:
        try:
            self._index(index, entry)
        except (KeyError, TypeError, ValueError, KeyError_) as exc:
            raise LogError(f"leaf {index} is not an entry this service writes: {exc}") from exc

    def _admit(self, index: int, entry: dict) -> None:
        """Re-run ingest's checks on a leaf another process wrote, before adopting it."""
        try:
            self._admissible(index, entry)
        except Refusal as exc:
            raise LogError(f"leaf {index} would have been refused: {exc.detail}") from exc
        except (KeyError, TypeError, ValueError, AttributeError, KeyError_, SignatureError) as exc:
            raise LogError(f"leaf {index} is not an entry this service writes: {exc}") from exc

    def _admissible(self, index: int, entry: dict) -> None:
        p = entry.get("payload")
        ts = entry.get("ts")
        if set(entry) != ENTRY_FIELDS or entry["v"] != 2 or not isinstance(p, dict) or not (_int(ts) and 0 < ts <= 2**53 - 1):
            raise LogError(f"leaf {index} is not a version 2 entry")
        for name in ("batch", "registration"):
            if name in p and not is_digest(p[name]):
                raise LogError(f"leaf {index} names its {name} by something that is not a digest")
        kind = entry["kind"]
        if kind == "service":
            if index != 0:
                raise LogError(f"leaf {index} is a second service entry")
        elif kind == "register":
            if set(p) != REGISTER_LEAF_FIELDS:
                raise LogError(f"leaf {index} is not a registration entry")
            raw = self.log.get_object(p["registration"])
            if raw is None:
                raise LogError(f"the registration for leaf {index} is not in the journal")
            key = self._registration_key(raw)
            if key.key_id != p["key_id"] or key.to_dict() != p["public_key"] or key.key_id in self.key_leaf:
                raise LogError(f"leaf {index} does not record the registration it names")
        elif kind == "release":
            if not _release_payload(p):
                raise LogError(f"leaf {index} is not a release entry")
        elif kind == "host":
            if not _host_payload(p):
                raise LogError(f"leaf {index} is not a host entry")
        elif kind == "batch":
            if set(p) != BATCH_LEAF_FIELDS:
                raise LogError(f"leaf {index} is not a batch entry")
            raw = self.log.get_object(p["batch"])
            if raw is None:
                raise LogError(f"the batch for leaf {index} is not in the journal")
            kid = decode(raw).key_id
            key = self.keys.get(kid)
            if key is None or kid != p["key_id"]:
                raise LogError(f"the batch for leaf {index} is not signed by a key registered before it")
            batch = _signed_payload(raw, key, "batch")
            self._check_shape(batch)
            said = {k: batch[k] for k in ("session", "from_seq", "to_seq", "head")} | {"last_ts": batch["events"][-1]["ts"]}
            if any(p[k] != v for k, v in said.items()) or p["batch"] != sha256_bytes(raw):
                raise LogError(f"leaf {index} does not record the batch it names")
            self._check_continuity(batch, kid)
        else:
            raise LogError(f"leaf {index} is of kind {kind!r}, which this service does not write")

    def _index(self, index: int, entry: dict) -> None:
        kind, p = entry.get("kind"), entry.get("payload") or {}
        if kind == "register":
            key = PublicKey.from_dict(p["public_key"])
            self.keys[key.key_id] = key
            self.key_leaf[key.key_id] = index
        elif kind == "release":
            self.latest_release = p
        elif kind == "host":
            self.latest_host = p
        elif kind == "batch":
            self.sessions[p["session"]] = SessionState(p["key_id"], p["to_seq"] + 1, p["head"], p["last_ts"])
            self.batches[p["batch"]] = index
            self.session_batches.setdefault(p["session"], []).append(index)

    # --- the release and the platform it runs on (SPEC.md §5 Deployment) ----------
    def record_release(self, tag: str, digest: str) -> int | None:
        """Append a ``release`` entry if ``digest`` is not the log's latest release.

        Deploying a new release is the recorded act: a different digest -- a
        rollback included -- is recorded; restarting the same one is not.
        """
        payload = {"tag": tag, "digest": digest}
        if not _release_payload(payload):
            raise ValueError("a release is a tag (at most 128 characters) and a sha256 image digest")
        return self._record("release", payload, lambda: (self.latest_release or {}).get("digest") == digest)

    def record_host(self, facts: dict) -> int | None:
        """Append a ``host`` entry if the platform's facts differ from the log's latest."""
        payload = {"facts": dict(facts)}
        if not _host_payload(payload):
            raise ValueError(f"host facts are at most {MAX_FACTS} names, each mapped to a string")
        return self._record("host", payload, lambda: self.latest_host == payload)

    def _record(self, kind: str, payload: dict, unchanged) -> int | None:
        def build(log: TransparencyLog):
            if unchanged():
                return Appended(-1, {})
            return {"kind": kind, "payload": payload}

        appended = self.log.append(build)
        return None if appended.index < 0 else appended.index

    # --- registration -------------------------------------------------------------
    @staticmethod
    def _registration_key(raw: bytes) -> PublicKey:
        """The researcher key a signed registration registers, once it proves possession."""
        try:
            body = decode(raw).payload_bytes
            if _nests_deeper(body):
                raise ValueError(f"it nests deeper than {MAX_DEPTH} levels")
            payload = json.loads(body)
            key = PublicKey.from_dict(payload["public_key"])
        except (SignatureError, ValueError, KeyError, TypeError, KeyError_, RecursionError) as exc:
            raise Refusal("malformed_request", f"not a key registration: {exc}", 400) from exc
        if key.role != "researcher":
            raise Refusal("malformed_request", f"only researcher keys register, not {key.role} keys", 400)
        payload = _signed_payload(raw, key, "registration")
        if set(payload) != {"v", "kind", "public_key"} or payload["v"] != 2 or payload["kind"] != "register":
            raise Refusal("malformed_request", 'a registration is {"v": 2, "kind": "register", "public_key"}', 400)
        if payload["public_key"] != key.to_dict():  # the key exactly as it reads back: nothing else rides along
            raise Refusal("malformed_request", "a registration's public_key is the key's own form, and only that", 400)
        return key

    def register(self, envelope_b64: object, *, admit: Callable[[], None] | None = None) -> dict:
        """``admit()`` runs, and may refuse, only for a key this log does not hold yet: a
        registration that would append a leaf (a rate limit; a re-registration is free)."""
        raw = _b64(envelope_b64, "registration")
        key = self._registration_key(raw)
        self.log.refresh()
        if key.key_id in self.key_leaf:  # held already: its receipt, and nothing written
            return self.receipt_for(self.key_leaf[key.key_id])
        if admit is not None:
            admit()
        digest = self.log.put_object(raw)  # before the leaf that names it, as for a batch

        def build(log: TransparencyLog):
            if key.key_id in self.key_leaf:
                i = self.key_leaf[key.key_id]
                return Appended(i, log.entries[i])
            payload = {"key_id": key.key_id, "public_key": key.to_dict(), "registration": digest}
            return {"kind": "register", "payload": payload}

        return self.receipt_for(self.log.append(build).index)

    # --- ingest -------------------------------------------------------------------
    def ingest(self, envelope_b64: object, *, admit: Callable[[str], None] | None = None) -> dict:
        """``admit(key_id)`` runs, and may refuse, once the batch is known to be signed by a
        registered key and is not an exact resend: a per-key limit no forger can spend."""
        raw = _b64(envelope_b64, "batch")
        try:
            kid = decode(raw).key_id
        except SignatureError as exc:
            raise Refusal("malformed_request", f"not a signed batch: {exc}", 400) from exc
        self.log.refresh()
        key = self.keys.get(kid)
        if key is None:
            raise Refusal("unregistered_key", f"key {kid} is not registered with this service", 403)
        batch = _signed_payload(raw, key, "batch")
        self._check_shape(batch)
        digest = sha256_bytes(raw)

        def build(log: TransparencyLog):
            if digest in self.batches:  # the exact batch again: its original receipt
                i = self.batches[digest]
                return Appended(i, log.entries[i])
            self._check_continuity(batch, kid)
            return {
                "kind": "batch",
                "payload": {
                    "session": batch["session"],
                    "key_id": kid,
                    "from_seq": batch["from_seq"],
                    "to_seq": batch["to_seq"],
                    "head": batch["head"],
                    "last_ts": batch["events"][-1]["ts"],
                    "batch": digest,
                },
            }

        if digest in self.batches:  # the exact batch again, before any other check
            return self.receipt_for(self.batches[digest])
        if admit is not None:
            admit(kid)
        # Refuse a bad batch before storing anything. The object is written
        # before the leaf that names it, so every leaf's batch is always there
        # to read; `build` checks again against the state it appends to, and a
        # batch whose leaf then loses leaves an unreferenced object, which costs
        # only space.
        self._check_continuity(batch, kid)
        self.log.put_object(raw)
        return self.receipt_for(self.log.append(build).index)

    def receipt_for(self, index: int, *, refresh: bool = True) -> dict:
        """Leaf ``index``'s receipt; for a batch, with the proof that the log only
        grew since the session's previous batch. Receipts never change once
        issued, so each is built once and handed out as a copy."""
        with self.log._lock:
            if index in self._receipts:
                self._receipts.move_to_end(index)
                return copy.deepcopy(self._receipts[index])
            if refresh:
                self.log.refresh()
            entry = self.log.entries[index] if 0 <= index < self.log.size else None
            previous = None
            if entry is not None and entry.get("kind") == "batch":
                held = self.session_batches.get(entry["payload"]["session"], [])
                at = held.index(index)
                previous = held[at - 1] + 1 if at else None
            try:
                receipt = self.log.receipt(index, consistency_from=previous)
            except JournalError as exc:  # the entry is in the log; only its checkpoint is not signed yet
                if entry is None:
                    raise
                raise ReceiptPending(index, f"the entry is at leaf {index}, but its checkpoint could not be signed: {exc}") from exc
            self._receipts[index] = receipt
            while len(self._receipts) > RECEIPT_CACHE:
                self._receipts.popitem(last=False)  # rebuilt, byte for byte, when asked again
            return copy.deepcopy(receipt)

    def _check_shape(self, b: dict) -> None:
        if set(b) != BATCH_FIELDS or b.get("v") != 2 or b.get("kind") != "batch":
            raise Refusal("malformed_request", f"a batch has fields {sorted(BATCH_FIELDS)}", 400)
        a, z, events = b["from_seq"], b["to_seq"], b["events"]
        if not (_int(a) and _int(z) and 0 <= a <= z):
            raise Refusal("malformed_request", "from_seq and to_seq must be integers with from_seq <= to_seq", 400)
        if not (isinstance(events, list) and len(events) == z - a + 1):
            raise Refusal("malformed_request", f"a batch from {a} to {z} carries {z - a + 1} events", 400)
        if len(events) > MAX_BATCH_EVENTS:
            raise Refusal("malformed_request", f"a batch carries at most {MAX_BATCH_EVENTS} events", 400)
        if not (isinstance(b["session"], str) and is_digest(b["prev_head"]) and is_digest(b["head"])):
            raise Refusal("malformed_request", "session must be a string, prev_head and head digests", 400)
        hs = b["heads"]
        if not (isinstance(hs, list) and len(hs) == len(events) and all(isinstance(h, str) and is_digest(h) for h in hs)):
            raise Refusal("malformed_request", "heads must be one digest per event", 400)
        if hs[-1] != b["head"]:
            raise Refusal("malformed_request", "head must be the last of heads", 400)

    def _check_continuity(self, b: dict, kid: str) -> None:
        s, a = b["session"], b["from_seq"]
        held = self.sessions.get(s)
        if held is None:
            expected_seq, expected_head, prev_ts = 0, GENESIS, None
        else:
            if held.key_id != kid:
                raise Refusal("session_owner", f"session {s} belongs to key {held.key_id}, not {kid}", 403)
            expected_seq, expected_head, prev_ts = held.next_seq, held.head, held.last_ts
        if a != expected_seq:
            if a < expected_seq:
                raise Refusal(
                    "position_held",
                    f"session {s} already holds events up to {expected_seq - 1}; a different batch at {a} is a rewrite",
                    409, next_expected_seq=expected_seq,
                )
            raise Refusal("chain_break", f"session {s} continues at event {expected_seq}, not {a}", 409,
                          at=expected_seq, next_expected_seq=expected_seq)
        if b["prev_head"] != expected_head:
            raise Refusal("chain_break", f"the batch continues from head {b['prev_head']}; session {s}'s head is {expected_head}",
                          409, at=a, next_expected_seq=expected_seq)
        records = [
            {"seq": e.get("seq") if isinstance(e, dict) else None, "head": h, "event": e}
            for e, h in zip(b["events"], b["heads"])
        ]
        r = replay(records, start=expected_head, first_seq=a, prev_ts=prev_ts, session=s, declared_head=b["head"])
        if r.uncheckable:
            raise Refusal("chain_break", r.uncheckable, 409, at=r.count, next_expected_seq=expected_seq)
        if not r.intact:
            raise Refusal("chain_break", f"the batch breaks the chain at event {r.broken_at}: {r.reason}", 409,
                          at=r.broken_at, next_expected_seq=expected_seq)

    # --- reading ----------------------------------------------------------------------
    def session_record(self, session: str) -> SessionRecord | None:
        """The session as the journal holds it, or None if it holds no batch of it.

        Read from the journal's batch objects and leaves, not from any state
        kept beside them: the count and head are the ones the last batch entry
        declares. Each batch is read back as ingest would have accepted it --
        present, signed by its key, canonical, of the batch's shape, and saying
        what its entry says -- and the record ends at the first batch that is
        not, so a batch object missing or changed shows as a break where it
        begins, not as an error or a shorter intact record. Every batch's
        receipt is kept, so the receipts still show what was sealed.

        A leaf in the journal that this service will not adopt is not part of
        the log; the record is read from the leaves it holds.
        """
        try:
            self.log.refresh()
        except LogError:
            pass
        with self.log._lock:  # a snapshot: a batch landing meanwhile is not half in the record
            leaves = list(self.session_batches.get(session, []))
        if not leaves:
            return None
        records, receipts, whole = [], [], True
        for i in leaves:
            p = self.log.entries[i]["payload"]
            receipts.append(self.receipt_for(i, refresh=False))
            if not whole:
                continue
            held = self._held_events(p)
            records += [{"seq": p["from_seq"] + k, "head": h, "event": e} for k, (e, h) in enumerate(held)]
            whole = len(held) == p["to_seq"] - p["from_seq"] + 1
        last = self.log.entries[leaves[-1]]["payload"]
        return SessionRecord(session, records, receipts, last["to_seq"] + 1, last["head"])

    def _held_events(self, p: dict) -> list[tuple[dict, str]]:
        """The (event, head) pairs of the batch a leaf names, as far as it reads as ingest accepted it."""
        try:
            raw = self.log.get_object(p["batch"])
            key = self.keys.get(p["key_id"])
            if raw is None or key is None:
                return []
            batch = _signed_payload(raw, key, "batch")
            self._check_shape(batch)
        except (LogError, Refusal, SignatureError):
            return []
        if any(batch[k] != p[k] for k in ("session", "from_seq", "to_seq", "head")):
            return []
        held = []
        for e, h in zip(batch["events"], batch["heads"]):
            if not isinstance(e, dict):
                break
            held.append((e, h))
        return held


__all__ = ["BATCH_FIELDS", "Refusal", "Service", "SessionRecord", "SessionState"]
