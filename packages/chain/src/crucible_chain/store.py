"""The client's local chain store: one SQLite file holding every session's chain.

Append-only is enforced three ways, as in v1's ledger store:

1. **Triggers** raise on any ``UPDATE`` or ``DELETE`` of an event or receipt,
   and on an ``INSERT`` at a position already held -- which is how ``INSERT OR
   REPLACE`` and ``REPLACE INTO`` would otherwise rewrite a row without firing
   the delete trigger. This holds even against the ``sqlite3`` shell, the
   realistic accident.
2. **The primary key** ``(session, seq)`` makes re-inserting a position an
   error.
3. **`append`** takes an ``IMMEDIATE`` transaction, so hooks running as
   separate, concurrent processes cannot read the same head and mint the same
   position.

`append` assigns the chain fields itself: ``seq`` is the next position, and
``ts`` is the clock in microseconds or one microsecond after the previous
event, whichever is later, so the timestamp is monotonic even when the wall
clock steps back.

Receipts are the service's answers to sent batches (SPEC.md §3 Sending). An
event with no receipt covering it is unsent; that is the sender's queue.

Whole-file replacement is still possible for someone with the file. That is
what the service's copy and its receipts are for: the local store defends
against revision, not replacement.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from crucible_core.canonical import CanonicalizationError, canonicalize

from .chain import GENESIS, link
from .events import MAX_SAFE_INT, PROTOCOL_VERSION, validate, validate_draft

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    session TEXT    NOT NULL,
    seq     INTEGER NOT NULL,
    ts      INTEGER NOT NULL,
    head    TEXT    NOT NULL,
    type    TEXT    NOT NULL,
    event   TEXT    NOT NULL,
    PRIMARY KEY (session, seq)
);

CREATE TABLE IF NOT EXISTS receipts (
    session TEXT    NOT NULL,
    to_seq  INTEGER NOT NULL,
    receipt TEXT    NOT NULL,
    PRIMARY KEY (session, to_seq)
);

CREATE TRIGGER IF NOT EXISTS events_no_replace BEFORE INSERT ON events
WHEN EXISTS (SELECT 1 FROM events WHERE session = NEW.session AND seq = NEW.seq)
BEGIN SELECT RAISE(ABORT, 'crucible: the chain is append-only'); END;
CREATE TRIGGER IF NOT EXISTS receipts_no_replace BEFORE INSERT ON receipts
WHEN EXISTS (SELECT 1 FROM receipts WHERE session = NEW.session AND to_seq = NEW.to_seq)
BEGIN SELECT RAISE(ABORT, 'crucible: receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'crucible: the chain is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'crucible: the chain is append-only'); END;
CREATE TRIGGER IF NOT EXISTS receipts_no_update BEFORE UPDATE ON receipts
BEGIN SELECT RAISE(ABORT, 'crucible: receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS receipts_no_delete BEFORE DELETE ON receipts
BEGIN SELECT RAISE(ABORT, 'crucible: receipts are append-only'); END;
"""


class StoreError(Exception):
    """A schema mismatch or an append-only violation."""


@dataclass(frozen=True)
class Record:
    """One stored event with its head."""

    seq: int
    head: str
    event: dict

    def as_record(self) -> dict:
        """The ``{"seq", "head", "event"}`` shape `chain.replay` reads."""
        return {"seq": self.seq, "head": self.head, "event": self.event}


class ChainStore:
    """Every session's chain, in one file."""

    def __init__(self, path: Path | str, *, clock: Callable[[], int] = lambda: time.time_ns() // 1000) -> None:
        self.path = Path(path)
        self._clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, isolation_level=None, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        # The busy timeout does not cover switching a fresh file to WAL: hooks
        # that open a new store at the same moment would fail with "database is
        # locked". Retry that one statement, within the same budget.
        self._retry_locked(lambda: self._conn.execute("PRAGMA journal_mode = WAL"))
        self._conn.execute("PRAGMA synchronous = FULL")
        self._retry_locked(lambda: self._conn.executescript(_SCHEMA))
        self._retry_locked(self._init_meta)

    @staticmethod
    def _retry_locked(fn, budget: float = 30.0):
        deadline = time.monotonic() + budget
        delay = 0.005
        while True:
            try:
                return fn()
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc) and "busy" not in str(exc):
                    raise
                if time.monotonic() >= deadline:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 0.25)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> ChainStore:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _init_meta(self) -> None:
        with self._immediate():
            row = self._conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO meta(key, value) VALUES('schema_version', ?), ('protocol_version', ?)",
                    (str(SCHEMA_VERSION), str(PROTOCOL_VERSION)),
                )
                return
        if int(row["value"]) != SCHEMA_VERSION:
            raise StoreError(f"{self.path} uses store schema v{row['value']}; this build speaks v{SCHEMA_VERSION}")

    @contextmanager
    def _immediate(self) -> Iterator[sqlite3.Connection]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield self._conn
        except BaseException:
            # SQLite rolls back on its own after SQLITE_FULL, SQLITE_IOERR and
            # SQLITE_NOMEM; an unconditional ROLLBACK would then raise and hide
            # the disk error that actually needs to be seen.
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
            raise
        else:
            self._conn.execute("COMMIT")

    # --- events --------------------------------------------------------------
    def append(self, session: str, draft: dict) -> Record:
        """Place ``draft`` at the end of ``session``'s chain and store it."""
        return self.append_all(session, [draft])[0]

    def append_all(self, session: str, drafts: list[dict]) -> list[Record]:
        """Place ``drafts`` at the end of ``session``'s chain, consecutively, in one
        transaction: nothing another writer appends can land between them."""
        for d in drafts:
            validate_draft(d)
        out = []
        with self._immediate():
            last = self._conn.execute(
                "SELECT seq, ts, head FROM events WHERE session = ? ORDER BY seq DESC LIMIT 1",
                (session,),
            ).fetchone()
            seq, ts, head = (-1, 0, GENESIS) if last is None else (last["seq"], last["ts"], last["head"])
            for d in drafts:
                seq, ts = seq + 1, max(self._clock(), ts + 1)
                event = {**d, "v": PROTOCOL_VERSION, "session": session, "seq": seq, "ts": ts}
                validate(event)
                head = link(head, event)
                text = canonicalize(event).decode("utf-8")
                try:
                    self._conn.execute(
                        "INSERT INTO events(session, seq, ts, head, type, event) VALUES(?,?,?,?,?,?)",
                        (session, seq, ts, head, event["type"], text),
                    )
                except sqlite3.IntegrityError as exc:
                    raise StoreError(f"cannot append {session}#{seq}: {exc}") from exc
                # Hand back what was stored, read back, so the caller never holds a
                # value the store cannot reproduce.
                out.append(Record(seq=seq, head=head, event=json.loads(text)))
        return out

    def head(self, session: str) -> Record | None:
        row = self._conn.execute(
            "SELECT seq, head, event FROM events WHERE session = ? ORDER BY seq DESC LIMIT 1", (session,)
        ).fetchone()
        return _record(row) if row else None

    def records(self, session: str, from_seq: int = 0, limit: int | None = None) -> list[Record]:
        rows = self._conn.execute(
            "SELECT seq, head, event FROM events WHERE session = ? AND seq >= ? ORDER BY seq LIMIT ?",
            (session, from_seq, -1 if limit is None else limit),
        ).fetchall()
        return [_record(r) for r in rows]

    def record(self, session: str, seq: int) -> Record | None:
        row = self._conn.execute("SELECT seq, head, event FROM events WHERE session = ? AND seq = ?", (session, seq)).fetchone()
        return _record(row) if row else None

    def sessions(self) -> list[str]:
        return [r["session"] for r in self._conn.execute("SELECT DISTINCT session FROM events ORDER BY session")]

    # --- receipts --------------------------------------------------------------
    def add_receipt(self, session: str, to_seq: int, receipt: dict) -> None:
        """Record the service's receipt for ``session`` up to and including ``to_seq``.

        ``to_seq`` must be a held event after the last receipted one: a receipt
        claiming events the store does not hold would silently empty the
        sender's queue. Storing a byte-identical receipt again is a no-op (an
        exact resend gets its original receipt back); a different receipt for
        the same span is refused.
        """
        if not (isinstance(to_seq, int) and not isinstance(to_seq, bool) and 0 <= to_seq <= MAX_SAFE_INT):
            raise StoreError(f"to_seq must be an event number, not {to_seq!r}")
        # Filed under its own signed span, or the store's own export would refuse it on read.
        entry = receipt.get("entry") if isinstance(receipt, dict) else None
        signed = entry.get("payload") if isinstance(entry, dict) else None
        if isinstance(signed, dict):
            if "to_seq" in signed and signed["to_seq"] != to_seq:
                raise StoreError(f"the receipt is signed for events up to {signed['to_seq']!r}, not {to_seq}")
            if "session" in signed and signed["session"] != session:
                raise StoreError(f"the receipt is for session {signed['session']!r}, not {session!r}")
        try:
            text = canonicalize(receipt).decode("utf-8")
            if canonicalize(json.loads(text)).decode("utf-8") != text:
                raise CanonicalizationError("it does not survive a JCS round trip byte for byte")
        except (CanonicalizationError, ValueError) as exc:
            raise StoreError(f"the receipt is not JCS-serializable: {exc}") from exc
        with self._immediate():
            held = self._conn.execute(
                "SELECT receipt FROM receipts WHERE session = ? AND to_seq = ?", (session, to_seq)
            ).fetchone()
            if held is not None:
                if held["receipt"] == text:
                    return
                raise StoreError(f"a different receipt for {session} up to {to_seq} is already held")
            last = self._conn.execute("SELECT MAX(to_seq) AS m FROM receipts WHERE session = ?", (session,)).fetchone()["m"]
            head = self._conn.execute("SELECT MAX(seq) AS m FROM events WHERE session = ?", (session,)).fetchone()["m"]
            if head is None:
                raise StoreError(f"no events are held for {session}, so no receipt can cover any")
            low = -1 if last is None else last
            if not (low < to_seq <= head):
                raise StoreError(
                    f"a receipt for {session} up to {to_seq} is outside the unreceipted events {low + 1}..{head}"
                )
            self._conn.execute(
                "INSERT INTO receipts(session, to_seq, receipt) VALUES(?,?,?)", (session, to_seq, text)
            )

    def receipts(self, session: str) -> list[tuple[int, dict]]:
        rows = self._conn.execute(
            "SELECT to_seq, receipt FROM receipts WHERE session = ? ORDER BY to_seq", (session,)
        ).fetchall()
        return [(r["to_seq"], json.loads(r["receipt"])) for r in rows]

    def last_receipted_seq(self, session: str) -> int:
        """The highest seq a held receipt covers, or -1."""
        row = self._conn.execute("SELECT MAX(to_seq) AS m FROM receipts WHERE session = ?", (session,)).fetchone()
        return -1 if row["m"] is None else row["m"]

    def unsent(self, session: str, limit: int | None = None) -> list[Record]:
        """Events no held receipt covers: the sender's queue for ``session`` (its first ``limit``)."""
        return self.records(session, self.last_receipted_seq(session) + 1, limit)


def _record(row: sqlite3.Row) -> Record:
    return Record(seq=row["seq"], head=row["head"], event=json.loads(row["event"]))


__all__ = ["ChainStore", "Record", "StoreError"]
