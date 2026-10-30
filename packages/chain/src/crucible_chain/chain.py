"""The per-session hash chain (SPEC.md §3 Sealing, §4 Chain).

    h_n = SHA-256( h_{n-1} || JCS(event_n) )

``h_{n-1}`` enters as its 32 raw bytes; the first event links to ``GENESIS``,
32 zero bytes. Heads are carried as ``"sha256:<hex>"``.

A session's first event will carry the previous session's final head for the
same study once phase 1 adds the study declaration (SPEC.md §4, §9); in phase 0
every session starts from ``GENESIS``.

`replay` walks a chain and names the first event at which it stops being the
chain it claims to be. That event number is what SPEC.md §7 reports as
"broken at event N".
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from crucible_core.canonical import CanonicalizationError, canonicalize, digest_hex, is_digest

from .events import PROTOCOL_VERSION, EventError, validate

GENESIS = "sha256:" + "00" * 32


def link(prev: str, event: dict) -> str:
    """The head after appending ``event`` to a chain whose head is ``prev``."""
    return "sha256:" + hashlib.sha256(digest_hex(prev) + canonicalize(event)).hexdigest()


def heads(events: Iterable[dict], start: str = GENESIS) -> list[str]:
    """Every head along ``events``, in order."""
    out, prev = [], start
    for e in events:
        prev = link(prev, e)
        out.append(prev)
    return out


@dataclass(frozen=True)
class Replay:
    """What a chain replay found.

    ``broken_at`` is the first event number at which the chain fails, or None.
    ``uncheckable`` is set instead when the chain's first event is in a
    protocol version this code does not read: that is ``could_not_check``, not a
    break (SPEC.md §4 Honesty rule). A chain is written in one version, the one
    its event 0 names, so a later event in another version is a break there:
    relabelling a tampered event cannot turn its break into could_not_check. ``count`` and ``head`` always describe the same intact
    prefix: ``count`` events, ending at ``head``.
    """

    count: int
    head: str
    broken_at: int | None = None
    reason: str | None = None
    uncheckable: str | None = None
    #: The rule that broke: seq, ts, session, head, record, truncated,
    #: declared-head, count, or event.<field> for an invalid event.
    rule: str | None = None

    @property
    def intact(self) -> bool:
        return self.broken_at is None and self.uncheckable is None


def _bad_count(value: object) -> bool:
    return not (isinstance(value, int) and not isinstance(value, bool) and value >= 0)


def replay(
    records: Sequence[dict],
    *,
    start: str = GENESIS,
    first_seq: int = 0,
    prev_ts: int | None = None,
    session: str | None = None,
    declared_count: int | None = None,
    declared_head: str | None = None,
) -> Replay:
    """Replay ``records`` (each ``{"seq", "event"}`` and optionally ``"head"``).

    A whole chain starts at seq 0 from ``GENESIS``. A batch continuing a chain
    starts at ``first_seq`` from ``start``, the head before it, and its first
    event must be later than ``prev_ts``. ``count`` and ``broken_at`` are event
    numbers in the chain, not positions in ``records``.

    Stored heads are all or none: if any record carries ``head``, one without
    it is a break, so dropping a head cannot move where a break is reported.

    Checked at every position N, in this order: the record is where N belongs;
    the event is in this protocol version (at event 0, else ``uncheckable``) and a valid §4
    event, at seq N, in the same session as the rest, and later than its
    predecessor; and its head is ``link(h_{N-1}, event_N)``. Then the declared
    count and head, if given, must match what was replayed: a declared count
    beyond the records is a truncated tail, broken at the first missing event.
    """
    if declared_count is not None and _bad_count(declared_count):
        raise ValueError(f"declared_count must be a non-negative integer, not {declared_count!r}")
    walk = list(records)
    overlong = declared_count is not None and declared_count < first_seq + len(walk)
    if overlong:
        walk = walk[: max(declared_count - first_seq, 0)]
    headed = any(isinstance(r, dict) and "head" in r for r in walk)
    prev = start
    for i, rec in enumerate(walk):
        n = first_seq + i

        def broken(reason: str, rule: str, at: int = n) -> Replay:
            return Replay(count=n, head=prev, broken_at=at, reason=reason, rule=rule)

        if not isinstance(rec, dict) or not isinstance(rec.get("event"), dict):
            return broken(f"record {n} is not a chain record", "record")
        event = rec["event"]
        version = event.get("v")
        if n == 0 and isinstance(version, int) and not isinstance(version, bool) and version != PROTOCOL_VERSION:
            return Replay(count=n, head=prev, uncheckable=f"event {n} is in protocol version {version}, which this code does not read")
        try:
            validate(event)
        except EventError as exc:
            field = str(exc).split(":", 1)[0].strip() or "event"
            return broken(f"event {n} is not a valid §4 event: {exc}", f"event.{field}")
        rec_seq = rec.get("seq", event["seq"])
        if rec_seq != n or event["seq"] != n:
            found = event["seq"] if event["seq"] != n else rec_seq
            later = any(isinstance(r, dict) and isinstance(r.get("event"), dict) and r["event"].get("seq") == n for r in walk[i + 1 :])
            if later:
                return broken(f"seq: expected event {n}, found event {found}; event {n} is out of order", "seq")
            if isinstance(found, int) and found > n:
                return broken(f"seq: expected event {n}, found event {found}; event {n} is missing", "seq")
            return broken(f"seq: expected event {n}, found {found!r}", "seq")
        if session is None:
            session = event["session"]
        elif event["session"] != session:
            return broken(f"session: event {n} belongs to {event['session']!r}, not {session!r}", "session")
        if prev_ts is not None and event["ts"] <= prev_ts:
            return broken(f"ts: event {n} at {event['ts']} is not later than the event before it at {prev_ts}", "ts")
        try:
            head = link(prev, event)
        except (CanonicalizationError, ValueError) as exc:
            return broken(f"event {n} cannot be hashed: {exc}", "event.hash")
        if headed:
            stored = rec.get("head")
            if stored != head:
                shown = stored if isinstance(stored, str) and is_digest(stored) else repr(stored)
                return broken(f"head: event {n} hashes to {head}, the record says {shown}", "head")
        prev, prev_ts = head, event["ts"]

    count = first_seq + len(walk)
    if overlong:
        return Replay(count, prev, broken_at=count, reason=f"{first_seq + len(records)} events present, {declared_count} declared", rule="count")
    if declared_count is not None and declared_count > count:
        return Replay(count, prev, broken_at=count, reason=f"truncated: {declared_count} events declared, {count} present", rule="truncated")
    if declared_head is not None and declared_head != prev:
        if not walk:
            return Replay(count, prev, broken_at=count, reason=f"declared head {declared_head} is not the replayed head {prev}", rule="declared-head")
        last = count - 1
        before = start if len(walk) == 1 else link_prefix(start, walk[:-1])
        return Replay(last, before, broken_at=last, reason=f"declared head {declared_head} is not the replayed head {prev}", rule="declared-head")
    return Replay(count=count, head=prev)


def link_prefix(start: str, records: Sequence[dict]) -> str:
    prev = start
    for r in records:
        prev = link(prev, r["event"])
    return prev


__all__ = ["GENESIS", "Replay", "heads", "link", "link_prefix", "replay"]
