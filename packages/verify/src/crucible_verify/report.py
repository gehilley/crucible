"""The SPEC.md §7 verification report.

Replays a session's chain, checks every receipt against the service's key, and
reports one of: intact; broken at event N; could_not_check with the reason
(and not_applicable for a record with no events and no receipts). It also
reports the evidence-class profile and lists every gap event, and names the
service, log and key that anchor the record. Nothing else is interpreted.

**N** is the first event at which the record can be shown to differ from a
record its service sealed honestly. It is the least of:

* where the chain stops replaying;
* for a receipt that is the service's word (signed by a given key, in its signed
  tree, for this session) but whose head is not the head the record's events
  link to at its last event -- or that anchors an event the record does not
  hold: the event after the last one a passing receipt anchors below it. Its
  head commits to every event before it, so nothing later than that anchor is
  known to match. Receipts are checked against heads linked from the events
  themselves (`computed_heads`), so a break the events do not cause (a stored
  head replaced, a declared head or count changed) cannot hide a change to
  the events before it;
* for passing receipts that contradict each other (two logs, two roots for one
  tree size, one leaf for two entries, a later span earlier in the log,
  overlapping spans, or a tree that is not a prefix of the later one): the first
  event any of them covers.

A receipt that is not the service's word (unsigned, signed badly, not in its
tree, for another session) says nothing about the events; it still fails the
record when nothing above places N, at the first event it claims to cover.

When some receipt holds, no N is placed past the first event no passing
receipt anchors: past it, nothing is known to be what was sealed, so a break
the events do not cause further on (a declared head left as sealed, a count)
cannot stand in front of a change before it; the verdict then says so. A
receipt that does not hold never moves N this way.

Otherwise the verdict is ``could_not_check`` when: event 0 is in a protocol
version this code does not read; there is no receipt, or no service key; a
receipt is signed by a key that was not given, or is in an unknown format; two
receipts cannot be linked; or events after the last anchored one are not yet
anchored. Only then is it ``pass``: intact. `could_not_check` is never rounded
to intact (SPEC.md §4 Honesty rule).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from crucible_chain.chain import GENESIS, link, replay
from crucible_chain.events import EVIDENCE_CLASSES
from crucible_core.canonical import CanonicalizationError
from crucible_core.keys import PublicKey

from .receipts import ReceiptResult, check_link, check_receipt, keyring
from .results import Check, State


@dataclass(frozen=True)
class Report:
    session: str | None
    count: int
    head: str
    verdict: Check
    at: int | None
    checks: list[Check]
    evidence: dict
    gaps: list[dict]
    services: list[str] = field(default_factory=list)
    #: Every receipt's result: its span, service, log, key, tree size and server time.
    receipts: list[ReceiptResult] = field(default_factory=list)

    @property
    def says(self) -> str:
        """The verdict in §7's words."""
        s = self.verdict.state
        if s == State.PASS:
            return "intact"
        if s == State.FAIL:
            return f"broken at event {self.at}"
        if s == State.COULD_NOT_CHECK:
            return f"could_not_check({self.verdict.reason})"
        return f"not_applicable({self.verdict.reason})"

    def to_json(self) -> dict:
        return {
            "session": self.session,
            "count": self.count,
            "head": self.head,
            "verdict": {**self.verdict.to_json(), "says": self.says, "at": self.at},
            "checks": [c.to_json() for c in self.checks],
            "evidence": self.evidence,
            "gaps": self.gaps,
            "services": self.services,
            "receipts": [x.to_json() for x in self.receipts],
        }

    def render(self) -> str:
        lines = [
            f"record     {self.says}",
            f"           session {self.session or '-'}, {self.count} events, head {self.head}",
        ]
        lines += [c.render() for c in self.checks]
        anchors = [x for x in self.receipts if x.check.state == State.PASS]
        if anchors:
            last = max(anchors, key=lambda x: (x.to_seq, x.ts))
            lines.append(
                f"anchored   by {last.service} (log {last.log_id}, key {last.key_id}); "
                f"events 0..{max(x.to_seq for x in anchors)}, last receipt at server time {last.ts}"
            )
        ev = self.evidence
        parts = [f"{k} {ev['counts'][k]} ({ev['fractions'][k]:.1%})" for k in EVIDENCE_CLASSES]
        lines.append(f"evidence   {' · '.join(parts)}")
        if self.gaps:
            lines.append(f"gaps       {len(self.gaps)}")
            lines += [f"           event {g['seq']}: could not see {g['could_not_see']!r}" for g in self.gaps]
        else:
            lines.append("gaps       none recorded")
        return "\n".join(lines) + "\n"


def _event(r: object) -> dict | None:
    e = r.get("event") if isinstance(r, dict) else None
    return e if isinstance(e, dict) else None


def evidence_profile(records: Sequence[dict]) -> dict:
    counts = {k: 0 for k in EVIDENCE_CLASSES}
    for r in records:
        cls = (_event(r) or {}).get("class")
        if isinstance(cls, str) and cls in counts:
            counts[cls] += 1
    total = sum(counts.values())
    return {
        "counts": counts,
        "total": total,
        "fractions": {k: (v / total if total else 0.0) for k, v in counts.items()},
    }


def gap_list(records: Sequence[dict]) -> list[dict]:
    out = []
    for r in records:
        e = _event(r)
        if e is not None and e.get("type") == "gap":
            body = e.get("body")
            out.append({"seq": e.get("seq"), "could_not_see": body.get("could_not_see") if isinstance(body, dict) else None})
    return out


def computed_heads(records: Sequence[dict]) -> dict[int, str]:
    """Each position's head, linked from the events alone, as far as they can be hashed.

    Receipts are checked against these, not against the stored heads: what the
    service sealed is a head over the events, so a receipt that matches here
    says the events up to it are the ones it sealed, whatever a stored head or
    a declared count says, and one that does not match says they are not.
    """
    heads, prev = {}, GENESIS
    for i, rec in enumerate(records):
        event = _event(rec)
        if event is None:
            break
        try:
            prev = link(prev, event)
        except (CanonicalizationError, ValueError, RecursionError):
            break
        heads[i] = prev
    return heads


def verify_record(
    records: Sequence[dict],
    receipts: Sequence[dict],
    *,
    service_key: PublicKey | Iterable[PublicKey] | Mapping[str, PublicKey] | None,
    session: str | None = None,
    declared_count: int | None = None,
    declared_head: str | None = None,
) -> Report:
    """Verify one session's record.

    ``records`` are ``{"seq", "event"[, "head"]}``; ``receipts`` are the
    receipts held for it (an export's receipt lines' ``receipt`` values, or the
    service's own). ``service_key`` is the public key, or keys, the receipts
    must be signed by, obtained out of band.
    """
    r = replay(records, session=session, declared_count=declared_count, declared_head=declared_head)
    if session is None and records and isinstance(records[0], dict) and isinstance(records[0].get("event"), dict):
        session = records[0]["event"].get("session")
    profile = evidence_profile(records)
    gaps = gap_list(records)
    keys = keyring(service_key)

    def done(verdict: Check, at: int | None, checks: list[Check], results: Sequence[ReceiptResult] = ()) -> Report:
        services = sorted({x.service for x in results if x.check.state == State.PASS and x.service})
        return Report(session, r.count, r.head, verdict, at, checks, profile, gaps, services, list(results))

    if not records and not receipts and declared_count in (None, 0) and declared_head in (None, GENESIS):
        v = Check("record", State.NOT_APPLICABLE, "the record holds no events and no receipts")
        return done(v, None, [Check("chain", State.NOT_APPLICABLE, "there are no events to replay")])

    broken = r.broken_at is not None
    if r.uncheckable is not None:
        chain = Check("chain", State.COULD_NOT_CHECK, r.uncheckable)
    elif broken:
        chain = Check("chain", State.FAIL, f"broken at event {r.broken_at}: {r.reason}")
    else:
        chain = Check("chain", State.PASS, f"{r.count} events replay from genesis to {r.head}")
    checks = [chain]
    heads = computed_heads(records)

    candidates: list[tuple[int, str]] = []  # (N, why) from the chain and the service's own word
    if broken:
        candidates.append((r.broken_at, chain.reason))

    if not receipts:
        receipts_check = Check("receipts", State.COULD_NOT_CHECK, "no receipt anchors this record")
    elif not keys:
        receipts_check = Check("receipts", State.COULD_NOT_CHECK, "no service public key was given to check the receipts against")
    else:
        receipts_check = None
    if receipts_check is not None:
        checks.append(receipts_check)
        if candidates:
            at, why = min(candidates, key=lambda c: c[0])
            return done(Check("record", State.FAIL, why), at, checks)
        if r.uncheckable is not None:
            return done(Check("record", State.COULD_NOT_CHECK, r.uncheckable), None, checks)
        return done(Check("record", State.COULD_NOT_CHECK, receipts_check.reason), None, checks)

    results = [check_receipt(rc, session=session or "", heads=heads, service_key=keys) for rc in receipts]
    passing = [x for x in results if x.check.state == State.PASS]

    anchored_to = max((x.to_seq for x in passing), default=-1)

    def after_last_anchor_below(b: int | None) -> int:
        below = [x.to_seq for x in passing if b is None or x.to_seq < b]
        return min(max(below, default=-1) + 1, len(records))

    stranded: list[tuple[int, str]] = []  # failures that say nothing about the events
    unchecked: list[str] = []
    for i, x in enumerate(results):
        if x.check.state == State.FAIL and x.authenticated:
            candidates.append((after_last_anchor_below(x.to_seq), f"receipt {i} does not hold: {x.check.reason}"))
        elif x.check.state == State.FAIL:
            claimed = max(x.from_seq if x.from_seq is not None else 0, 0)
            stranded.append((min(claimed, r.count), f"receipt {i} does not verify: {x.check.reason}"))
        elif x.check.state == State.COULD_NOT_CHECK:
            unchecked.append(f"receipt {i}: {x.check.reason}")

    # Passing receipts must agree with each other: one log, one root per size,
    # one entry per leaf, and a log that only grew between them.
    links: list[Check] = []
    logs = sorted({(x.service, x.log_id) for x in passing})
    if len(logs) > 1:
        reason = f"the session's receipts come from {len(logs)} logs: {', '.join(f'{s} {l}' for s, l in logs)}"
        candidates.append((min(x.from_seq for x in passing), reason))
        links.append(Check("link", State.FAIL, reason))
    else:
        roots: dict[int, ReceiptResult] = {}
        leaves: dict[int, ReceiptResult] = {}
        for x in passing:
            for seen, key in ((roots, x.tree_size), (leaves, x.leaf_index)):
                held = seen.setdefault(key, x)
                clash = (held.root != x.root) if seen is roots else (held.entry_hash != x.entry_hash)
                if clash:
                    what = f"two roots for tree size {key}" if seen is roots else f"two entries at leaf {key}"
                    reason = f"the log signed {what} (events {held.from_seq}..{held.to_seq} and {x.from_seq}..{x.to_seq})"
                    candidates.append((min(held.from_seq, x.from_seq), reason))
                    links.append(Check("link", State.FAIL, reason))
        distinct = sorted({x.entry_hash: x for x in passing}.values(), key=lambda x: (x.to_seq, x.leaf_index))
        for earlier, later in zip(distinct, distinct[1:]):
            if later.from_seq <= earlier.to_seq:
                c = Check("link", State.FAIL, f"events {earlier.from_seq}..{earlier.to_seq} and {later.from_seq}..{later.to_seq} are anchored twice")
            else:
                c = check_link(earlier, later)
            links.append(c)
            if c.state == State.FAIL:
                candidates.append((min(earlier.from_seq, later.from_seq), c.reason))
            elif c.state == State.COULD_NOT_CHECK:
                unchecked.append(c.reason)

    states = {x.check.state for x in results}
    receipts_state = State.FAIL if State.FAIL in states else State.COULD_NOT_CHECK if State.COULD_NOT_CHECK in states else State.PASS
    checks.append(Check("receipts", receipts_state, f"{len(passing)} of {len(results)} receipt(s) verify"))
    failed_links = [c for c in links if c.state == State.FAIL]
    if links:
        checks.append(failed_links[0] if failed_links else next((c for c in links if c.state == State.COULD_NOT_CHECK), links[-1]))

    if candidates or stranded:
        # Receipts were checked: nothing past the last event a passing receipt
        # anchors is known to be what was sealed, so no break is placed later
        # than the first event they leave unanchored -- whatever stopped the
        # replay (a declared head, a count, a stale stored head) further on.
        placed = []
        for n, why in candidates or stranded:
            if passing and n > anchored_to + 1:  # only receipts that hold can say what is anchored
                n, why = anchored_to + 1, f"nothing after event {anchored_to} is anchored by a receipt that holds; {why}"
            placed.append((n, why))
        at, why = min(placed, key=lambda c: c[0])  # the first found, among equals
        return done(Check("record", State.FAIL, why), at, checks, results)
    if r.uncheckable is not None:
        return done(Check("record", State.COULD_NOT_CHECK, r.uncheckable), None, checks, results)
    if unchecked:
        return done(Check("record", State.COULD_NOT_CHECK, unchecked[0]), None, checks, results)
    covered = max((x.to_seq for x in passing), default=-1)
    last = r.count - 1
    if covered < last:
        c = Check("anchoring", State.COULD_NOT_CHECK, f"events {covered + 1}..{last} are not yet anchored by any receipt")
        return done(Check("record", State.COULD_NOT_CHECK, c.reason), None, checks + [c], results)
    return done(Check("record", State.PASS, f"{r.count} events replay intact and every one is anchored"), None, checks, results)


__all__ = ["Report", "evidence_profile", "gap_list", "verify_record"]
