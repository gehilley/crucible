"""SPEC.md §4 events.

Every event has: a sequence number; a monotonic client timestamp; an event type
from a closed vocabulary; the actor; the content, or a digest plus a truncation
note; and (outside the event itself) the chain hash. Each also carries the
evidence class the client can honestly claim.

Shape, closed world::

    {
      "v": 2,                       # this protocol version
      "session": "<id>",            # the session whose chain this event is in
      "seq": 0,                     # position in that chain, from 0
      "ts": 1761300000000000,       # client clock, microseconds since the epoch,
                                    #   strictly increasing within the session
      "type": "tool.call",          # one of EVENT_TYPES
      "actor": "model:<id>",        # human | model:<id> | tool:<name>
      "class": "witnessed",         # witnessed | sealed | reconstructed
      "supplier": "...",            # required for, and only for, reconstructed
      "body": {...},                # small metadata: tool name, path, ids
      "content": <json>             # the content itself, or instead:
      "digest": "sha256:...",       #   its digest
      "note": {"reason": ..., ...}  #   and why the content is not here
    }

Phase 0 carries digests (full content is phase 1, SPEC.md §9), so a phase 0
event's note says ``{"reason": "digest_only", "of": "jcs"|"bytes", "size": n}``:
what was digested, and how big it was.

Content over a size limit (SPEC.md §3, phase 1) is "stored whole up to the limit
and digested beyond it, with the truncation recorded as such": such an event
carries ``content`` (the kept part), ``digest`` (of the whole) and a note
``{"reason": "truncated", "limit": n, "size": m}``. That is the only case in
which content and digest travel together.

A gap event carries ``content: null``: nothing was captured, and the event says
so rather than digesting an empty stand-in.

Every event must survive a JCS round trip byte for byte. JCS writes an integral
float such as ``1e16`` as a bare integer that no reader can take back, and an
event like that would seal and then fail its own replay forever; it is refused
at the door instead.
"""

from __future__ import annotations

import json
import re
from typing import Any

from crucible_core.canonical import CanonicalizationError, canonicalize, is_digest, sha256_bytes

#: The event format version carried in every event's ``v``.
PROTOCOL_VERSION = 2

EVENT_TYPES: tuple[str, ...] = (
    "session.start",
    "session.end",
    "prompt",
    "response",
    "tool.call",
    "tool.result",
    "file.read",
    "file.write",
    "fetch",
    "context.injected",
    "gap",
)

EVIDENCE_CLASSES: tuple[str, ...] = ("witnessed", "sealed", "reconstructed")

_ACTOR_RE = re.compile(r"(?:human|model:\S+|tool:\S+)")
_SESSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_MAX_ACTOR = 256

#: The largest integer JCS can carry (RFC 8785 numbers are IEEE doubles).
#: Microseconds since the epoch stay below it until about the year 2255;
#: nanoseconds would not fit today.
MAX_SAFE_INT = 2**53 - 1
#: The deepest an event may nest, counting the event object as 1. A stated
#: limit, so that the client that seals an event and the service that checks it
#: give the same answer whatever their call stacks, far below the depth at
#: which a JSON parser runs out of stack.
MAX_DEPTH = 64

_CHAIN_FIELDS = ("v", "session", "seq", "ts")
_FIELDS = frozenset(
    {*_CHAIN_FIELDS, "type", "actor", "class", "supplier", "body", "content", "digest", "note"}
)

_MISSING = object()


class EventError(ValueError):
    """An event, or a draft of one, breaks a §4 rule. The message names the field."""


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def digest_only(content: Any) -> dict:
    """Content reduced to a digest plus the note saying so.

    ``bytes`` are digested as they are (a file's contents, comparable with
    ``sha256sum``); anything else is digested in its JCS form.
    """
    if isinstance(content, (bytes, bytearray)):
        raw, of = bytes(content), "bytes"
    else:
        try:
            raw = canonicalize(content)
        except CanonicalizationError as exc:
            raise EventError(f"content is not JCS-serializable: {exc}") from exc
        of = "jcs"
    return {"digest": sha256_bytes(raw), "note": {"reason": "digest_only", "of": of, "size": len(raw)}}


def draft(
    type: str,
    actor: str,
    cls: str,
    body: dict | None = None,
    *,
    content: Any = _MISSING,
    digest: str | None = None,
    note: dict | None = None,
    supplier: str | None = None,
    keep_content: bool = False,
) -> dict:
    """An event without its chain fields, which the store assigns.

    Give ``content`` and it is reduced to a digest plus note, unless
    ``keep_content`` (phase 1) keeps it whole. Or give a ``digest`` and ``note``
    you computed yourself -- a file's bytes digested by streaming, say.
    """
    d: dict[str, Any] = {"type": type, "actor": actor, "class": cls, "body": dict(body or {})}
    if supplier is not None:
        d["supplier"] = supplier
    if type == "gap" and (content is None or content is _MISSING) and digest is None and note is None:
        d["content"] = None  # nothing was captured: said as null, never as a digest of a stand-in
    elif content is not _MISSING:
        if digest is not None or note is not None:
            # Only the truncated form carries both; validate_draft holds it to that.
            d["content"], d["digest"], d["note"] = content, digest, dict(note or {})
        elif keep_content:
            d["content"] = content
        else:
            d.update(digest_only(content))
    else:
        if digest is None or note is None:
            raise EventError("content: a draft needs content, or a digest and a note")
        d["digest"], d["note"] = digest, dict(note)
    validate_draft(d)
    return d


def _too_deep(value: object, limit: int = MAX_DEPTH) -> bool:
    stack = [(value, 1)]
    while stack:
        v, depth = stack.pop()
        if isinstance(v, (dict, list)):
            if depth > limit:
                return True
            stack.extend((c, depth + 1) for c in (v.values() if isinstance(v, dict) else v))
    return False


def validate_draft(d: object) -> None:
    """Check everything a draft carries; the chain fields are not yet there."""
    if not isinstance(d, dict):
        raise EventError("event: must be a JSON object")
    if _too_deep(d):
        raise EventError(f"event: nests deeper than {MAX_DEPTH} levels")
    unknown = set(d) - _FIELDS
    if unknown:
        raise EventError(f"unknown field(s): {sorted(unknown)}")
    if d.get("type") not in EVENT_TYPES:
        raise EventError(f"type: {d.get('type')!r} is not in the §4 vocabulary")
    actor = d.get("actor")
    if not (isinstance(actor, str) and len(actor) <= _MAX_ACTOR and _ACTOR_RE.fullmatch(actor)):
        raise EventError(f"actor: {actor!r} is not human, model:<id> or tool:<name>")
    cls = d.get("class")
    if cls not in EVIDENCE_CLASSES:
        raise EventError(f"class: {cls!r} is not witnessed, sealed or reconstructed")
    if cls == "reconstructed":
        if not (isinstance(d.get("supplier"), str) and d["supplier"].strip()):
            raise EventError("supplier: a reconstructed event must name who supplied it")
    elif "supplier" in d:
        raise EventError(f"supplier: only a reconstructed event names a supplier, not {cls}")
    body = d.get("body")
    if not isinstance(body, dict):
        raise EventError("body: must be a JSON object")
    if d["type"] == "gap":
        what = body.get("could_not_see")
        if not (isinstance(what, str) and what.strip()):
            raise EventError("could_not_see: a gap event must say what could not be seen")
        if d.get("content", _MISSING) is not None or "digest" in d or "note" in d:
            raise EventError("content: a gap event carries content null and no digest; nothing was captured")
    has_content = "content" in d
    has_digest = "digest" in d
    note = d.get("note")
    if not (has_content or has_digest):
        raise EventError("content: an event carries its content, or a digest and note; this one has neither")
    if has_digest:
        if not is_digest(d["digest"]):
            raise EventError(f"digest: {d['digest']!r} is not a sha256 digest")
        if not (isinstance(note, dict) and isinstance(note.get("reason"), str) and note["reason"]):
            raise EventError("note: a digest must come with a note giving its reason")
        if has_content:
            truncated = note.get("reason") == "truncated"
            sizes_ok = all(_is_int(note.get(k)) and note[k] >= 0 for k in ("limit", "size"))
            if not (truncated and sizes_ok and note["limit"] < note["size"]):
                raise EventError(
                    "content: content and digest travel together only for truncated content, "
                    "with a note {reason: truncated, limit, size} and limit < size"
                )
    elif "note" in d:
        raise EventError("note: an event that carries its content whole has no truncation note")
    _round_trip(d)


def _round_trip(value: object) -> None:
    try:
        raw = canonicalize(value)
    except CanonicalizationError as exc:
        raise EventError(f"event: not JCS-serializable: {exc}") from exc
    try:
        again = canonicalize(json.loads(raw))
    except (CanonicalizationError, ValueError, RecursionError) as exc:
        raise EventError(f"event: does not survive a JCS round trip: {exc}") from exc
    if again != raw:
        raise EventError("event: does not survive a JCS round trip byte for byte")


def validate(event: object) -> None:
    """Check a placed event: a valid draft plus its chain fields."""
    if not isinstance(event, dict):
        raise EventError("event: must be a JSON object")
    if event.get("v") != PROTOCOL_VERSION or not _is_int(event.get("v")):
        raise EventError(f"v: {event.get('v')!r} is not protocol version {PROTOCOL_VERSION}")
    session = event.get("session")
    if not (isinstance(session, str) and _SESSION_RE.fullmatch(session)):
        raise EventError(f"session: {session!r} is not a session id")
    seq = event.get("seq")
    if not (_is_int(seq) and 0 <= seq <= MAX_SAFE_INT):
        raise EventError(f"seq: {seq!r} is not a non-negative integer within JCS's safe range")
    ts = event.get("ts")
    if not (_is_int(ts) and 0 < ts <= MAX_SAFE_INT):
        raise EventError(f"ts: {ts!r} is not a positive integer of microseconds within JCS's safe range")
    validate_draft({k: v for k, v in event.items() if k not in _CHAIN_FIELDS})


__all__ = [
    "EVENT_TYPES",
    "EVIDENCE_CLASSES",
    "PROTOCOL_VERSION",
    "MAX_DEPTH",
    "MAX_SAFE_INT",
    "EventError",
    "digest_only",
    "draft",
    "validate",
    "validate_draft",
]
