"""A session's chain as JSON lines, readable and verifiable without the store.

    {"kind":"header","format":"crucible-chain/2","session":...,"count":n,"head":h}
    {"kind":"event","seq":0,"head":h_0,"event":{...}}
    ...
    {"kind":"receipt","to_seq":k,"receipt":{...}}

Every line is JCS, so an export is byte-stable. The header's count and head are
claims the reader checks: `chain.replay` reports a count beyond the event lines
as a truncated tail. Lines are read with `loads_one_reading`, so a line that
states a key twice is refused rather than read two ways.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from crucible_core import atomic
from crucible_core.canonical import DuplicateJSONKeyError, canonicalize, is_digest, loads_one_reading

from .chain import GENESIS
from .store import ChainStore

FORMAT = "crucible-chain/2"


class ExportError(ValueError):
    """An export file that is not one."""


@dataclass
class Export:
    header: dict
    records: list[dict] = field(default_factory=list)
    receipts: list[dict] = field(default_factory=list)


def dumps(session: str, records: list[dict], receipts: list[dict] | None = None, *, header: dict | None = None) -> str:
    """Serialize an export. ``header`` overrides the computed one (for planted fixtures)."""
    head = records[-1]["head"] if records else GENESIS
    hdr = header if header is not None else {
        "kind": "header", "format": FORMAT, "session": session, "count": len(records), "head": head,
    }
    lines = [hdr]
    lines += [{"kind": "event", "seq": r["seq"], "head": r["head"], "event": r["event"]} for r in records]
    lines += [{"kind": "receipt", "to_seq": r["to_seq"], "receipt": r["receipt"]} for r in (receipts or [])]
    return "".join(canonicalize(line).decode("utf-8") + "\n" for line in lines)


def write(store: ChainStore, session: str, path: Path | str) -> Path:
    """Export ``session`` from ``store`` to ``path``, atomically."""
    records = [r.as_record() for r in store.records(session)]
    receipts = [{"to_seq": k, "receipt": rec} for k, rec in store.receipts(session)]
    return atomic.write_text(path, dumps(session, records, receipts))


_HEADER_KEYS = frozenset({"kind", "format", "session", "count", "head"})
_EVENT_KEYS = frozenset({"kind", "seq", "head", "event"})
_RECEIPT_KEYS = frozenset({"kind", "to_seq", "receipt"})


def _is_count(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def loads(text: str) -> Export:
    """Parse an export, holding every line to its exact shape.

    Lines are split on ``\n`` only. JCS escapes control characters but writes
    U+2028, U+2029 and U+0085 raw inside strings, and ``str.splitlines`` would
    cut an honest line at them.
    """
    raw_lines = text.split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines.pop()
    parsed = []
    for i, ln in enumerate(raw_lines, 1):
        if ln.endswith("\r"):
            ln = ln[:-1]
        if not ln.strip():
            raise ExportError(f"line {i} is blank")
        try:
            obj = loads_one_reading(ln)
        except DuplicateJSONKeyError as exc:
            raise ExportError(f"line {i} has two readings: {exc}") from exc
        except (ValueError, RecursionError) as exc:
            raise ExportError(f"line {i} is not JSON: {exc}") from exc
        if not isinstance(obj, dict) or "kind" not in obj:
            raise ExportError(f"line {i} is not an export line")
        parsed.append(obj)
    if not parsed:
        raise ExportError("empty export: no header")
    header = parsed[0]
    if header.get("kind") != "header" or header.get("format") != FORMAT:
        raise ExportError(f"the first line must be the {FORMAT} header")
    if set(header) != _HEADER_KEYS:
        raise ExportError(f"the header has fields {sorted(header)}, not {sorted(_HEADER_KEYS)}")
    if not (_is_count(header["count"]) and isinstance(header["head"], str) and is_digest(header["head"])):
        raise ExportError("the header's count must be a non-negative integer and its head a digest")
    if not (isinstance(header["session"], str) and header["session"]):
        raise ExportError("the header must name its session")
    out = Export(header=header)
    for i, obj in enumerate(parsed[1:], 2):
        kind = obj["kind"]
        if kind == "event":
            if set(obj) != _EVENT_KEYS:
                raise ExportError(f"line {i}: an event line has fields {sorted(_EVENT_KEYS)}, not {sorted(obj)}")
            if not (_is_count(obj["seq"]) and isinstance(obj["head"], str) and is_digest(obj["head"]) and isinstance(obj["event"], dict)):
                raise ExportError(f"line {i}: an event line needs an integer seq, a digest head and an event object")
            out.records.append({"seq": obj["seq"], "head": obj["head"], "event": obj["event"]})
        elif kind == "receipt":
            if set(obj) != _RECEIPT_KEYS or not _is_count(obj["to_seq"]):
                raise ExportError(f"line {i}: a receipt line needs an integer to_seq and a receipt")
            # The line's to_seq is an unsigned copy; it may not disagree with the signed one.
            entry = obj["receipt"].get("entry") if isinstance(obj["receipt"], dict) else None
            payload = entry.get("payload") if isinstance(entry, dict) else None
            if isinstance(payload, dict) and "to_seq" in payload and payload["to_seq"] != obj["to_seq"]:
                raise ExportError(f"line {i}: the line says to_seq {obj['to_seq']}, its receipt {payload['to_seq']!r}")
            out.receipts.append({"to_seq": obj["to_seq"], "receipt": obj["receipt"]})
        else:
            raise ExportError(f"line {i} has unknown kind {kind!r}")
    return out


def read(path: Path | str) -> Export:
    try:
        return loads(Path(path).read_bytes().decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ExportError(f"{path} is not UTF-8: {exc}") from exc


__all__ = ["FORMAT", "Export", "ExportError", "dumps", "loads", "read", "write"]
