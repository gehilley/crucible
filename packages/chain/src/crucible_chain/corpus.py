"""The planted-answer corpus (SPEC.md §8 rule 4): one control chain, one chain
per kind of break, each with a manifest stating the answer a verifier must give.

Deterministic: the same code writes the same bytes, so `corpus/` is committed
and a test regenerates it and compares. Each break is planted so that exactly
one rule fails at the stated event N. Where a planted change would also upset
the heads after it, those heads are recomputed, so the only failing rule is the
one the fixture is named for.

    python -m crucible_chain.corpus corpus/          # write
    python -m crucible_chain.corpus corpus/ --check  # compare, exit 1 on drift
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from .chain import GENESIS, link
from .events import PROTOCOL_VERSION, digest_only
from .export import FORMAT, dumps

SESSION = "corpus-0001"
_T0 = 1_761_264_000_000_000  # 2025-10-24T00:00:00Z, microseconds
_STEP = 1_000
MODEL = "model:claude-opus-5-5"

# (type, actor, class, body, content) for the control session.
_SCRIPT: list[tuple[str, str, str, dict, object]] = [
    ("session.start", "tool:claude-code", "witnessed", {"surface": "claude-code", "version": "2.1.281"}, {"cwd": "/work"}),
    ("context.injected", "tool:claude-code", "sealed", {"source": "CLAUDE.md"}, b"# Project notes\n"),
    ("prompt", "human", "witnessed", {}, {"text": "Count the lines in data/sample.txt and write the count to count.txt."}),
    ("tool.call", MODEL, "witnessed", {"tool": "Read", "tool_use_id": "toolu_01"}, {"file_path": "data/sample.txt"}),
    ("file.read", "tool:Read", "sealed", {"path": "data/sample.txt"}, b"alpha\nbeta\ngamma\n"),
    ("tool.result", "tool:Read", "witnessed", {"tool": "Read", "tool_use_id": "toolu_01"}, {"lines": 3}),
    ("tool.call", MODEL, "witnessed", {"tool": "Write", "tool_use_id": "toolu_02"}, {"file_path": "count.txt", "content": "3\n"}),
    ("file.write", "tool:Write", "sealed", {"path": "count.txt"}, b"3\n"),
    ("tool.result", "tool:Write", "witnessed", {"tool": "Write", "tool_use_id": "toolu_02"}, {"ok": True}),
    ("response", MODEL, "witnessed", {}, {"text": "The file has 3 lines; I wrote 3 to count.txt."}),
    ("gap", "tool:crucible", "witnessed", {"could_not_see": "the system prompt the surface injected"}, None),
    ("session.end", "tool:claude-code", "witnessed", {"reason": "completed"}, None),
]


def control_records() -> list[dict]:
    """The intact control session: every record with its head."""
    out, prev = [], GENESIS
    for seq, (type_, actor, cls, body, content) in enumerate(_SCRIPT):
        event = {
            "v": PROTOCOL_VERSION,
            "session": SESSION,
            "seq": seq,
            "ts": _T0 + seq * _STEP,
            "type": type_,
            "actor": actor,
            "class": cls,
            "body": body,
            # Nothing captured is said as content: null, never as a digest of a stand-in.
            **({"content": None} if content is None else digest_only(content)),
        }
        prev = link(prev, event)
        out.append({"seq": seq, "head": prev, "event": event})
    return out


def _rehash_from(records: list[dict], n: int) -> list[dict]:
    prev = GENESIS if n == 0 else records[n - 1]["head"]
    for r in records[n:]:
        prev = link(prev, r["event"])
        r["head"] = prev
    return records


def _header(records: list[dict]) -> dict:
    return {
        "kind": "header",
        "format": FORMAT,
        "session": SESSION,
        "count": len(records),
        "head": records[-1]["head"] if records else GENESIS,
    }


Fixture = tuple[str, int | None, Callable[[], tuple[list[dict], dict]]]


def _control():
    r = control_records()
    return r, _header(r)


def _altered_event():
    r = control_records()
    original = _header(r)
    r[5]["event"].update(digest_only({"lines": 4}))  # the record now claims a different result
    return r, original


def _missing_seq():
    # The deletion an attacker would make: event 4 removed and every later
    # head recomputed, so only the seq rule can see it.
    r = control_records()
    del r[4]
    r = _rehash_from(r, 4)
    return r, _header(r)


def _bad_link():
    r = control_records()
    r[7]["head"] = "sha256:" + "ab" * 32
    return r, _header(control_records())


def _truncated_tail():
    r = control_records()
    return r[:9], _header(r)


def _reordered():
    r = control_records()
    r[6], r[7] = r[7], r[6]
    r = _rehash_from(r, 6)
    return r, _header(r)


def _header_head_replaced():
    r = control_records()
    h = _header(r)
    h["head"] = "sha256:" + "cd" * 32
    return r, h


def _ts_not_increasing():
    r = control_records()
    r[8]["event"]["ts"] = r[7]["event"]["ts"]
    r = _rehash_from(r, 8)
    return r, _header(r)


def _foreign_session():
    r = control_records()
    r[10]["event"]["session"] = "corpus-0002"
    r = _rehash_from(r, 10)
    return r, _header(r)


def _type_outside_vocabulary():
    r = control_records()
    r[3]["event"]["type"] = "thought"
    r = _rehash_from(r, 3)
    return r, _header(r)


#: name -> (expected break N or None for intact, the rule that must catch it, description, builder)
FIXTURES: dict[str, tuple[int | None, str | None, str, Callable[[], tuple[list[dict], dict]]]] = {
    "control": (None, None, "An intact twelve-event session.", _control),
    "altered-event": (5, "head", "Event 5's content digest was changed after the fact; heads were not.", _altered_event),
    "missing-seq": (4, "seq", "Event 4 was removed and every later head recomputed.", _missing_seq),
    "bad-link": (7, "head", "Event 7's stored head was replaced.", _bad_link),
    "truncated-tail": (9, "truncated", "Events 9-11 were cut off; the header still declares twelve.", _truncated_tail),
    "reordered": (6, "seq", "Events 6 and 7 were swapped and the heads recomputed.", _reordered),
    "ts-not-increasing": (8, "ts", "Event 8's timestamp equals event 7's; heads are consistent.", _ts_not_increasing),
    "foreign-session": (10, "session", "Event 10 names another session; heads are consistent.", _foreign_session),
    "type-outside-vocabulary": (3, "event.type", "Event 3's type is not in §4's vocabulary; heads are consistent.", _type_outside_vocabulary),
    "header-head-replaced": (11, "declared-head", "Every event and head is intact; the header's declared head was replaced.", _header_head_replaced),
}


def generate(out: Path | str) -> None:
    out = Path(out)
    for name, (at, rule, description, build) in FIXTURES.items():
        records, header = build()
        d = out / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "chain.jsonl").write_text(dumps(SESSION, copy.deepcopy(records), header=header), encoding="utf-8")
        manifest = {
            "name": name,
            "description": description,
            "expect": {"verdict": "intact" if at is None else "broken", "at": at, "rule": rule},
        }
        (d / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def check(target: Path | str) -> list[str]:
    """Relative paths that differ between ``target`` and a fresh generation."""
    target = Path(target)
    with tempfile.TemporaryDirectory() as tmp:
        generate(tmp)
        fresh = {p.relative_to(tmp): p.read_bytes() for p in Path(tmp).rglob("*") if p.is_file()}
    have = {p.relative_to(target): p.read_bytes() for p in target.rglob("*") if p.is_file()}
    return sorted(str(k) for k in fresh.keys() | have.keys() if fresh.get(k) != have.get(k))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m crucible_chain.corpus")
    ap.add_argument("out", type=Path)
    ap.add_argument("--check", action="store_true", help="compare instead of writing; exit 1 on drift")
    args = ap.parse_args(argv)
    if args.check:
        drift = check(args.out)
        for name in drift:
            print(f"differs: {name}")
        return 1 if drift else 0
    generate(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
