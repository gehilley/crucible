"""Regression plants for the step 2 fresh-session review.

Each test pins a defect the review demonstrated on the first draft of this
package, with the answer the fixed code must give.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys

import pytest

from crucible_chain.blobs import BlobStore
from crucible_chain.chain import GENESIS, link, replay
from crucible_chain.events import EventError, draft, validate
from crucible_chain.export import ExportError, loads, read, write
from crucible_chain.store import ChainStore, StoreError

S = "session-r"


def d(body=None, content=None):
    return draft("prompt", "human", "witnessed", body or {}, content=content if content is not None else {"t": 1})


# --- an event must survive a JCS round trip -------------------------------------


@pytest.mark.parametrize("value", [1e16, 2.0**60, 1e20])
def test_an_integral_float_jcs_cannot_read_back_is_refused_at_append(tmp_path, value):
    with ChainStore(tmp_path / "c.sqlite") as store:
        with pytest.raises(EventError, match="round trip"):
            store.append(S, draft("prompt", "human", "witnessed", {"x": value}, keep_content=True, content=None))
        assert store.head(S) is None


@pytest.mark.parametrize("value", [1e21, 1.5, 0.1, -3.25])
def test_floats_jcs_writes_faithfully_are_accepted_and_replay(tmp_path, value):
    with ChainStore(tmp_path / "c.sqlite") as store:
        store.append(S, draft("prompt", "human", "witnessed", {"x": value}, keep_content=True, content=None))
        assert replay([r.as_record() for r in store.records(S)]).intact


def test_seq_beyond_jcs_range_is_refused():
    e = {"v": 2, "session": S, "seq": 2**53, "ts": 5, "type": "prompt", "actor": "human", "class": "witnessed", "body": {}, "content": None}
    with pytest.raises(EventError, match="seq"):
        validate(e)


# --- the export reader -------------------------------------------------------------


@pytest.mark.parametrize("ch", [" ", " ", "\u0085", "\x0b", "\x0c"])
def test_an_export_with_unicode_line_separators_in_strings_round_trips(tmp_path, ch):
    with ChainStore(tmp_path / "c.sqlite") as store:
        store.append(S, draft("file.read", "tool:Read", "sealed", {"path": f"notes{ch}draft.txt"}, content=b"x"))
        path = write(store, S, tmp_path / "e.jsonl")
    ex = read(path)
    assert ex.records[0]["event"]["body"]["path"] == f"notes{ch}draft.txt"
    assert replay(ex.records, declared_count=ex.header["count"], declared_head=ex.header["head"]).intact


def _export(tmp_path, n=3):
    with ChainStore(tmp_path / "c.sqlite") as store:
        for i in range(n):
            store.append(S, d(content={"i": i}))
        return write(store, S, tmp_path / "e.jsonl").read_text()


@pytest.mark.parametrize("count", ['"3"', "null", "-1", "3.0", "true"])
def test_a_malformed_header_count_is_refused(tmp_path, count):
    lines = _export(tmp_path).split("\n")
    lines[0] = lines[0].replace('"count":3', f'"count":{count}')
    with pytest.raises(ExportError, match="count"):
        loads("\n".join(lines))


def test_an_event_line_without_a_head_is_refused(tmp_path):
    lines = _export(tmp_path).split("\n")
    rec = json.loads(lines[2])
    del rec["head"]
    lines[2] = json.dumps(rec)
    with pytest.raises(ExportError, match="event line"):
        loads("\n".join(lines))


def test_bytes_that_are_not_utf8_are_an_export_error(tmp_path):
    p = tmp_path / "x.jsonl"
    p.write_bytes(b"\xff\xfe not utf8\n")
    with pytest.raises(ExportError, match="UTF-8"):
        read(p)


def test_deeply_nested_input_is_an_export_error_not_a_crash():
    with pytest.raises(ExportError):
        loads("[" * 100000 + "]" * 100000 + "\n")


def test_a_blank_line_inside_an_export_is_refused(tmp_path):
    lines = _export(tmp_path).split("\n")
    lines.insert(2, "")
    with pytest.raises(ExportError, match="blank"):
        loads("\n".join(lines))


# --- heads all or none; prefixes consistent ---------------------------------------


def _records(n=6):
    out, prev = [], GENESIS
    for i in range(n):
        e = {"v": 2, "session": S, "seq": i, "ts": 100 + i, "type": "prompt", "actor": "human", "class": "witnessed", "body": {}, "content": {"i": i}}
        prev = link(prev, e)
        out.append({"seq": i, "head": prev, "event": e})
    return out


def test_dropping_the_head_of_an_altered_record_does_not_move_n():
    recs = _records()
    recs[3]["event"] = {**recs[3]["event"], "content": {"i": "x"}}
    del recs[3]["head"]
    r = replay(recs)
    assert r.broken_at == 3


def test_a_declared_count_must_be_a_count():
    for bad in ["6", -1, 6.0, True]:
        with pytest.raises(ValueError):
            replay(_records(), declared_count=bad)


def test_count_and_head_describe_the_same_prefix():
    recs = _records(8)
    r = replay(recs, declared_count=5)
    assert (r.broken_at, r.count, r.head) == (5, 5, recs[4]["head"])
    r = replay(recs, declared_count=8, declared_head="sha256:" + "11" * 32)
    assert (r.broken_at, r.count, r.head) == (7, 7, recs[6]["head"])
    r = replay(recs[:3])
    assert (r.count, r.head) == (3, recs[2]["head"])


def test_an_event_found_later_is_out_of_order_not_missing():
    recs = _records()
    recs[2], recs[3] = recs[3], recs[2]
    r = replay(recs)
    assert r.broken_at == 2 and "out of order" in r.reason and r.rule == "seq"


def test_an_unknown_protocol_version_is_uncheckable_not_broken():
    recs = _records(3)
    for rec in recs:
        rec["event"]["v"] = 3
    r = replay([{"seq": x["seq"], "event": x["event"]} for x in recs])
    assert r.broken_at is None and r.uncheckable and "protocol version 3" in r.uncheckable
    assert not r.intact


def test_relabelling_a_tampered_event_with_another_version_does_not_hide_its_break():
    from crucible_chain.corpus import FIXTURES

    records, _header = FIXTURES["altered-event"][3]()
    records[5]["event"]["v"] = 3
    r = replay(records)
    assert (r.broken_at, r.uncheckable) == (5, None) and r.rule == "event.v"


def test_a_later_event_in_another_version_is_a_break_there():
    recs = _records(4)
    recs[2]["event"]["v"] = 3
    r = replay([{"seq": x["seq"], "event": x["event"]} for x in recs])
    assert (r.broken_at, r.uncheckable, r.rule) == (2, None, "event.v")


def test_the_first_break_is_the_first_undeclared_event_even_if_a_later_one_is_tampered():
    from crucible_chain.corpus import control_records

    recs = control_records()
    recs[10]["head"] = "sha256:" + "ab" * 32
    r = replay(recs, declared_count=9)
    assert (r.broken_at, r.rule) == (9, "count")


# --- the store: triggers, first open, receipts ------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT OR REPLACE INTO events(session, seq, ts, head, type, event) VALUES('session-r', 0, 1, 'x', 'prompt', '{}')",
        "REPLACE INTO events(session, seq, ts, head, type, event) VALUES('session-r', 0, 1, 'x', 'prompt', '{}')",
        "INSERT OR REPLACE INTO receipts(session, to_seq, receipt) VALUES('session-r', 0, '{}')",
    ],
)
def test_replace_cannot_rewrite_a_stored_row(tmp_path, sql):
    path = tmp_path / "c.sqlite"
    with ChainStore(path) as store:
        store.append(S, d())
        store.add_receipt(S, 0, {"r": 1})
        before = store.records(S)[0]
    conn = sqlite3.connect(path)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute(sql)
    conn.close()
    with ChainStore(path) as store:
        assert store.records(S)[0] == before
        assert store.receipts(S) == [(0, {"r": 1})]


_OPENER = """
import sys
from crucible_chain.events import draft
from crucible_chain.store import ChainStore
with ChainStore(sys.argv[1]) as store:
    store.append("session-r", draft("prompt", "human", "witnessed", {}, content={"w": sys.argv[2]}))
"""


def test_many_processes_opening_a_fresh_store_at_once_all_succeed(tmp_path):
    for trial in range(3):
        path = tmp_path / f"fresh-{trial}.sqlite"
        procs = [subprocess.Popen([sys.executable, "-c", _OPENER, str(path), str(w)], stderr=subprocess.PIPE) for w in range(8)]
        errs = [p.communicate(timeout=120)[1].decode() for p in procs]
        assert all(p.returncode == 0 for p in procs), errs
        with ChainStore(path) as store:
            assert [r.seq for r in store.records(S)] == list(range(8))


def test_a_receipt_must_cover_held_unreceipted_events(tmp_path):
    with ChainStore(tmp_path / "c.sqlite") as store:
        for _ in range(5):
            store.append(S, d())
        with pytest.raises(StoreError):
            store.add_receipt(S, 99, {"r": 1})
        with pytest.raises(StoreError):
            store.add_receipt("no-such-session", 0, {"r": 1})
        with pytest.raises(StoreError):
            store.add_receipt(S, "4", {"r": 1})  # type: ignore[arg-type]
        assert [r.seq for r in store.unsent(S)] == [0, 1, 2, 3, 4]
        store.add_receipt(S, 2, {"r": 1})
        with pytest.raises(StoreError):
            store.add_receipt(S, 1, {"r": 2})  # behind the last receipt
        assert [r.seq for r in store.unsent(S)] == [3, 4]


def test_storing_the_same_receipt_twice_is_a_no_op_and_a_different_one_is_refused(tmp_path):
    with ChainStore(tmp_path / "c.sqlite") as store:
        store.append(S, d())
        store.add_receipt(S, 0, {"r": 1, "z": [1, 2]})
        store.add_receipt(S, 0, {"z": [1, 2], "r": 1})
        with pytest.raises(StoreError):
            store.add_receipt(S, 0, {"r": 2})
        assert store.receipts(S) == [(0, {"r": 1, "z": [1, 2]})]


def test_a_receipt_jcs_cannot_carry_is_refused(tmp_path):
    with ChainStore(tmp_path / "c.sqlite") as store:
        store.append(S, d())
        for bad in (float("nan"), 1e16, 2.0**60):
            with pytest.raises(StoreError):
                store.add_receipt(S, 0, {"r": bad})
        assert store.receipts(S) == []
        store.add_receipt(S, 0, {"r": 1})  # and the store still works


@pytest.mark.parametrize("to_seq", [-1, 2**53, 2**64, True])
def test_a_receipt_position_outside_event_numbers_is_a_store_error(tmp_path, to_seq):
    with ChainStore(tmp_path / "c.sqlite") as store:
        store.append(S, d())
        with pytest.raises(StoreError, match="to_seq"):
            store.add_receipt(S, to_seq, {"r": 1})


# --- the truncation form, and gaps with nothing captured ---------------------------


def test_content_and_digest_together_only_as_a_truncation():
    full = {"v": 2, "session": S, "seq": 0, "ts": 5, "type": "tool.result", "actor": "tool:Bash", "class": "witnessed", "body": {}}
    validate({**full, "content": "first 4K", "digest": "sha256:" + "ab" * 32, "note": {"reason": "truncated", "limit": 4096, "size": 9000}})
    for note in [{"reason": "digest_only", "of": "jcs", "size": 9}, {"reason": "truncated", "limit": 9000, "size": 9000}, {"reason": "truncated"}]:
        with pytest.raises(EventError, match="content"):
            validate({**full, "content": "x", "digest": "sha256:" + "ab" * 32, "note": note})


def test_the_corpus_gap_says_nothing_was_captured():
    from crucible_chain.corpus import control_records

    gap = next(r["event"] for r in control_records() if r["event"]["type"] == "gap")
    assert gap["content"] is None and "digest" not in gap and "note" not in gap


def test_a_drafted_gap_carries_null_content_and_no_digest():
    for kwargs in ({}, {"content": None}):
        g = draft("gap", "tool:crucible", "witnessed", {"could_not_see": "the system prompt"}, **kwargs)
        assert g["content"] is None and "digest" not in g and "note" not in g


@pytest.mark.parametrize(
    "carries",
    [
        {"digest": "sha256:" + "ab" * 32, "note": {"reason": "digest_only", "of": "jcs", "size": 4}},
        {"content": "something"},
        {"content": None, "digest": "sha256:" + "ab" * 32, "note": {"reason": "truncated", "limit": 1, "size": 2}},
    ],
)
def test_a_gap_that_carries_anything_is_refused(carries):
    gap = {"v": 2, "session": S, "seq": 0, "ts": 5, "type": "gap", "actor": "tool:crucible", "class": "witnessed",
           "body": {"could_not_see": "the system prompt"}, **carries}
    with pytest.raises(EventError, match="gap"):
        validate(gap)


# --- blobs -------------------------------------------------------------------------


def test_fsck_reports_a_stray_file_instead_of_stopping(tmp_path):
    store = BlobStore(tmp_path / "blobs")
    good = store.put_bytes(b"real")
    shard = store.path_for(good).parent
    (shard / "not-a-digest").write_bytes(b"stray")
    bad = store.fsck()
    assert any("not-a-digest" in b for b in bad)
    assert good not in bad
    assert good in list(store.iter_digests())


def test_a_blob_filed_under_the_wrong_shard_is_reported_not_listed(tmp_path):
    store = BlobStore(tmp_path / "blobs")
    good = store.put_bytes(b"real")
    path = store.path_for(good)
    misfiled = path.parent.parent / (path.parent.name + path.name[0]) / path.name[1:]
    misfiled.parent.mkdir()
    path.rename(misfiled)
    assert good not in list(store.iter_digests())
    assert any(str(misfiled) in b or misfiled.name in b for b in store.fsck())


@pytest.mark.parametrize("change", ["drop:count", "drop:head", "drop:session", "drop:format", "add:extra"])
def test_a_header_without_exactly_its_fields_is_an_export_error(tmp_path, change):
    from crucible_chain.export import dumps

    text = dumps(S, [], header=None)
    lines = text.split("\n")
    header = json.loads(lines[0])
    op, key = change.split(":")
    if op == "drop":
        header.pop(key)
    else:
        header[key] = 1
    lines[0] = json.dumps(header, sort_keys=True, separators=(",", ":"))
    with pytest.raises(ExportError, match="header"):
        loads("\n".join(lines))


def test_a_value_json_cannot_read_back_for_depth_is_an_event_error(monkeypatch):
    """Near the interpreter's limit, JCS can write a value that json then cannot
    read back (the depth window moves with the caller's stack, so it is planted
    here directly); that must be an EventError, not a crash."""
    import crucible_chain.events as events

    def too_deep(_raw):
        raise RecursionError("maximum recursion depth exceeded while decoding a JSON object")

    monkeypatch.setattr(events.json, "loads", too_deep)
    event = {"v": 2, "session": S, "seq": 0, "ts": 5, "type": "prompt", "actor": "human", "class": "witnessed",
             "body": {}, **events.digest_only("x")}
    with pytest.raises(EventError, match="round trip"):
        validate(event)


def test_a_receipt_filed_under_another_span_or_session_is_refused(tmp_path):
    with ChainStore(tmp_path / "c.sqlite") as store:
        store.append(S, d())
        store.append(S, d())
        signed_for_0 = {"entry": {"payload": {"session": S, "to_seq": 0}}}
        with pytest.raises(StoreError, match="up to 0"):
            store.add_receipt(S, 1, signed_for_0)
        with pytest.raises(StoreError, match="session"):
            store.add_receipt(S, 0, {"entry": {"payload": {"session": "other", "to_seq": 0}}})
        store.add_receipt(S, 0, signed_for_0)
        path = write(store, S, tmp_path / "x.jsonl")
        assert read(path).receipts[0]["to_seq"] == 0  # and the store's export still reads
