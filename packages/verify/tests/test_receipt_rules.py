"""Planted answers for the receipt rules: what each receipt proves, how receipts
must agree with each other, and where N falls when one does not hold.

Each plant names the rule it pins. Receipts are minted by the test-only RFC 6962
builder in conftest.py, then changed one way.
"""

from __future__ import annotations

import base64
import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from crucible_chain.corpus import FIXTURES
from crucible_chain.export import ExportError, dumps, loads, read
from crucible_core.canonical import canonicalize
from crucible_core.cose import SignatureError, decode, sign, verify
from crucible_core.keys import PrivateKey
from crucible_verify.report import verify_record
from crucible_verify.results import State

CORPUS = Path(__file__).resolve().parents[3] / "corpus"
SESSION = "corpus-0001"


def control():
    return read(CORPUS / "control" / "chain.jsonl")


def report(records, receipts, key, *, count=None, head=None):
    return verify_record(records, receipts, service_key=key, session=SESSION, declared_count=count, declared_head=head)


def entries_for(records, spans, minter, *, heads=None):
    heads = heads or {}
    return [
        minter.batch_entry(SESSION, a, b, heads.get(b, records[b]["head"]), ts=1_761_264_050_000_000 + b)
        for a, b in spans
    ]


def resign(receipt, key, **changes):
    """The receipt's checkpoint with ``changes``, signed again by ``key``."""
    payload = {**decode(base64.b64decode(receipt["checkpoint"])).payload(), **changes}
    receipt["checkpoint"] = base64.b64encode(sign(payload, key)).decode()


# --- the service's word sets N; a receipt that is not its word does not -------------------


def test_a_failing_receipt_breaks_after_the_last_passing_anchor_below_it(minter, service_key):
    # Event 2 altered and the chain recomputed; only the 6..11 receipt is kept. Its
    # head commits to events 0..11, and nothing anchors 0..5, so N is 0, not 6.
    ex = control()
    sealed = copy.deepcopy(ex.records)
    altered, _ = FIXTURES["altered-event"][3]()
    from crucible_chain.chain import GENESIS, link

    prev = GENESIS
    for r in altered:
        prev = link(prev, r["event"])
        r["head"] = prev
    rc = minter.mint(entries_for(sealed, [(0, 5), (6, 11)], minter), service_key)
    r = report(altered, [rc[1]], service_key.public())
    assert (r.verdict.state, r.at) == (State.FAIL, 0)
    r = report(altered, rc, service_key.public())
    assert (r.verdict.state, r.at) == (State.FAIL, 0)  # 0..5 does not hold either: event 5 is past the change


@pytest.mark.parametrize("claimed", [-5, 10**6])
def test_n_stays_within_the_record_whatever_a_receipt_claims(minter, service_key, claimed):
    ex = control()
    rc = minter.mint(entries_for(ex.records, [(0, 11)], minter), service_key)
    rc[0]["entry"]["payload"]["from_seq"] = claimed
    r = report(ex.records, rc, service_key.public())
    assert r.verdict.state == State.FAIL and 0 <= r.at <= 12


def test_a_junk_receipt_beside_a_full_anchor_still_fails_the_record(minter, service_key):
    # The record carries a receipt that does not verify; the record is not intact.
    # The junk names no events, so it does not move N past what it claims.
    ex = control()
    good = minter.mint(entries_for(ex.records, [(0, 11)], minter), service_key)
    junk = copy.deepcopy(good[0])
    junk["entry_hash"] = "sha256:" + "00" * 32
    junk["entry"]["payload"]["from_seq"] = 7
    r = report(ex.records, good + [junk], service_key.public())
    assert (r.verdict.state, r.at) == (State.FAIL, 7)
    assert "does not verify" in r.verdict.reason


def test_a_chain_break_is_not_moved_by_a_junk_receipt(minter, service_key):
    ex = read(CORPUS / "bad-link" / "chain.jsonl")
    good = minter.mint(entries_for(control().records, [(0, 11)], minter), service_key)
    junk = copy.deepcopy(good[0])
    junk["entry"]["payload"]["from_seq"] = 2
    junk["entry_hash"] = "sha256:" + "00" * 32
    r = report(ex.records, good + [junk], service_key.public(), count=12, head=ex.header["head"])
    assert (r.verdict.state, r.at) == (State.FAIL, 7)


def test_a_receipt_past_a_break_still_bounds_n(minter, service_key):
    # Event 5 changed; the 3..11 receipt commits to events 0..11 as sealed, and
    # only 0..2 is anchored by a receipt that holds, so 3 is the first event that
    # can differ from what was sealed: earlier than where the chain stops replaying.
    ex = read(CORPUS / "altered-event" / "chain.jsonl")
    rc = minter.mint(entries_for(control().records, [(0, 2), (3, 11)], minter), service_key)
    r = report(ex.records, rc, service_key.public(), count=12, head=ex.header["head"])
    assert (r.verdict.state, r.at) == (State.FAIL, 3)
    assert [x.check.state for x in r.receipts] == [State.PASS, State.FAIL]


def test_a_change_hidden_behind_a_later_break_is_found(minter, service_key):
    """Event 7 changed and every head recomputed; the header still declares the
    sealed head, so the chain stops replaying only at 11. The 6..11 receipt is
    the service's word and does not match: N is 6, not 11."""
    from crucible_chain.chain import GENESIS, link

    ex = control()
    sealed = minter.mint(entries_for(ex.records, [(0, 5), (6, 11)], minter), service_key)
    forged = copy.deepcopy(ex.records)
    forged[7]["event"]["body"] = {"rewritten": True}
    prev = GENESIS
    for r in forged:
        prev = link(prev, r["event"])
        r["head"] = prev
    r = report(forged, sealed, service_key.public(), count=12, head=ex.header["head"])
    assert (r.verdict.state, r.at) == (State.FAIL, 6)
    r = report(forged[:9], sealed, service_key.public(), count=12, head=ex.header["head"])  # tail dropped instead
    assert (r.verdict.state, r.at) == (State.FAIL, 6)


def test_a_stored_head_replaced_is_broken_there_when_the_events_match_what_was_sealed(minter, service_key):
    ex = read(CORPUS / "bad-link" / "chain.jsonl")
    sealed = minter.mint(entries_for(control().records, [(0, 11)], minter), service_key)
    r = report(ex.records, sealed, service_key.public(), count=12, head=ex.header["head"])
    assert (r.verdict.state, r.at) == (State.FAIL, 7)
    assert [x.check.state for x in r.receipts] == [State.PASS]


def test_a_record_emptied_of_events_with_its_receipts_kept_is_broken_at_0(minter, service_key):
    ex = control()
    rc = minter.mint(entries_for(ex.records, [(0, 11)], minter), service_key)
    from crucible_chain.chain import GENESIS

    r = report([], rc, service_key.public(), count=0, head=GENESIS)
    assert (r.verdict.state, r.at) == (State.FAIL, 0)


# --- keys --------------------------------------------------------------------------------


def test_the_wrong_key_file_gives_could_not_check_not_broken(minter, service_key):
    ex = control()
    rc = minter.mint(entries_for(ex.records, [(0, 11)], minter), service_key)
    r = report(ex.records, rc, PrivateKey.generate("service").public())
    assert r.verdict.state == State.COULD_NOT_CHECK and "no key with that id" in r.verdict.reason


def test_a_service_whose_key_changed_verifies_with_both_keys(minter, service_key):
    ex = control()
    k2 = PrivateKey.generate("service")
    entries = entries_for(ex.records, [(0, 5), (6, 11)], minter)
    rc = minter.mint(entries, service_key)
    later = minter.mint(entries, k2)[1]
    r = report(ex.records, [rc[0], later], [service_key.public(), k2.public()])
    assert r.verdict.state == State.PASS, r.verdict.reason
    r = report(ex.records, [rc[0], later], service_key.public())
    assert r.verdict.state == State.COULD_NOT_CHECK


# --- receipts must agree with each other ---------------------------------------------------


def test_two_roots_for_one_tree_size_fail(minter, service_key):
    ex = control()
    rc = minter.mint(entries_for(ex.records, [(0, 5), (6, 11)], minter), service_key, at="end")
    rc[0]["checkpoint"] = _same_size_other_root(minter, rc, service_key)  # each receipt verifies alone
    r = report(ex.records, rc, service_key.public())
    assert r.verdict.state == State.FAIL and "two roots for tree size 2" in r.verdict.reason
    assert r.at == 0


def _same_size_other_root(minter, rc, key):
    """A size-2 tree whose leaf 0 is rc[0]'s entry and whose leaf 1 is some other entry."""
    other = copy.deepcopy(rc[1]["entry"])
    other["payload"]["batch"] = "sha256:" + "cc" * 32
    leaves = [canonicalize(rc[0]["entry"]), canonicalize(other)]
    rc[0]["inclusion_path"] = [minter.hex(p) for p in minter.path(0, leaves)]
    return minter.checkpoint_envelope(leaves, 2, key, service="test.service", log_id="log-1", ts=1_761_264_100_000_000)


def test_two_roots_for_one_size_fail_even_when_the_receipts_between_cannot_be_linked(minter, service_key):
    # A at size 3 (root X), B at size 4 with no proof, C at size 3 (root Y): the
    # links alone could only say could_not_check; the two roots for size 3 are a fork.
    ex = control()
    ea, eb, ec = entries_for(ex.records, [(0, 3), (4, 7), (8, 11)], minter)
    filler = copy.deepcopy(ea)
    filler["payload"]["session"] = "someone-else"
    a = minter.mint([ea, eb, filler], service_key, at="end")[0]
    b = minter.mint([ea, eb, filler, filler], service_key, at="end")[1]
    c = minter.mint([filler, filler, ec], service_key, at="end")[2]
    r = report(ex.records, [a, b, c], service_key.public())
    assert r.verdict.state == State.FAIL and "two roots for tree size 3" in r.verdict.reason


def test_two_entries_at_one_leaf_fail(minter, service_key):
    ex = control()
    entries = entries_for(ex.records, [(0, 5), (6, 11)], minter)
    rc = minter.mint(entries, service_key, at="end")  # one tree of size 2
    twin = copy.deepcopy(entries[0])
    twin["payload"]["batch"] = "sha256:" + "cc" * 32  # another entry for the same span, at leaf 0 of a size-3 tree
    forked = minter.mint([twin, entries[1], entries[1]], service_key, at="end")[0]
    r = report(ex.records, rc + [forked], service_key.public())
    assert r.verdict.state == State.FAIL and "two entries at leaf 0" in r.verdict.reason


def test_a_later_span_earlier_in_the_log_fails(minter, service_key):
    ex = control()
    entries = entries_for(ex.records, [(6, 11), (0, 5)], minter)  # 6..11 logged first
    r = report(ex.records, minter.mint(entries, service_key), service_key.public())
    assert r.verdict.state == State.FAIL and "not after leaf" in r.verdict.reason


def test_overlapping_spans_fail(minter, service_key):
    ex = control()
    entries = entries_for(ex.records, [(0, 7), (4, 11)], minter)
    r = report(ex.records, minter.mint(entries, service_key), service_key.public())
    assert r.verdict.state == State.FAIL and "anchored twice" in r.verdict.reason


def test_one_session_in_two_logs_fails(minter, service_key):
    ex = control()
    entries = entries_for(ex.records, [(0, 5), (6, 11)], minter)
    a = minter.mint(entries, service_key, log_id="log-1")
    b = minter.mint(entries, service_key, log_id="log-2")
    r = report(ex.records, [a[0], b[1]], service_key.public())
    assert r.verdict.state == State.FAIL and "2 logs" in r.verdict.reason


def test_a_tree_that_is_not_a_prefix_of_the_later_one_fails(minter, service_key):
    ex = control()
    rc = minter.mint(entries_for(ex.records, [(0, 5), (6, 11)], minter), service_key)
    rc[1]["consistency"]["path"][0] = "sha256:" + "55" * 32
    r = report(ex.records, rc, service_key.public())
    assert r.verdict.state == State.FAIL and "not a prefix" in r.verdict.reason and r.at == 0


def test_two_receipts_that_cannot_be_linked_could_not_be_checked(minter, service_key):
    ex = control()
    rc = minter.mint(entries_for(ex.records, [(0, 5), (6, 11)], minter), service_key)
    rc[1]["consistency"] = None
    r = report(ex.records, rc, service_key.public())
    assert r.verdict.state == State.COULD_NOT_CHECK and "no consistency proof" in r.verdict.reason


def test_receipts_issued_as_the_service_does_link_and_are_intact(minter, service_key):
    ex = control()
    rc = minter.mint(entries_for(ex.records, [(0, 2), (3, 5), (6, 9), (10, 11)], minter), service_key)
    r = report(ex.records, rc, service_key.public())
    assert r.verdict.state == State.PASS, r.verdict.reason
    link = next(c for c in r.checks if c.name == "link")
    assert link.state == State.PASS


# --- formats, versions, timestamps -----------------------------------------------------------


@pytest.mark.parametrize("where", ["receipt", "entry", "checkpoint"])
def test_an_unknown_format_version_could_not_be_checked(minter, service_key, where):
    ex = control()
    rc = minter.mint(entries_for(ex.records, [(0, 11)], minter), service_key)
    if where == "receipt":
        rc[0]["v"] = 99
    elif where == "entry":
        rc[0]["entry"]["v"] = 99
    else:
        resign(rc[0], service_key, v=99)
    r = report(ex.records, rc, service_key.public())
    assert r.verdict.state == State.COULD_NOT_CHECK and "version 99" in r.verdict.reason


@pytest.mark.parametrize("change", [{"service": None}, {"service": ""}, {"log_id": " "}, {"kind": "tree"}, {"ts": -10}])
def test_a_checkpoint_that_does_not_say_what_it_is_fails(minter, service_key, change):
    ex = control()
    rc = minter.mint(entries_for(ex.records, [(0, 11)], minter), service_key)
    resign(rc[0], service_key, **change)
    if "service" in change:
        rc[0]["service"] = change["service"]
    if "log_id" in change:
        rc[0]["log_id"] = change["log_id"]
    r = report(ex.records, rc, service_key.public())
    assert r.verdict.state == State.FAIL


@pytest.mark.parametrize("ts", [-5, 0, 1_761_264_100_000_001])
def test_an_entry_timestamp_outside_the_checkpoint_fails(minter, service_key, ts):
    ex = control()
    entry = entries_for(ex.records, [(0, 11)], minter)[0]
    entry["ts"] = ts  # the checkpoint is at 1_761_264_100_000_000
    r = report(ex.records, minter.mint([entry], service_key), service_key.public())
    assert r.verdict.state == State.FAIL and "timestamp" in r.verdict.reason


def test_a_checkpoint_in_non_canonical_base64_fails(minter, service_key):
    ex = control()
    rc = minter.mint(entries_for(ex.records, [(0, 11)], minter), service_key)
    raw = base64.b64decode(rc[0]["checkpoint"])
    text = base64.b64encode(raw).decode()
    if text.endswith("="):
        # Set a pad bit: decodes to the same bytes, but is a second spelling.
        body = text.rstrip("=")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        body = body[:-1] + alphabet[alphabet.index(body[-1]) + 1]
        rc[0]["checkpoint"] = body + "=" * (len(text) - len(text.rstrip("=")))
        assert base64.b64decode(rc[0]["checkpoint"]) == raw
        r = report(ex.records, rc, service_key.public())
        assert r.verdict.state == State.FAIL and "canonical base64" in r.verdict.reason


# --- one encoding per signed object -------------------------------------------------------------


@pytest.mark.parametrize("change", ["trailing", "unprotected", "crit"])
def test_an_envelope_in_another_encoding_is_refused(service_key, change):
    import cbor2

    raw = sign({"a": 1}, service_key)
    tag = cbor2.loads(raw)
    protected, unprotected, payload, sig = tag.value
    if change == "trailing":
        bad = raw + cbor2.dumps(0)
    elif change == "unprotected":
        bad = cbor2.dumps(cbor2.CBORTag(18, [protected, {4: service_key.key_id.encode()}, payload, sig]))
    else:
        hdr = cbor2.loads(protected)
        hdr[2] = [99]
        bad = cbor2.dumps(cbor2.CBORTag(18, [cbor2.dumps(hdr), {}, payload, sig]))
    with pytest.raises(SignatureError):
        verify(bad, service_key.public())
    verify(raw, service_key.public())


# --- what the report names ---------------------------------------------------------------------


def test_the_report_names_the_service_log_key_and_time(minter, service_key):
    ex = control()
    rc = minter.mint(entries_for(ex.records, [(0, 5), (6, 11)], minter), service_key)
    r = report(ex.records, rc, service_key.public())
    text = r.render()
    assert f"by test.service (log log-1, key {service_key.key_id})" in text
    assert "server time 1761264050000011" in text
    js = r.to_json()
    assert [x["to_seq"] for x in js["receipts"]] == [5, 11]
    assert js["receipts"][1]["key_id"] == service_key.key_id and js["receipts"][1]["tree_size"] == 2


# --- the export's unsigned copy of a span --------------------------------------------------------


def test_an_export_line_whose_span_disagrees_with_its_receipt_is_refused(minter, service_key):
    ex = control()
    rc = minter.mint(entries_for(ex.records, [(0, 11)], minter), service_key)
    text = dumps(SESSION, ex.records, [{"to_seq": 3, "receipt": rc[0]}])
    with pytest.raises(ExportError, match="to_seq"):
        loads(text)


# --- the CLI: only verdicts look like verdicts ------------------------------------------------------


def _cli(*args):
    return subprocess.run([sys.executable, "-m", "crucible_verify.cli", *map(str, args)], capture_output=True, text=True)


def test_cli_usage_errors_are_not_verdicts():
    assert _cli().returncode == 64
    assert _cli("--bogus", "x").returncode == 64


def test_cli_unreadable_keys_are_not_verdicts(tmp_path, service_key):
    rec = CORPUS / "control" / "chain.jsonl"
    assert _cli(rec, "--service-key", tmp_path).returncode == 4  # a directory
    junk = tmp_path / "junk.json"
    junk.write_bytes(b"\xff\xfe")
    assert _cli(rec, "--service-key", junk).returncode == 4
    researcher = tmp_path / "researcher.pub.json"
    PrivateKey.generate("researcher").public().write(researcher)
    assert _cli(rec, "--service-key", researcher).returncode == 4


@pytest.mark.parametrize("depth", [900, 986, 988, 990, 5000])
def test_a_deeply_nested_event_is_a_verdict_or_unreadable_not_a_crash(tmp_path, depth):
    lines = (CORPUS / "control" / "chain.jsonl").read_text().split("\n")
    assert lines[3].count('"body":{}') == 1  # event 2, a prompt with an empty body
    lines[3] = lines[3].replace('"body":{}', '"body":' + '{"x":' * depth + "{}" + "}" * depth)
    path = tmp_path / "deep.jsonl"
    path.write_text("\n".join(lines))
    out = _cli(path)
    assert out.returncode in (1, 4), out.stdout + out.stderr
    assert "internal error" not in out.stderr and "Traceback" not in out.stderr


# --- from the fresh review of the fixes --------------------------------------------------------


def test_a_receipt_that_is_not_the_services_word_cannot_choose_n(minter, service_key):
    """Event 7 changed, heads and header recomputed, the 6..11 receipt replaced by
    junk claiming 11: nothing anchors 6..10, so N is 6, not the 11 the junk names."""
    from crucible_chain.chain import GENESIS, link

    ex = control()
    good = minter.mint(entries_for(ex.records, [(0, 5), (6, 11)], minter), service_key)
    forged = copy.deepcopy(ex.records)
    forged[7]["event"]["body"] = {"rewritten": True}
    prev = GENESIS
    for r in forged:
        prev = link(prev, r["event"])
        r["head"] = prev
    junk = copy.deepcopy(good[1])
    junk["entry"]["payload"]["from_seq"] = 11
    r = report(forged, [good[0], junk], service_key.public(), count=12, head=forged[-1]["head"])
    assert (r.verdict.state, r.at) == (State.FAIL, 6)


def test_overlapping_spans_break_at_the_first_event_either_covers(minter, service_key):
    ex = control()
    for order in ([(0, 11), (6, 7)], [(6, 7), (0, 11)]):
        r = report(ex.records, minter.mint(entries_for(ex.records, order, minter), service_key), service_key.public())
        assert (r.verdict.state, r.at) == (State.FAIL, 0), order


def test_receipts_from_two_logs_break_at_the_first_event_any_covers(minter, service_key):
    ex = control()
    a = minter.mint(entries_for(ex.records, [(3, 4), (0, 11)], minter), service_key, log_id="log-A")
    b = minter.mint(entries_for(ex.records, [(6, 7)], minter), service_key, log_id="log-B")
    r = report(ex.records, a + b, service_key.public())
    assert (r.verdict.state, r.at) == (State.FAIL, 0) and "2 logs" in r.verdict.reason


def test_an_empty_record_declaring_a_head_is_broken_not_not_applicable():
    r = report([], [], None, count=0, head="sha256:" + "ab" * 32)
    assert (r.verdict.state, r.at) == (State.FAIL, 0)
    from crucible_chain.chain import GENESIS

    assert report([], [], None, count=0, head=GENESIS).verdict.state == State.NOT_APPLICABLE


@pytest.mark.parametrize("change", [
    lambda e: e.__setitem__("class", ["witnessed"]),
    lambda e: e.__setitem__("class", {}),
    lambda e: e.__setitem__("body", ["x"]) if e["type"] == "gap" else None,
])
def test_an_event_of_any_shape_gets_a_verdict(change):
    ex = control()
    recs = copy.deepcopy(ex.records)
    change(recs[10]["event"])  # event 10 is the gap
    change(recs[5]["event"])
    r = report(recs, [], None, count=12, head=ex.header["head"])
    assert r.verdict.state == State.FAIL


def test_the_receipts_check_does_not_read_fail_when_nothing_failed(minter, service_key):
    ex = control()
    rc = minter.mint(entries_for(ex.records, [(0, 11)], minter), service_key)
    other = minter.mint(entries_for(ex.records, [(0, 11)], minter), PrivateKey.generate("service"))
    r = report(ex.records, rc + other, service_key.public())
    receipts = next(c for c in r.checks if c.name == "receipts")
    assert receipts.state == State.COULD_NOT_CHECK and r.verdict.state == State.COULD_NOT_CHECK


def test_records_without_a_seq_field_are_read_by_position(minter, service_key):
    ex = control()
    rc = minter.mint(entries_for(ex.records, [(0, 11)], minter), service_key)
    bare = [{"event": r["event"]} for r in ex.records]
    assert report(bare, rc, service_key.public()).verdict.state == State.PASS


def _serve_once(body: bytes, declared: int, status_line: bytes = b"HTTP/1.1 200 OK"):
    """A one-shot server that announces ``declared`` bytes and sends ``body``, then hangs up."""
    import socket
    import threading

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        conn.recv(65536)
        conn.sendall(status_line + b"\r\nContent-Length: " + str(declared).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        conn.close()
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return f"http://127.0.0.1:{srv.getsockname()[1]}/export"


def test_a_record_cut_short_in_transit_is_unreadable_not_a_verdict():
    whole = (CORPUS / "control" / "chain.jsonl").read_bytes()
    cut = whole[: whole.index(b"\n", len(whole) // 2) + 1]
    out = _cli(_serve_once(cut, len(whole)))
    assert out.returncode == 4 and "arrived as" in out.stderr


def test_a_malformed_http_answer_is_unreadable_not_an_internal_error():
    out = _cli(_serve_once(b"", 0, status_line=b"HTTP/1.1 abc"))
    assert out.returncode == 4, out.stderr


def test_a_key_file_nested_too_deep_is_unreadable(tmp_path):
    key = tmp_path / "deep.json"
    key.write_text("[" * 100000)
    assert _cli(CORPUS / "control" / "chain.jsonl", "--service-key", key).returncode == 4


# --- from the second fresh review of the fixes ---------------------------------------------------


@pytest.mark.parametrize("variant", ["header-left-as-sealed", "receipt-dropped", "receipt-edited", "count-raised"])
def test_a_later_break_does_not_hide_an_earlier_unanchored_change(minter, service_key, variant):
    """Event 7 rewritten, heads recomputed; the 6..11 receipt that would refute it is
    dropped or made unverifiable, and something further on stops the replay.
    Nothing anchors 6..10, so N is 6 whatever stops the replay later."""
    from crucible_chain.chain import GENESIS, link

    ex = control()
    good = minter.mint(entries_for(ex.records, [(0, 5), (6, 11)], minter), service_key)
    forged = copy.deepcopy(ex.records)
    forged[7]["event"]["body"] = {"rewritten": True}
    prev = GENESIS
    for r in forged:
        prev = link(prev, r["event"])
        r["head"] = prev
    receipts, count, head = [good[0]], 12, ex.header["head"]  # the header's head as sealed
    if variant == "receipt-edited":
        bad = copy.deepcopy(good[1])
        bad["service"] = "other.service"
        receipts.append(bad)
    elif variant == "count-raised":
        count, head = 13, forged[-1]["head"]
    elif variant == "header-left-as-sealed":
        receipts.append(good[1])
    r = report(forged, receipts, service_key.public(), count=count, head=head)
    assert (r.verdict.state, r.at) == (State.FAIL, 6), r.verdict.reason


@pytest.mark.parametrize("value", ["inf", "nan", "-1", "0", "abc", "1e9"])
def test_cli_timeout_values_that_are_not_a_timeout_are_usage_errors(value):
    out = _cli(CORPUS / "control" / "chain.jsonl", "--timeout", value)
    assert out.returncode == 64, out.stderr


@pytest.mark.parametrize("receipts", ["wrong-key", "junk-only", "none"])
def test_a_receipt_that_does_not_hold_never_moves_the_chains_own_break(minter, service_key, receipts):
    ex = read(CORPUS / "bad-link" / "chain.jsonl")
    if receipts == "wrong-key":
        rc = minter.mint(entries_for(control().records, [(0, 11)], minter), PrivateKey.generate("service"))
    elif receipts == "junk-only":
        rc = [{"entry": {"payload": {"from_seq": 0}}}]
    else:
        rc = []
    r = report(ex.records, rc, service_key.public(), count=12, head=ex.header["head"])
    assert (r.verdict.state, r.at) == (State.FAIL, 7)


def test_when_the_clamp_moves_n_the_verdict_says_why(minter, service_key):
    from crucible_chain.chain import GENESIS, link

    ex = control()
    good = minter.mint(entries_for(ex.records, [(0, 5), (6, 11)], minter), service_key)
    forged = copy.deepcopy(ex.records)
    forged[7]["event"]["body"] = {"rewritten": True}
    prev = GENESIS
    for r in forged:
        prev = link(prev, r["event"])
        r["head"] = prev
    r = report(forged, [good[0]], service_key.public(), count=12, head=ex.header["head"])
    assert r.at == 6 and "nothing after event 5 is anchored" in r.verdict.reason


@pytest.mark.parametrize("anchored", ["nothing", "0..2"])
def test_a_receipt_that_does_not_verify_is_placed_where_it_claims_or_where_anchoring_ends(minter, service_key, anchored):
    # A real receipt for 7..11 with its entry hash zeroed: it does not verify, so it says
    # nothing about what was sealed. With nothing anchored it is placed at the first event
    # it claims; with 0..2 anchored, at 3, and the verdict says why N moved.
    ex = control()
    rcs = minter.mint(entries_for(ex.records, [(0, 2), (7, 11)], minter), service_key)
    rcs[1]["entry_hash"] = "sha256:" + "00" * 32
    r = report(ex.records, rcs[1:] if anchored == "nothing" else rcs, service_key.public())
    if anchored == "nothing":
        assert (r.verdict.state, r.at) == (State.FAIL, 7) and "does not verify" in r.verdict.reason
    else:
        assert (r.verdict.state, r.at) == (State.FAIL, 3)
        assert "nothing after event 2 is anchored" in r.verdict.reason and "does not verify" in r.verdict.reason
