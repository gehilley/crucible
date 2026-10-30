"""The chain rule h_n = H(h_{n-1} || canonical(event_n)) (SPEC.md §3, §4).

The known answers here are computed independently in the test with hashlib and
rfc8785 directly, so a wrong construction in `crucible_chain.chain` cannot agree
with them by sharing a mistake.
"""

from __future__ import annotations

import hashlib

import pytest
import rfc8785

from crucible_chain.chain import GENESIS, link, replay
from crucible_chain.events import PROTOCOL_VERSION, digest_only

SESSION = "s-1"


def event(seq, ts=None, **over):
    e = {
        "v": PROTOCOL_VERSION,
        "session": SESSION,
        "seq": seq,
        "ts": ts if ts is not None else 1000 + seq,
        "type": "prompt",
        "actor": "human",
        "class": "witnessed",
        "body": {},
        **digest_only({"n": seq}),
    }
    e.update(over)
    return e


def independent_head(prev_hex: str, ev: dict) -> str:
    return "sha256:" + hashlib.sha256(bytes.fromhex(prev_hex) + rfc8785.dumps(ev)).hexdigest()


def test_genesis_is_thirty_two_zero_bytes():
    assert GENESIS == "sha256:" + "00" * 32


def test_link_matches_an_independent_computation():
    e0, e1, e2 = event(0), event(1), event(2)
    h0 = independent_head("00" * 32, e0)
    h1 = independent_head(h0[7:], e1)
    h2 = independent_head(h1[7:], e2)
    assert link(GENESIS, e0) == h0
    assert link(h0, e1) == h1
    assert link(h1, e2) == h2


def test_the_hash_covers_every_field_of_the_event():
    base = event(0)
    h = link(GENESIS, base)
    for field, value in [("ts", 9999), ("actor", "tool:Read"), ("body", {"x": 1}), ("class", "sealed")]:
        assert link(GENESIS, {**base, field: value}) != h, field


def records(n=6):
    out, prev = [], GENESIS
    for i in range(n):
        e = event(i)
        prev = link(prev, e)
        out.append({"seq": i, "head": prev, "event": e})
    return out


def test_an_intact_chain_replays_to_its_head():
    recs = records()
    r = replay(recs)
    assert r.broken_at is None and r.reason is None
    assert r.count == 6 and r.head == recs[-1]["head"]


def test_an_empty_chain_is_intact_at_genesis():
    r = replay([])
    assert r.broken_at is None and r.count == 0 and r.head == GENESIS


@pytest.mark.parametrize("n", [0, 3, 5])
def test_an_altered_event_breaks_at_that_event(n):
    recs = records()
    recs[n]["event"] = {**recs[n]["event"], **digest_only({"n": "tampered"})}
    assert replay(recs).broken_at == n


@pytest.mark.parametrize("n", [0, 2, 5])
def test_an_altered_head_breaks_at_that_event(n):
    recs = records()
    recs[n]["head"] = "sha256:" + "ab" * 32
    assert replay(recs).broken_at == n


@pytest.mark.parametrize("n", [0, 2, 4])
def test_a_missing_event_breaks_at_the_missing_seq(n):
    recs = records()
    del recs[n]
    r = replay(recs)
    assert r.broken_at == n and "seq" in r.reason


def test_swapped_events_break_at_the_first_of_them():
    recs = records()
    recs[2], recs[3] = recs[3], recs[2]
    assert replay(recs).broken_at == 2


def test_a_timestamp_that_does_not_increase_breaks_there():
    recs, prev = [], GENESIS
    for i, ts in enumerate([10, 20, 20, 30]):
        e = event(i, ts=ts)
        prev = link(prev, e)
        recs.append({"seq": i, "head": prev, "event": e})
    r = replay(recs)
    assert r.broken_at == 2 and "ts" in r.reason


def test_an_event_from_another_session_breaks_there():
    recs, prev = [], GENESIS
    for i in range(4):
        e = event(i, session="other" if i == 3 else SESSION)
        prev = link(prev, e)
        recs.append({"seq": i, "head": prev, "event": e})
    r = replay(recs)
    assert r.broken_at == 3 and "session" in r.reason


def test_an_invalid_event_breaks_there_even_if_its_head_is_consistent():
    recs, prev = [], GENESIS
    for i in range(4):
        e = event(i, type="thought" if i == 1 else "prompt")
        prev = link(prev, e)
        recs.append({"seq": i, "head": prev, "event": e})
    r = replay(recs)
    assert r.broken_at == 1 and "type" in r.reason


def test_a_declared_count_beyond_the_records_is_a_truncated_tail():
    recs = records(9)
    r = replay(recs, declared_count=12)
    assert r.broken_at == 9 and "truncated" in r.reason


def test_a_declared_head_that_disagrees_breaks_at_the_last_event():
    recs = records(5)
    r = replay(recs, declared_count=5, declared_head="sha256:" + "cd" * 32)
    assert r.broken_at == 4 and "declared head" in r.reason


def test_records_without_stored_heads_are_checked_on_their_events_alone():
    recs = [{"seq": r["seq"], "event": r["event"]} for r in records()]
    assert replay(recs).broken_at is None
    recs[3]["event"] = {**recs[3]["event"], "seq": 9}
    assert replay(recs).broken_at == 3


def test_a_batch_continuing_a_chain_replays_from_the_head_before_it():
    recs = records(8)
    tail = [{"seq": r["seq"], "event": r["event"]} for r in recs[5:]]
    r = replay(tail, start=recs[4]["head"], first_seq=5, prev_ts=recs[4]["event"]["ts"])
    assert r.broken_at is None and r.count == 8 and r.head == recs[-1]["head"]


def test_a_continuing_batch_names_breaks_by_their_chain_position():
    recs = records(8)
    tail = [{"seq": r["seq"], "event": r["event"]} for r in recs[5:]]
    # From the wrong head, unheaded records still chain consistently; only the
    # declared final head can show it, and it shows at the last event.
    assert replay(tail, start=recs[3]["head"], first_seq=5).broken_at is None
    assert replay(tail, start=recs[3]["head"], first_seq=5, declared_head=recs[7]["head"]).broken_at == 7
    assert replay(tail, start=recs[4]["head"], first_seq=6).broken_at == 6  # starts at the wrong seq
    late = recs[4]["event"]["ts"] + 10**6
    assert replay(tail, start=recs[4]["head"], first_seq=5, prev_ts=late).broken_at == 5
