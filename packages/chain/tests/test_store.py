"""The client's local chain store.

The store assigns ``seq`` and the monotonic timestamp inside one IMMEDIATE
transaction, so hooks running as separate, concurrent processes cannot mint the
same position or a timestamp that goes backwards.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys

import pytest

from crucible_chain.chain import GENESIS, link, replay
from crucible_chain.events import draft
from crucible_chain.store import ChainStore, StoreError

S = "session-a"


def d(i=0):
    return draft("prompt", "human", "witnessed", {}, content={"text": f"prompt {i}"})


def test_append_assigns_contiguous_seq_and_chains_heads(tmp_path):
    with ChainStore(tmp_path / "chain.sqlite") as store:
        recs = [store.append(S, d(i)) for i in range(5)]
    assert [r.seq for r in recs] == [0, 1, 2, 3, 4]
    prev = GENESIS
    for r in recs:
        prev = link(prev, r.event)
        assert r.head == prev
        assert r.event["session"] == S and r.event["seq"] == r.seq


def test_sessions_have_separate_chains(tmp_path):
    with ChainStore(tmp_path / "chain.sqlite") as store:
        a0 = store.append("a", d())
        b0 = store.append("b", d())
        a1 = store.append("a", d())
        assert (a0.seq, b0.seq, a1.seq) == (0, 0, 1)
        assert store.sessions() == ["a", "b"]
        assert replay([r.as_record() for r in store.records("a")]).broken_at is None


def test_the_timestamp_strictly_increases_even_when_the_clock_goes_back(tmp_path):
    clock = iter([5_000, 4_000, 4_000, 9_000]).__next__
    with ChainStore(tmp_path / "chain.sqlite", clock=clock) as store:
        ts = [store.append(S, d()).event["ts"] for _ in range(4)]
    assert ts == [5_000, 5_001, 5_002, 9_000]


def test_stored_events_cannot_be_updated_or_deleted(tmp_path):
    path = tmp_path / "chain.sqlite"
    with ChainStore(path) as store:
        store.append(S, d())
    conn = sqlite3.connect(path)
    for sql in ("UPDATE events SET head = 'x'", "DELETE FROM events"):
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute(sql)
    conn.close()


def test_receipts_are_append_only_and_track_what_is_unsent(tmp_path):
    path = tmp_path / "chain.sqlite"
    with ChainStore(path) as store:
        for i in range(5):
            store.append(S, d(i))
        assert [r.seq for r in store.unsent(S)] == [0, 1, 2, 3, 4]
        store.add_receipt(S, 2, {"entry_hash": "sha256:" + "11" * 32})
        assert store.last_receipted_seq(S) == 2
        assert [r.seq for r in store.unsent(S)] == [3, 4]
        with pytest.raises(StoreError):
            store.add_receipt(S, 2, {"entry_hash": "sha256:" + "22" * 32})
    conn = sqlite3.connect(path)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM receipts")
    conn.close()


def test_an_invalid_draft_is_refused_and_nothing_is_stored(tmp_path):
    with ChainStore(tmp_path / "chain.sqlite") as store:
        bad = {**d(), "type": "thought"}
        with pytest.raises(Exception, match="type"):
            store.append(S, bad)
        assert store.head(S) is None


_WRITER = """
import sys
from crucible_chain.events import draft
from crucible_chain.store import ChainStore
path, worker, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
with ChainStore(path) as store:
    for i in range(n):
        store.append("session-a", draft("tool.result", "tool:Bash", "witnessed", {"w": worker}, content={"i": i}))
"""


def test_concurrent_processes_never_mint_the_same_position(tmp_path):
    """Four separate processes append at once, the way parallel hooks do."""
    path = tmp_path / "chain.sqlite"
    ChainStore(path).close()
    procs = [subprocess.Popen([sys.executable, "-c", _WRITER, str(path), str(w), "25"]) for w in range(4)]
    for p in procs:
        assert p.wait(120) == 0
    with ChainStore(path) as store:
        recs = [r.as_record() for r in store.records(S)]
    assert [r["seq"] for r in recs] == list(range(100))
    assert replay(recs).broken_at is None
    assert len({r["event"]["ts"] for r in recs}) == 100
