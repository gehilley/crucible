"""A session's chain exported as JSON lines, readable without the store."""

from __future__ import annotations

import json

import pytest

from crucible_chain.chain import replay
from crucible_chain.events import draft
from crucible_chain.export import ExportError, read, write
from crucible_chain.store import ChainStore

S = "session-x"


@pytest.fixture
def exported(tmp_path):
    with ChainStore(tmp_path / "chain.sqlite") as store:
        for i in range(6):
            store.append(S, draft("prompt", "human", "witnessed", {}, content={"i": i}))
        store.add_receipt(S, 5, {"entry_hash": "sha256:" + "33" * 32})
        path = write(store, S, tmp_path / "out.jsonl")
    return path


def test_round_trip_replays_intact(exported):
    ex = read(exported)
    assert ex.header["session"] == S and ex.header["count"] == 6
    assert [r["seq"] for r in ex.records] == list(range(6))
    assert ex.receipts == [{"to_seq": 5, "receipt": {"entry_hash": "sha256:" + "33" * 32}}]
    r = replay(ex.records, declared_count=ex.header["count"], declared_head=ex.header["head"])
    assert r.broken_at is None


def test_altering_one_line_breaks_at_that_event(exported):
    lines = exported.read_text().splitlines()
    rec = json.loads(lines[1 + 4])
    rec["event"]["body"] = {"edited": True}
    lines[1 + 4] = json.dumps(rec)
    exported.write_text("\n".join(lines) + "\n")
    ex = read(exported)
    assert replay(ex.records, declared_count=ex.header["count"], declared_head=ex.header["head"]).broken_at == 4


def test_a_line_with_two_readings_is_refused(exported):
    text = exported.read_text()
    assert '"kind":"event"' in text
    exported.write_text(text.replace('"kind":"event"', '"kind":"event","kind":"receipt"', 1))
    with pytest.raises(ExportError):
        read(exported)


def test_the_first_line_must_be_the_header(exported):
    lines = exported.read_text().splitlines()
    exported.write_text("\n".join(lines[1:] + lines[:1]) + "\n")
    with pytest.raises(ExportError, match="header"):
        read(exported)
