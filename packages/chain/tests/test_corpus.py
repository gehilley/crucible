"""The planted-answer corpus (SPEC.md §8 rule 4).

`corpus/` at the repository root holds one intact control chain and one chain
per planted break, each with a manifest stating the expected verdict and, for a
break, the event N it must be reported at. The generator is deterministic, so
the committed files must equal a fresh generation byte for byte.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from crucible_chain.chain import replay
from crucible_chain.corpus import FIXTURES, generate
from crucible_chain.export import read

CORPUS = Path(__file__).resolve().parents[3] / "corpus"


def test_the_committed_corpus_equals_a_fresh_generation(tmp_path):
    generate(tmp_path)
    fresh = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*") if p.is_file())
    committed = sorted(p.relative_to(CORPUS) for p in CORPUS.rglob("*") if p.is_file())
    assert fresh == committed
    for rel in fresh:
        assert (tmp_path / rel).read_bytes() == (CORPUS / rel).read_bytes(), rel


def test_there_is_one_control_and_every_planted_kind_of_break():
    names = set(FIXTURES)
    assert "control" in names
    assert {
        "altered-event",
        "missing-seq",
        "bad-link",
        "truncated-tail",
        "reordered",
        "ts-not-increasing",
        "foreign-session",
        "type-outside-vocabulary",
        "header-head-replaced",
    } <= names


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_each_fixture_replays_to_its_manifest(name):
    manifest = json.loads((CORPUS / name / "manifest.json").read_text())
    ex = read(CORPUS / name / "chain.jsonl")
    r = replay(ex.records, session=ex.header["session"], declared_count=ex.header["count"], declared_head=ex.header["head"])
    expect = manifest["expect"]
    if expect["verdict"] == "intact":
        assert r.intact, r.reason
    else:
        assert expect["verdict"] == "broken"
        assert r.broken_at == expect["at"], (r.broken_at, r.reason)
        # Each plant is caught by the rule it is named for, not by another rule
        # that happens to fire at the same event.
        assert r.rule == expect["rule"], (expect["rule"], r.rule, r.reason)


def test_every_break_states_n_in_machine_form():
    for name in FIXTURES:
        manifest = json.loads((CORPUS / name / "manifest.json").read_text())
        if manifest["expect"]["verdict"] == "broken":
            assert isinstance(manifest["expect"]["at"], int), name


@pytest.mark.parametrize("name", sorted(n for n, f in FIXTURES.items() if f[1] not in (None, "head")))
def test_every_head_is_consistent_where_the_plant_is_not_a_head(name):
    """So that the only rule that can catch the plant is the one it is named for."""
    from crucible_chain.chain import GENESIS, link

    records, _header = FIXTURES[name][3]()
    prev = GENESIS
    for r in records:
        prev = link(prev, r["event"])
        assert r["head"] == prev, (name, r["seq"])
