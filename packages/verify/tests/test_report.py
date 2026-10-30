"""The §7 report against planted known answers.

The corpus (step 2) supplies the chain breaks; receipts are minted here by an
independent RFC 6962 builder (conftest.py) and then planted wrong one way at a
time.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from crucible_chain.corpus import FIXTURES
from crucible_chain.export import read
from crucible_core.keys import PrivateKey
from crucible_verify.report import verify_record
from crucible_verify.results import State

CORPUS = Path(__file__).resolve().parents[3] / "corpus"


def load(name):
    ex = read(CORPUS / name / "chain.jsonl")
    return ex, json.loads((CORPUS / name / "manifest.json").read_text())


def report(ex, receipts=(), key=None):
    return verify_record(
        ex.records, list(receipts), service_key=key, session=ex.header["session"],
        declared_count=ex.header["count"], declared_head=ex.header["head"],
    )


@pytest.mark.parametrize("name", sorted(n for n, (at, *_rest) in FIXTURES.items() if at is not None))
def test_every_planted_break_is_reported_at_its_manifest_n(name):
    ex, manifest = load(name)
    r = report(ex)
    assert r.verdict.state == State.FAIL
    assert r.at == manifest["expect"]["at"]
    assert r.says == f"broken at event {manifest['expect']['at']}"


def test_the_control_with_no_receipts_could_not_be_checked():
    ex, _ = load("control")
    r = report(ex)
    assert r.verdict.state == State.COULD_NOT_CHECK
    assert "no receipt" in r.verdict.reason
    assert r.says.startswith("could_not_check(")


def test_a_missing_service_key_reports_could_not_check(receipts_for, service_key):
    ex, _ = load("control")
    rc = receipts_for(ex.records, [(0, 5), (6, 11)], service_key)
    r = report(ex, rc, key=None)
    assert r.verdict.state == State.COULD_NOT_CHECK
    assert "service public key" in r.verdict.reason


def test_the_control_with_valid_receipts_is_intact(receipts_for, service_key):
    ex, _ = load("control")
    rc = receipts_for(ex.records, [(0, 5), (6, 11)], service_key)
    r = report(ex, rc, key=service_key.public())
    assert r.verdict.state == State.PASS, r.verdict.reason
    assert r.says == "intact"
    assert r.services == ["test.service"]


def test_an_unanchored_tail_is_not_called_intact(receipts_for, service_key):
    ex, _ = load("control")
    rc = receipts_for(ex.records, [(0, 5)], service_key)
    r = report(ex, rc, key=service_key.public())
    assert r.verdict.state == State.COULD_NOT_CHECK
    assert "6..11" in r.verdict.reason


def test_a_receipt_signed_by_a_key_not_given_could_not_be_checked(receipts_for, service_key):
    ex, _ = load("control")
    other = PrivateKey.generate("service")
    rc = receipts_for(ex.records, [(0, 5), (6, 11)], other)
    r = report(ex, rc, key=service_key.public())
    assert r.verdict.state == State.COULD_NOT_CHECK
    assert other.key_id in r.verdict.reason and "no key with that id" in r.verdict.reason


def test_a_receipt_forged_under_the_given_key_id_fails(receipts_for, service_key):
    from crucible_core.cose import decode, sign_with

    ex, _ = load("control")
    rc = receipts_for(ex.records, [(0, 5), (6, 11)], service_key)
    impostor = PrivateKey.generate("service")
    import base64

    payload = decode(base64.b64decode(rc[1]["checkpoint"])).payload()
    rc[1]["checkpoint"] = base64.b64encode(sign_with(payload, service_key.key_id, impostor.obj.sign)).decode()
    r = report(ex, rc, key=service_key.public())
    assert r.verdict.state == State.FAIL and r.at == 6
    assert "not signed by service key" in r.verdict.reason


def test_a_receipt_anchoring_a_different_head_breaks_after_the_last_anchor_below_it(minter, service_key):
    ex, _ = load("control")
    entries = [
        minter.batch_entry(ex.header["session"], 0, 5, ex.records[5]["head"], ts=1_761_264_050_000_005),
        minter.batch_entry(ex.header["session"], 6, 11, "sha256:" + "ee" * 32, ts=1_761_264_050_000_011),  # sealed something else
    ]
    r = report(ex, minter.mint(entries, service_key), key=service_key.public())
    assert r.verdict.state == State.FAIL and r.at == 6
    assert "anchors head" in r.verdict.reason


@pytest.mark.parametrize(
    "plant,needle",
    [
        (lambda rc: rc["inclusion_path"].__setitem__(0, "sha256:" + "00" * 32), "not in the signed tree"),
        (lambda rc: rc["entry"].__setitem__("ts", rc["entry"]["ts"] + 1), "entry_hash"),
        (lambda rc: rc["entry"]["payload"].__setitem__("session", "other-session"), "entry_hash"),
        (lambda rc: rc.__setitem__("leaf_index", rc["leaf_index"] + 1), "not in the signed tree"),
        (lambda rc: rc.__setitem__("checkpoint", rc["checkpoint"][:-8] + "AAAAAAA="), "checkpoint"),
        (lambda rc: rc.__setitem__("service", "other.service"), "different service"),
        (lambda rc: rc.pop("entry_hash"), "not a receipt"),
    ],
)
def test_a_receipt_tampered_one_way_fails(receipts_for, service_key, plant, needle):
    ex, _ = load("control")
    rc = receipts_for(ex.records, [(0, 5), (6, 11)], service_key)
    plant(rc[1])
    r = report(ex, rc, key=service_key.public())
    assert r.verdict.state == State.FAIL, r.verdict.reason
    assert r.at == 6
    assert needle in r.verdict.reason


def test_a_receipt_for_another_session_fails(receipts_for, service_key):
    ex, _ = load("control")
    other = copy.deepcopy(ex.records)
    for rec in other:
        rec["event"]["session"] = "corpus-0002"
    rc = receipts_for(other, [(0, 11)], service_key)
    r = report(ex, rc, key=service_key.public())
    assert r.verdict.state == State.FAIL and "session" in r.verdict.reason


def test_the_evidence_profile_and_gap_list():
    ex, _ = load("control")
    r = report(ex)
    assert r.evidence["counts"] == {"witnessed": 9, "sealed": 3, "reconstructed": 0}
    assert r.evidence["total"] == 12
    assert r.gaps == [{"seq": 10, "could_not_see": "the system prompt the surface injected"}]


def test_an_empty_record_is_not_applicable():
    r = verify_record([], [], service_key=None)
    assert r.verdict.state == State.NOT_APPLICABLE
    assert r.says.startswith("not_applicable(")


def test_could_not_check_is_never_rendered_as_pass(receipts_for, service_key):
    ex, _ = load("control")
    text = report(ex).render()
    assert "UNCHECKED" in text and "intact" not in text.splitlines()[0]


def _cli(*args):
    return subprocess.run([sys.executable, "-m", "crucible_verify.cli", *map(str, args)], capture_output=True, text=True)


def test_the_cli_exit_status_names_the_verdict(tmp_path, receipts_for, service_key):
    assert _cli(CORPUS / "bad-link" / "chain.jsonl").returncode == 1
    assert _cli(CORPUS / "control" / "chain.jsonl").returncode == 2
    ex, _ = load("control")
    from crucible_chain.export import dumps

    rc = receipts_for(ex.records, [(0, 11)], service_key)
    path = tmp_path / "anchored.jsonl"
    path.write_text(dumps(ex.header["session"], ex.records, [{"to_seq": 11, "receipt": rc[0]}]))
    key = tmp_path / "service.pub.json"
    service_key.public().write(key)
    out = _cli(path, "--service-key", key)
    assert out.returncode == 0, out.stdout + out.stderr
    assert out.stdout.splitlines()[0].split() == ["record", "intact"]
    js = _cli(path, "--service-key", key, "--json")
    assert json.loads(js.stdout)["verdict"]["says"] == "intact"


def test_the_cli_refuses_an_unreadable_file(tmp_path):
    bad = tmp_path / "x.jsonl"
    bad.write_text("not json\n")
    assert _cli(bad).returncode == 4


def test_a_record_in_an_unknown_protocol_version_could_not_be_checked():
    ex, _ = load("control")
    recs = copy.deepcopy(ex.records)
    for rec in recs:
        rec["event"]["v"] = 3
        rec.pop("head")
    r = verify_record(recs, [], service_key=None, session=ex.header["session"])
    assert r.verdict.state == State.COULD_NOT_CHECK
    assert "protocol version 3" in r.verdict.reason
