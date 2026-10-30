"""Service-side verification, and the CLI re-running it (docs/v1-audit.md §5 step 5).

Both paths run over a real service on a real socket (the root conftest's
``ephemeral_service``): the service's own ``/v2/sessions/<id>/verify``, and
``crucible-verify`` over that session's ``/export`` with the service key given
out of band. The control chain is ingested through step 4. Each broken chain is
written straight into the journal, because ingest would refuse it, and both
paths must report its manifest's N.
"""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from crucible_chain import wire
from crucible_chain.chain import GENESIS
from crucible_chain.corpus import FIXTURES, SESSION
from crucible_chain.export import read
from crucible_core.cose import sign

CORPUS = Path(__file__).resolve().parents[3] / "corpus"


def call(url: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url + path, data=data, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def both_paths(svc, service_key, tmp_path, session=SESSION) -> tuple[dict, dict, int]:
    """(the service's report, the CLI's report, the CLI's exit status)."""
    status, served = call(svc.url, f"/v2/sessions/{session}/verify")
    assert status == 200, served
    key = tmp_path / "service.pub.json"
    service_key.public().write(key)  # out of band: never fetched from the service
    out = subprocess.run(
        [sys.executable, "-m", "crucible_verify.cli", f"{svc.url}/v2/sessions/{session}/export", "--service-key", str(key), "--json"],
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode in (0, 1, 2, 3), out.stderr
    return served, json.loads(out.stdout), out.returncode


def plant_batch(service, key, records, *, from_seq, to_seq, prev_head, head, payload_bytes=None, last_ts=1) -> None:
    """Write one batch into the journal, past every ingest check: the object, and
    a leaf the service signs over."""
    payload = {
        "v": 2, "kind": "batch", "session": SESSION, "from_seq": from_seq, "to_seq": to_seq,
        "prev_head": prev_head, "head": head,
        "events": [r["event"] for r in records], "heads": [r["head"] for r in records],
    }
    raw = sign(payload, key) if payload_bytes is None else _sign_raw(payload_bytes, key)
    digest = service.log.put_object(raw)
    if records and isinstance(records[-1].get("event"), dict) and isinstance(records[-1]["event"].get("ts"), int):
        last_ts = records[-1]["event"]["ts"]
    entry = {"session": SESSION, "key_id": key.key_id, "from_seq": from_seq, "to_seq": to_seq, "head": head,
             "last_ts": last_ts, "batch": digest}
    service.log.append(lambda _log: {"kind": "batch", "payload": entry})


def _sign_raw(payload_bytes: bytes, key) -> bytes:
    import cbor2

    from crucible_core.cose import CONTENT_TYPE

    protected = cbor2.dumps({1: -8, 4: key.key_id.encode(), 3: CONTENT_TYPE})
    signature = key.obj.sign(cbor2.dumps(["Signature1", protected, b"", payload_bytes]))
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload_bytes, signature]))


def plant(service, key, records, header, at: int | None = None) -> None:
    """Write a chain into the journal past ingest: the honest events before ``at``
    as one batch (as the client would have sent them), the rest as another,
    declaring the header's count and head."""
    at = 0 if at is None else at
    if at:
        plant_batch(service, key, records[:at], from_seq=0, to_seq=at - 1, prev_head=GENESIS, head=records[at - 1]["head"])
    prev = records[at - 1]["head"] if at else GENESIS
    plant_batch(service, key, records[at:], from_seq=at, to_seq=header["count"] - 1, prev_head=prev, head=header["head"])


def test_the_control_ingested_through_the_service_is_intact_by_both_paths(ephemeral_service, researcher_key, service_key, tmp_path):
    ex = read(CORPUS / "control" / "chain.jsonl")
    status, _ = call(ephemeral_service.url, "/v2/keys", {"registration": wire.registration(researcher_key)})
    assert status == 200
    prev = None
    for a, b in [(0, 2), (3, 7), (8, 11)]:
        status, body = call(ephemeral_service.url, "/v2/batches", {"batch": wire.batch(researcher_key, ex.records[a : b + 1], prev_head=prev)})
        assert status == 200, body
        prev = ex.records[b]["head"]
    served, cli, code = both_paths(ephemeral_service, service_key, tmp_path)
    assert served["verdict"]["says"] == "intact", served["verdict"]
    assert (code, cli["verdict"]["says"]) == (0, "intact")
    assert cli == served
    assert served["services"] == ["test.service"] and [r["to_seq"] for r in served["receipts"]] == [2, 7, 11]


@pytest.mark.parametrize("name", sorted(n for n, (at, *_rest) in FIXTURES.items() if at is not None))
def test_each_broken_chain_in_the_journal_gives_its_manifest_n_by_both_paths(ephemeral_service, researcher_key, service_key, tmp_path, name):
    ex = read(CORPUS / name / "chain.jsonl")
    manifest = json.loads((CORPUS / name / "manifest.json").read_text())
    want = f"broken at event {manifest['expect']['at']}"
    call(ephemeral_service.url, "/v2/keys", {"registration": wire.registration(researcher_key)})
    plant(ephemeral_service.service, researcher_key, ex.records, ex.header, at=manifest["expect"]["at"])
    served, cli, code = both_paths(ephemeral_service, service_key, tmp_path)
    assert served["verdict"]["says"] == want, served["verdict"]
    assert (code, cli["verdict"]["says"]) == (1, want)
    assert cli == served


def test_the_control_planted_the_same_way_is_intact_so_the_plant_is_not_the_break(ephemeral_service, researcher_key, service_key, tmp_path):
    ex = read(CORPUS / "control" / "chain.jsonl")
    call(ephemeral_service.url, "/v2/keys", {"registration": wire.registration(researcher_key)})
    plant(ephemeral_service.service, researcher_key, ex.records, ex.header)
    served, cli, code = both_paths(ephemeral_service, service_key, tmp_path)
    assert served["verdict"]["says"] == "intact" and (code, cli["verdict"]["says"]) == (0, "intact")


def test_a_wrong_key_out_of_band_is_not_intact_by_the_cli(ephemeral_service, researcher_key, tmp_path):
    from crucible_core.keys import PrivateKey

    ex = read(CORPUS / "control" / "chain.jsonl")
    call(ephemeral_service.url, "/v2/keys", {"registration": wire.registration(researcher_key)})
    call(ephemeral_service.url, "/v2/batches", {"batch": wire.batch(researcher_key, ex.records)})
    _served, cli, code = both_paths(ephemeral_service, PrivateKey.generate("service"), tmp_path)
    assert code == 2 and cli["verdict"]["says"].startswith("could_not_check(")


def test_a_session_the_service_does_not_hold_is_404_on_both_routes(ephemeral_service):
    for route in ("verify", "export"):
        status, body = call(ephemeral_service.url, f"/v2/sessions/nobody-0001/{route}")
        assert (status, body["error"]) == (404, "unknown_session")


# --- a journal holding what ingest would refuse still gets a verdict, the same by both paths ---------


def _ingest_control(svc, researcher_key):
    ex = read(CORPUS / "control" / "chain.jsonl")
    call(svc.url, "/v2/keys", {"registration": wire.registration(researcher_key)})
    prev = None
    for a, b in [(0, 2), (3, 7), (8, 11)]:
        assert call(svc.url, "/v2/batches", {"batch": wire.batch(researcher_key, ex.records[a : b + 1], prev_head=prev)})[0] == 200
        prev = ex.records[b]["head"]
    return ex


@pytest.mark.parametrize("damage", ["changed", "missing"])
def test_a_batch_object_changed_or_missing_is_a_break_where_it_begins_by_both_paths(ephemeral_service, researcher_key, service_key, tmp_path, damage):
    _ingest_control(ephemeral_service, researcher_key)
    log = ephemeral_service.service.log
    middle = [e for e in log.entries if e["kind"] == "batch"][1]["payload"]["batch"]
    obj = ephemeral_service.journal / "object" / middle.removeprefix("sha256:")
    if damage == "changed":
        obj.write_bytes(obj.read_bytes()[:-1] + b"\x00")
    else:
        obj.unlink()
    log._objects.clear()
    ephemeral_service.stop()
    ephemeral_service.start()  # a fresh process, nothing cached
    served, cli, code = both_paths(ephemeral_service, service_key, tmp_path)
    assert served["verdict"]["says"] == "broken at event 3" and cli == served and code == 1


def test_a_leaf_the_service_refuses_does_not_stop_it_serving_the_rest(ephemeral_service, researcher_key, service_key, tmp_path):
    from crucible_core.canonical import canonicalize
    from crucible_service.log import leaf_key

    _ingest_control(ephemeral_service, researcher_key)
    log = ephemeral_service.service.log
    planted = {"v": 2, "kind": "batch", "ts": 1, "payload": {"session": "other-0001", "key_id": researcher_key.key_id,
               "from_seq": 0, "to_seq": 3, "head": "sha256:" + "ab" * 32, "last_ts": 1, "batch": "sha256:" + "cd" * 32}}
    assert log.store.create(leaf_key(log.size), canonicalize(planted))  # by someone without the service key
    served, cli, code = both_paths(ephemeral_service, service_key, tmp_path)
    assert served["verdict"]["says"] == "intact" and cli == served
    status, health = call(ephemeral_service.url, "/v2/health")
    assert status == 503 and health["error"] == "log_unavailable"  # but it accepts nothing until someone looks


@pytest.mark.parametrize("bad", ["seq-float", "event-not-object", "no-heads", "bad-signature"])
def test_a_batch_ingest_would_refuse_gives_the_same_verdict_by_both_paths(ephemeral_service, researcher_key, service_key, tmp_path, bad):
    from crucible_core.canonical import canonicalize
    from crucible_core.keys import PrivateKey

    ex = read(CORPUS / "control" / "chain.jsonl")
    call(ephemeral_service.url, "/v2/keys", {"registration": wire.registration(researcher_key)})
    svc = ephemeral_service.service
    plant_batch(svc, researcher_key, ex.records[:5], from_seq=0, to_seq=4, prev_head=GENESIS, head=ex.records[4]["head"])
    rest, kw = ex.records[5:], {}
    payload = {"v": 2, "kind": "batch", "session": SESSION, "from_seq": 5, "to_seq": 11, "prev_head": ex.records[4]["head"],
               "head": ex.header["head"], "events": [r["event"] for r in rest], "heads": [r["head"] for r in rest]}
    text = canonicalize(payload).decode()
    key = researcher_key
    if bad == "seq-float":
        kw["payload_bytes"] = text.replace('"seq":5,', '"seq":5.0,', 1).encode()
    elif bad == "event-not-object":
        payload["events"][2] = "x"
        kw["payload_bytes"] = canonicalize(payload)
    elif bad == "no-heads":
        del payload["heads"]
        kw["payload_bytes"] = canonicalize(payload)
    else:
        key = PrivateKey.generate("researcher")
    plant_batch(svc, key, rest, from_seq=5, to_seq=11, prev_head=ex.records[4]["head"], head=ex.header["head"], **kw)
    served, cli, code = both_paths(ephemeral_service, service_key, tmp_path)
    assert served["verdict"]["says"] == "broken at event 5" and cli == served, served["verdict"]
