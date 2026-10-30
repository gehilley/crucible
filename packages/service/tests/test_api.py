"""The HTTP interface, end to end through a test client."""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from crucible_chain import wire
from crucible_service.api import MAX_BODY, create_app
from crucible_verify.receipts import check_receipt
from crucible_verify.results import State


@pytest.fixture
def client(svc):
    return TestClient(create_app(svc))


def test_register_ingest_and_read_back(client, researcher_key, service_key, chain):
    r = client.post("/v2/keys", json={"registration": wire.registration(researcher_key)})
    assert r.status_code == 200, r.text
    recs = chain("s-1", 6)
    r = client.post("/v2/batches", json={"batch": wire.batch(researcher_key, recs)})
    assert r.status_code == 200, r.text
    receipt = r.json()["receipt"]
    res = check_receipt(receipt, session="s-1", heads={x["seq"]: x["head"] for x in recs}, service_key=service_key.public())
    assert res.check.state == State.PASS, res.check.reason

    again = client.get(f"/v2/receipts/{receipt['entry_hash']}")
    assert again.status_code == 200 and again.json()["receipt"]["entry_hash"] == receipt["entry_hash"]
    cp = client.get("/v2/checkpoint").json()
    assert cp["tree_size"] == 3
    assert client.get("/v2/pubkey").json()["key_id"] == service_key.key_id
    proof = client.get("/v2/consistency", params={"first": 1, "second": 3})
    assert proof.status_code == 200 and isinstance(proof.json()["proof"], list)
    health = client.get("/v2/health").json()
    assert health == {"status": "ok", "service": "test.service", "log_id": "log-test", "tree_size": 3}


def test_a_chain_break_says_where_and_where_to_continue(client, researcher_key, chain):
    client.post("/v2/keys", json={"registration": wire.registration(researcher_key)})
    recs = chain("s-1", 6)
    client.post("/v2/batches", json={"batch": wire.batch(researcher_key, recs[:3])})
    r = client.post("/v2/batches", json={"batch": wire.batch(researcher_key, recs[4:], prev_head=recs[3]["head"])})
    assert r.status_code == 409
    assert r.json() == {"error": "chain_break", "detail": r.json()["detail"], "at": 3, "next_expected_seq": 3}


def test_refusals_have_one_shape(client, researcher_key):
    r = client.post("/v2/batches", json={"batch": wire.batch(researcher_key, [{"seq": 0, "head": "sha256:" + "00" * 32, "event": {"session": "s"}}])})
    assert r.status_code == 403 and set(r.json()) >= {"error", "detail"}
    r = client.post("/v2/batches", json={"wrong": "field"})
    assert r.status_code == 400 and r.json()["error"] == "malformed_request"
    r = client.post("/v2/batches", json={"batch": "not base64!"})
    assert r.status_code == 400
    r = client.get("/v2/receipts/sha256:" + "ab" * 32)
    assert r.status_code == 404 and r.json()["error"] == "unknown_entry"


def test_a_body_over_the_limit_is_refused(client):
    big = "A" * (MAX_BODY + 1)
    r = client.post("/v2/batches", content=('{"batch":"' + big + '"}').encode(), headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_a_chunked_body_over_the_limit_is_refused(client):
    def chunks():
        yield b'{"batch":"'
        for _ in range(MAX_BODY // 65536 + 1):
            yield b"A" * 65536
        yield b'"}'

    r = client.post("/v2/batches", content=chunks(), headers={"content-type": "application/json"})
    assert r.status_code == 413 and r.json()["error"] == "too_large"


def test_an_unknown_route_has_the_refusal_shape(client):
    r = client.get("/v2/nothing-here")
    assert r.status_code == 404 and r.json()["error"] == "not_found"


def test_a_503_carries_retry_after_and_says_whether_the_entry_was_appended(tmp_path, signer, researcher_key):
    from crucible_service.journal import DirStore, JournalError
    from crucible_service.log import TransparencyLog
    from crucible_service.service import Service

    class Flaky(DirStore):
        fail = ""

        def create(self, key, data):
            if self.fail and key.startswith(self.fail):
                raise JournalError("the bucket is unreachable")
            return super().create(key, data)

    store = Flaky(tmp_path / "j")
    TransparencyLog.create(store, signer, service="test.service")
    client = TestClient(create_app(Service(TransparencyLog.open(store, signer))))
    body = {"registration": wire.registration(researcher_key)}

    store.fail = "object/"  # before anything is appended
    r = client.post("/v2/keys", json=body)
    assert r.status_code == 503 and r.headers["retry-after"] and r.json()["error"] == "journal_unavailable"

    store.fail = "checkpoint/"  # the leaf lands, its checkpoint does not
    r = client.post("/v2/keys", json=body)
    assert r.status_code == 503 and r.headers["retry-after"]
    assert r.json()["error"] == "receipt_pending" and r.json()["leaf_index"] == 1

    store.fail = ""
    r = client.post("/v2/keys", json=body)  # the same request again: its receipt
    assert r.status_code == 200 and r.json()["receipt"]["leaf_index"] == 1


def test_health_follows_the_last_liveness_pass(svc, tmp_path):
    import json

    from crucible_service.api import Liveness

    now = [1_800_000_000.0]
    status = tmp_path / "status.json"
    gate = Liveness(status, 3600, clock=lambda: now[0])
    client = TestClient(create_app(svc, liveness=gate))
    assert client.get("/v2/health").status_code == 200  # just started: one interval to see a pass
    now[0] += 3601
    r = client.get("/v2/health")
    assert r.status_code == 503 and r.json()["error"] == "stale" and r.headers["retry-after"]
    status.write_text(json.dumps({"last_pass": int((now[0] - 60) * 1e6)}))
    assert client.get("/v2/health").status_code == 200
    now[0] += 3600
    r = client.get("/v2/health")  # stop ingest: no new pass, and after the interval health turns red
    assert r.status_code == 503 and "minutes ago" in r.json()["detail"]
