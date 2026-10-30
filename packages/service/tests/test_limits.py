"""Rate limits in front of the write-once journal (docs/phase0-deployment.md, "Abuse"):
per client address and per key; over a limit the answer is 429 with Retry-After, and
nothing is written."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from crucible_chain import wire
from crucible_core.keys import PrivateKey
from crucible_service.api import create_app
from crucible_service.limits import Buckets, Limits, Rule


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_a_bucket_allows_its_burst_then_refuses_until_it_refills():
    clock = Clock()
    b = Buckets(Rule(burst=3, rate=0.5), clock=clock)
    assert [b.take("a") for _ in range(3)] == [None, None, None]
    assert b.take("a") == pytest.approx(2.0)  # one token takes two seconds at 0.5 a second
    assert b.take("b") is None  # another name has its own bucket
    clock.now += 2.0
    assert b.take("a") is None and b.take("a") is not None


def test_a_bucket_forgets_the_least_recently_used_beyond_its_size():
    b = Buckets(Rule(burst=1, rate=0.001), clock=Clock(), size=2)
    for name in ("a", "b", "c"):
        b.take(name)
    assert list(b._state) == ["b", "c"]


@pytest.mark.parametrize("peer, forwarded, expect", [
    ("172.17.0.2", "203.0.113.9", "203.0.113.9"),               # behind the trusted proxy: the entry it appended
    ("172.17.0.2", "10.0.0.1, 203.0.113.9", "203.0.113.9"),     # the client's own claims come first, and are ignored
    ("198.51.100.7", "203.0.113.9", "198.51.100.7"),            # anyone else's header is ignored
    ("172.17.0.2", "not-an-address", "172.17.0.2"),
    ("172.17.0.2", None, "172.17.0.2"),
    (None, "203.0.113.9", "unknown"),
])
def test_the_client_address_is_the_peers_or_what_the_trusted_proxy_says(peer, forwarded, expect):
    assert Limits(trusted_proxies=("172.17.0.0/16",)).address(peer, forwarded) == expect


def test_registrations_over_the_limit_are_refused_429_and_write_nothing(svc):
    client = TestClient(create_app(svc, limits=Limits(register=Rule(burst=2, rate=1e-6))))
    keys = [PrivateKey.generate("researcher") for _ in range(3)]
    assert [client.post("/v2/keys", json={"registration": wire.registration(k)}).status_code for k in keys[:2]] == [200, 200]
    size = svc.log.size
    r = client.post("/v2/keys", json={"registration": wire.registration(keys[2])})
    assert r.status_code == 429 and r.json()["error"] == "rate_limited" and int(r.headers["Retry-After"]) >= 1
    assert svc.log.size == size


def test_registering_a_held_key_again_is_not_charged(svc):
    client = TestClient(create_app(svc, limits=Limits(register=Rule(burst=1, rate=1e-6))))
    held, other = PrivateKey.generate("researcher"), PrivateKey.generate("researcher")
    assert client.post("/v2/keys", json={"registration": wire.registration(held)}).status_code == 200
    for _ in range(5):  # a rerun of install, a reboot: nothing is appended, nothing is charged
        assert client.post("/v2/keys", json={"registration": wire.registration(held)}).status_code == 200
    assert client.post("/v2/keys", json={"registration": wire.registration(other)}).status_code == 429


def _forged(batch_b64: str, victim: PrivateKey, forger: PrivateKey) -> str:
    """The same batch payload, naming the victim's key id but signed by someone else."""
    import base64

    from crucible_core.cose import decode, sign_with

    payload = __import__("json").loads(decode(base64.b64decode(batch_b64)).payload_bytes)
    return base64.b64encode(sign_with(payload, victim.key_id, forger.obj.sign)).decode()


def test_forged_batches_naming_a_key_cannot_spend_its_allowance(svc, researcher_key, chain):
    limits = Limits(trusted_proxies=("127.0.0.0/8",), batch_key=Rule(burst=2, rate=1e-6))
    client = TestClient(create_app(svc, limits=limits), client=("127.0.0.1", 50000))
    assert client.post("/v2/keys", json={"registration": wire.registration(researcher_key)}).status_code == 200
    recs = chain("s-1", 2)
    forger = PrivateKey.generate("researcher")
    for i in range(50):  # the victim's key id is public (it is in every export); its signature is not
        body = {"batch": _forged(wire.batch(researcher_key, recs[:1]), researcher_key, forger)}
        assert client.post("/v2/batches", json=body, headers={"X-Forwarded-For": f"203.0.113.{i}"}).status_code == 401
    assert client.post("/v2/batches", json={"batch": wire.batch(researcher_key, recs[:1])}).status_code == 200
    assert list(limits.batch_key._state) == [researcher_key.key_id]  # only a registered key id is ever a name


def test_a_key_id_longer_than_any_key_id_is_refused_unread():
    import base64

    from crucible_core.cose import MAX_KID, SignatureError, decode, sign_with

    forger = PrivateKey.generate("researcher")
    with pytest.raises(SignatureError, match="longer than any key id"):
        decode(sign_with({"v": 2}, "x" * (MAX_KID + 1), forger.obj.sign))
    assert decode(sign_with({"v": 2}, forger.key_id, forger.obj.sign)).key_id == forger.key_id


def test_batches_are_limited_per_key_whatever_the_address(svc, researcher_key, chain):
    limits = Limits(trusted_proxies=("127.0.0.0/8",), batch_key=Rule(burst=2, rate=1e-6))
    client = TestClient(create_app(svc, limits=limits), client=("127.0.0.1", 50000))
    assert client.post("/v2/keys", json={"registration": wire.registration(researcher_key)}).status_code == 200
    recs = chain("s-1", 3)
    sent = []
    for i, rec in enumerate(recs):  # each batch from another address, by the proxy's word
        body = {"batch": wire.batch(researcher_key, [rec], prev_head=recs[i - 1]["head"] if i else None)}
        sent.append(client.post("/v2/batches", json=body, headers={"X-Forwarded-For": f"203.0.113.{i}"}).status_code)
    assert sent == [200, 200, 429]


def test_batches_are_limited_per_address(svc, researcher_key, chain):
    other = PrivateKey.generate("researcher")
    for k in (researcher_key, other):
        assert TestClient(create_app(svc)).post("/v2/keys", json={"registration": wire.registration(k)}).status_code == 200
    client = TestClient(create_app(svc, limits=Limits(batch_address=Rule(burst=1, rate=1e-6))))
    assert client.post("/v2/batches", json={"batch": wire.batch(researcher_key, chain("s-1", 1))}).status_code == 200
    assert client.post("/v2/batches", json={"batch": wire.batch(other, chain("s-2", 1))}).status_code == 429


def test_reads_are_limited_and_health_is_not(svc):
    client = TestClient(create_app(svc, limits=Limits(read=Rule(burst=1, rate=1e-6))))
    assert client.get("/v2/checkpoint").status_code == 200
    assert client.get("/v2/checkpoint").status_code == 429
    assert client.get("/v2/sessions/s-1/verify").status_code == 429
    assert client.get("/v2/health").status_code == 200 and client.get("/v2/pubkey").status_code == 200


def test_an_exact_resend_is_not_charged_to_the_key(svc, researcher_key, chain):
    limits = Limits(batch_key=Rule(burst=1, rate=1e-6))
    client = TestClient(create_app(svc, limits=limits))
    assert client.post("/v2/keys", json={"registration": wire.registration(researcher_key)}).status_code == 200
    batch = {"batch": wire.batch(researcher_key, chain("s-1", 1))}
    first = client.post("/v2/batches", json=batch)
    assert first.status_code == 200
    for _ in range(3):  # a lost answer, sent again: its original receipt, whatever the key's allowance
        again = client.post("/v2/batches", json=batch)
        assert again.status_code == 200 and again.json() == first.json()


def test_registering_a_held_key_writes_nothing(svc, researcher_key):
    client = TestClient(create_app(svc))
    assert client.post("/v2/keys", json={"registration": wire.registration(researcher_key)}).status_code == 200

    def no_writes(*_a, **_k):
        raise AssertionError("a held key's registration wrote to the journal")

    svc.log.put_object = no_writes
    assert client.post("/v2/keys", json={"registration": wire.registration(researcher_key)}).status_code == 200


def test_a_registration_carrying_more_than_the_key_is_refused(svc, researcher_key):
    import base64

    from crucible_core.cose import sign

    padded = {**researcher_key.public().to_dict(), "v": "x" * 200_000}  # a field the key's reader does not look at
    payload = {"v": 2, "kind": "register", "public_key": padded}
    body = {"registration": base64.b64encode(sign(payload, researcher_key)).decode()}
    r = TestClient(create_app(svc)).post("/v2/keys", json=body)
    assert r.status_code == 400 and "and only that" in r.json()["detail"], r.text
