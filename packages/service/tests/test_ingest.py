"""Registration and ingest against planted known answers (SPEC.md §5 Ingest).

Every receipt the service issues here is checked by the verifier's own code
(`crucible_verify.receipts`), which shares nothing with the service's tree
builder.
"""

from __future__ import annotations

import base64
import copy
import json

import pytest

from crucible_chain import wire
from crucible_chain.chain import GENESIS
from crucible_core.cose import sign
from crucible_service.log import Refusal
from crucible_verify import merkle
from crucible_verify.receipts import check_receipt, signed_checkpoint
from crucible_verify.results import State


def heads(records):
    return {r["seq"]: r["head"] for r in records}


def assert_receipt_holds(receipt, records, session, service_key):
    result = check_receipt(receipt, session=session, heads=heads(records), service_key=service_key.public())
    assert result.check.state == State.PASS, result.check.reason
    return result


# --- registration ----------------------------------------------------------------


def test_a_registration_is_appended_and_its_receipt_is_in_the_signed_tree(svc, researcher_key, service_key):
    receipt = svc.register(wire.registration(researcher_key))
    assert receipt["entry"]["kind"] == "register"
    assert receipt["entry"]["payload"]["key_id"] == researcher_key.key_id
    cp = signed_checkpoint(receipt["checkpoint"], service_key.public())
    from crucible_core.canonical import canonicalize, digest_hex

    walked = merkle.verify_inclusion(
        leaf=merkle.leaf_hash(canonicalize(receipt["entry"])),
        leaf_index=receipt["leaf_index"],
        tree_size=cp["tree_size"],
        path=[digest_hex(p) for p in receipt["inclusion_path"]],
        root=digest_hex(cp["root"]),
    )
    assert walked.outcome == merkle.Outcome.PASS


def test_registering_again_returns_the_original_entry(svc, researcher_key):
    first = svc.register(wire.registration(researcher_key))
    again = svc.register(wire.registration(researcher_key))
    assert again["entry_hash"] == first["entry_hash"] and again["leaf_index"] == first["leaf_index"]
    assert svc.log.size == 2  # genesis + one registration


def test_a_registration_signed_by_another_key_is_refused(svc, researcher_key, other_researcher):
    payload = {"v": 2, "kind": "register", "public_key": researcher_key.public().to_dict()}
    forged = base64.b64encode(sign(payload, other_researcher)).decode()
    with pytest.raises(Refusal) as exc:
        svc.register(forged)
    assert exc.value.status in (400, 401)


def test_only_researcher_keys_register(svc, service_key):
    from crucible_core.keys import PrivateKey

    k = PrivateKey.generate("service")
    payload = {"v": 2, "kind": "register", "public_key": k.public().to_dict()}
    with pytest.raises(Refusal, match="researcher"):
        svc.register(base64.b64encode(sign(payload, k)).decode())


# --- ingest: accepted -------------------------------------------------------------


def test_batches_are_accepted_and_each_receipt_anchors_its_head(svc, researcher_key, service_key, chain):
    svc.register(wire.registration(researcher_key))
    recs = chain("s-1", 10)
    r1 = svc.ingest(wire.batch(researcher_key, recs[:5]))
    r2 = svc.ingest(wire.batch(researcher_key, recs[5:], prev_head=recs[4]["head"]))
    assert_receipt_holds(r1, recs, "s-1", service_key)
    res = assert_receipt_holds(r2, recs, "s-1", service_key)
    assert (res.from_seq, res.to_seq) == (5, 9)
    assert r2["entry"]["payload"]["head"] == recs[9]["head"]
    assert isinstance(r2["entry"]["ts"], int)  # the server timestamp, inside the signed tree


def test_an_exact_resend_returns_the_original_receipt(svc, researcher_key, chain):
    svc.register(wire.registration(researcher_key))
    recs = chain("s-1", 4)
    b = wire.batch(researcher_key, recs)
    first = svc.ingest(b)
    size = svc.log.size
    again = svc.ingest(b)
    assert again["entry_hash"] == first["entry_hash"] and again["leaf_index"] == first["leaf_index"]
    assert svc.log.size == size


# --- ingest: refused, and saying why -----------------------------------------------


@pytest.fixture
def registered(svc, researcher_key, chain):
    svc.register(wire.registration(researcher_key))
    recs = chain("s-1", 10)
    svc.ingest(wire.batch(researcher_key, recs[:5]))
    return recs


def refusal(svc, b):
    with pytest.raises(Refusal) as exc:
        svc.ingest(b)
    return exc.value


def test_an_unregistered_key_is_refused(svc, other_researcher, chain):
    r = refusal(svc, wire.batch(other_researcher, chain("s-9", 2)))
    assert (r.status, r.code) == (403, "unregistered_key")


def test_a_different_batch_at_a_held_position_is_a_refused_rewrite(svc, researcher_key, registered):
    rewritten = copy.deepcopy(registered[:5])
    rewritten[2]["event"]["body"] = {"rewritten": True}
    r = refusal(svc, wire.batch(researcher_key, rewritten))
    assert r.code == "position_held" and r.extra["next_expected_seq"] == 5


def test_a_gap_is_refused_with_where_to_continue(svc, researcher_key, registered):
    r = refusal(svc, wire.batch(researcher_key, registered[7:], prev_head=registered[6]["head"]))
    assert r.code == "chain_break" and r.extra == {"at": 5, "next_expected_seq": 5}


def test_a_wrong_prev_head_is_refused(svc, researcher_key, registered):
    r = refusal(svc, wire.batch(researcher_key, registered[5:], prev_head=registered[3]["head"]))
    assert r.code == "chain_break" and r.extra["at"] == 5


def test_an_altered_event_is_refused_at_that_event(svc, researcher_key, registered):
    tampered = copy.deepcopy(registered[5:])
    tampered[2]["event"]["body"] = {"edited": True}  # event 7 no longer hashes to its head
    r = refusal(svc, wire.batch(researcher_key, tampered, prev_head=registered[4]["head"]))
    assert r.code == "chain_break" and r.extra["at"] == 7


def test_an_invalid_event_is_refused_at_its_position(svc, researcher_key, registered):
    bad = copy.deepcopy(registered[5:])
    bad[1]["event"]["type"] = "thought"  # event 6
    r = refusal(svc, wire.batch(researcher_key, bad, prev_head=registered[4]["head"]))
    assert r.code == "chain_break" and r.extra["at"] == 6


def test_a_timestamp_earlier_than_the_held_chain_is_refused(svc, researcher_key, registered):
    late = copy.deepcopy(registered[5:6])
    late[0]["event"]["ts"] = registered[4]["event"]["ts"]
    from crucible_chain.chain import link

    late[0]["head"] = link(registered[4]["head"], late[0]["event"])
    r = refusal(svc, wire.batch(researcher_key, late, prev_head=registered[4]["head"]))
    assert r.code == "chain_break" and r.extra["at"] == 5 and "ts" in r.detail


def test_a_session_belonging_to_another_key_is_refused(svc, researcher_key, other_researcher, registered):
    svc.register(wire.registration(other_researcher))
    r = refusal(svc, wire.batch(other_researcher, registered[5:], prev_head=registered[4]["head"]))
    assert (r.status, r.code) == (403, "session_owner")


def test_a_batch_signed_by_another_key_under_a_registered_kid_is_refused(svc, researcher_key, other_researcher, registered):
    from crucible_core.cose import sign_with

    payload = wire.batch_payload(registered[5:], prev_head=registered[4]["head"])
    forged = sign_with(payload, researcher_key.key_id, other_researcher.obj.sign)
    r = refusal(svc, base64.b64encode(forged).decode())
    assert (r.status, r.code) == (401, "bad_signature")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.pop("prev_head"),
        lambda p: p.__setitem__("extra", 1),
        lambda p: p.__setitem__("to_seq", p["to_seq"] + 1),
        lambda p: p.__setitem__("from_seq", -1),
        lambda p: p.__setitem__("events", []),
        lambda p: p.__setitem__("heads", p["heads"][:-1]),
        lambda p: p.__setitem__("head", p["heads"][0]),
    ],
)
def test_a_malformed_batch_is_refused_before_anything_is_stored(svc, researcher_key, chain, mutate, journal):
    svc.register(wire.registration(researcher_key))
    payload = wire.batch_payload(chain("s-1", 3))
    mutate(payload)
    before = set(journal.list(""))
    r = refusal(svc, base64.b64encode(sign(payload, researcher_key)).decode())
    assert r.status == 400
    assert set(journal.list("")) == before


def test_a_refused_batch_stores_nothing(svc, researcher_key, registered, journal):
    before = set(journal.list(""))
    refusal(svc, wire.batch(researcher_key, registered[7:], prev_head=registered[6]["head"]))
    assert set(journal.list("")) == before


# --- receipts are the same bytes every time, and link a session's batches ------------------


def test_a_resent_batch_and_a_re_read_receipt_are_byte_identical(svc, researcher_key, chain):
    from crucible_core.canonical import canonicalize

    svc.register(wire.registration(researcher_key))
    recs = chain("s-1", 6)
    first = svc.ingest(wire.batch(researcher_key, recs[:3]))
    svc.ingest(wire.batch(researcher_key, recs[3:], prev_head=recs[2]["head"]))  # the log grows
    again = svc.ingest(wire.batch(researcher_key, recs[:3]))
    assert canonicalize(again) == canonicalize(first)
    assert canonicalize(svc.receipt_for(first["leaf_index"])) == canonicalize(first)


def test_a_session_in_many_batches_verifies_intact_with_every_link_proved(svc, researcher_key, other_researcher, service_key, chain):
    from crucible_verify.report import verify_record

    svc.register(wire.registration(researcher_key))
    svc.register(wire.registration(other_researcher))
    recs = chain("s-1", 12)
    others = chain("s-2", 4)
    prev = None
    for a, b in [(0, 2), (3, 5), (6, 9), (10, 11)]:
        svc.ingest(wire.batch(researcher_key, recs[a : b + 1], prev_head=prev))
        prev = recs[b]["head"]
        svc.ingest(wire.batch(researcher_key, others[: 1 + a // 3])) if a == 0 else None  # interleave another session
    held = svc.session_record("s-1")
    assert [rc["consistency"] is None for rc in held.receipts] == [True, False, False, False]
    r = verify_record(held.records, held.receipts, service_key=service_key.public(), session="s-1")
    assert r.verdict.state == State.PASS, r.verdict.reason
    assert next(c for c in r.checks if c.name == "link").state == State.PASS


def test_a_checkpoint_is_never_earlier_than_the_entries_it_signs(journal, signer, researcher_key, chain):
    from crucible_service.log import TransparencyLog
    from crucible_service.service import Service

    times = iter([5_000, 5_000, 9_000, 1_000])  # genesis entry, its checkpoint; the entry, then a clock that stepped back
    log = TransparencyLog.create(journal, signer, service="test.service", clock=lambda: next(times))
    svc = Service(log)
    receipt = svc.register(wire.registration(researcher_key))
    cp = signed_checkpoint(receipt["checkpoint"], signer.public())
    assert cp["ts"] >= receipt["entry"]["ts"]


def _sign_raw(payload_bytes: bytes, key) -> str:
    """A COSE_Sign1 over bytes as given, which `sign` would canonicalize first."""
    import cbor2

    from crucible_core.cose import CONTENT_TYPE

    protected = cbor2.dumps({1: -8, 4: key.key_id.encode(), 3: CONTENT_TYPE})
    signature = key.obj.sign(cbor2.dumps(["Signature1", protected, b"", payload_bytes]))
    return base64.b64encode(cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload_bytes, signature]))).decode()


@pytest.mark.parametrize("depth", [65, 983, 1500, 100_000])
def test_a_too_deep_event_is_refused_the_same_way_at_any_depth(svc, researcher_key, chain, depth):
    from crucible_core.canonical import canonicalize

    svc.register(wire.registration(researcher_key))
    recs = chain("s-1", 3)
    text = canonicalize(wire.batch_payload(recs)).decode()
    assert text.count('"body":{"i":1}') == 1
    text = text.replace('"body":{"i":1}', '"body":' + '{"x":' * depth + "{}" + "}" * depth)
    r = refusal(svc, _sign_raw(text.encode(), researcher_key))
    assert r.status in (400, 409), r.detail
    if r.status == 409:
        assert r.extra["at"] == 1 and "nests deeper" in r.detail


@pytest.mark.parametrize("public_key", [[1, 2], "abc", None, {"role": "researcher"}])
def test_a_registration_whose_key_is_not_a_key_is_a_400(svc, researcher_key, public_key):
    payload = {"v": 2, "kind": "register", "public_key": public_key}
    with pytest.raises(Refusal) as exc:
        svc.register(base64.b64encode(sign(payload, researcher_key)).decode())
    assert exc.value.status == 400


def test_a_small_order_key_cannot_register(svc):
    import cbor2

    from crucible_core.cose import CONTENT_TYPE
    from crucible_core.keys import b64u, compute_key_id

    identity = bytes.fromhex("01" + "00" * 31)
    kid = compute_key_id(identity)
    payload = {"v": 2, "kind": "register", "public_key": {"role": "researcher", "key_id": kid, "x": b64u(identity)}}
    from crucible_core.canonical import canonicalize

    protected = cbor2.dumps({1: -8, 4: kid.encode(), 3: CONTENT_TYPE})
    forged = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, canonicalize(payload), identity + bytes(32)]))
    with pytest.raises(Refusal) as exc:
        svc.register(base64.b64encode(forged).decode())
    assert exc.value.status == 400 and "usable" in exc.value.detail


@pytest.mark.parametrize("depth", [62, 63, 64])
def test_an_event_as_deep_as_the_chain_allows_is_accepted(svc, researcher_key, tmp_path, depth):
    """What the client seals the service accepts: the batch may nest two deeper than an event."""
    from crucible_chain.events import draft
    from crucible_chain.store import ChainStore

    body: dict = {}
    node = body
    for _ in range(depth - 2):
        node["x"] = {}
        node = node["x"]
    svc.register(wire.registration(researcher_key))
    with ChainStore(tmp_path / "c.sqlite") as store:
        store.append("deep-1", draft("tool.result", "tool:Bash", "witnessed", body, content="x"))
        recs = [r.as_record() for r in store.records("deep-1")]
    assert svc.ingest(wire.batch(researcher_key, recs))["entry"]["payload"]["to_seq"] == 0


def test_the_receipt_cache_is_bounded_and_an_evicted_receipt_is_rebuilt_byte_for_byte(svc, researcher_key, chain, monkeypatch):
    import crucible_service.service as service_module
    from crucible_core.canonical import canonicalize

    monkeypatch.setattr(service_module, "RECEIPT_CACHE", 3)
    svc.register(wire.registration(researcher_key))
    first = svc.ingest(wire.batch(researcher_key, chain("c-0", 1)))
    for i in range(1, 6):
        svc.ingest(wire.batch(researcher_key, chain(f"c-{i}", 1)))
    assert len(svc._receipts) <= 3 and first["leaf_index"] not in svc._receipts
    assert canonicalize(svc.receipt_for(first["leaf_index"])) == canonicalize(first)
