"""The journal as the log of record (SPEC.md §5 Scale): genesis, statelessness,
rebuild, tamper detection, and a failing journal."""

from __future__ import annotations

import base64
import concurrent.futures as cf
import json

import pytest

from crucible_chain import wire
from crucible_core.keys import PrivateKey
from crucible_service.journal import DirStore, JournalError
from crucible_service.log import LogError, TransparencyLog, checkpoint_key, leaf_key
from crucible_service.service import Refusal, Service
from crucible_service.signer import LocalSigner
from crucible_verify.receipts import check_receipt
from crucible_verify.results import State


# --- genesis and open --------------------------------------------------------------


def test_genesis_writes_the_service_entry_first(svc, service_key):
    e = svc.log.entries[0]
    assert e["kind"] == "service"
    assert e["payload"]["service"] == "test.service" and e["payload"]["key_id"] == service_key.key_id


def test_a_second_genesis_over_an_existing_log_is_refused(svc, journal, signer):
    with pytest.raises(LogError, match="already holds a log"):
        TransparencyLog.create(journal, signer, service="test.service")


def test_an_empty_journal_does_not_open(tmp_path, signer):
    with pytest.raises(LogError, match="--genesis"):
        TransparencyLog.open(DirStore(tmp_path / "empty"), signer)


def test_the_log_will_not_open_under_another_key(svc, journal):
    with pytest.raises(LogError, match="refusing to sign"):
        TransparencyLog.open(journal, LocalSigner(PrivateKey.generate("service")))


def test_two_racing_geneses_make_exactly_one_log(tmp_path, signer):
    store = DirStore(tmp_path / "j")
    with cf.ThreadPoolExecutor(8) as pool:
        futs = [pool.submit(TransparencyLog.create, DirStore(store.root), signer, service="test.service") for _ in range(8)]
    made = [f for f in futs if f.exception() is None]
    assert len(made) == 1
    assert all(isinstance(f.exception(), LogError) for f in futs if f not in made)
    assert store.list("leaf/") == [leaf_key(0)]
    assert TransparencyLog.open(store, signer).log_id == made[0].result().log_id


def test_a_log_whose_first_checkpoint_was_never_signed_still_opens(svc, journal, signer):
    (journal.root / checkpoint_key(1)).unlink()  # as if the process died between leaf 0 and its checkpoint
    log = TransparencyLog.open(journal, signer)
    size, env = log.checkpoint()
    assert size == 1 and (journal.root / checkpoint_key(1)).exists()


def test_a_first_leaf_that_is_not_a_service_entry_does_not_open(tmp_path, signer):
    store = DirStore(tmp_path / "j")
    from crucible_core.canonical import canonicalize

    store.create(leaf_key(0), canonicalize({"v": 2, "kind": "register", "ts": 1, "payload": {}}))
    with pytest.raises(LogError, match="service entry"):
        TransparencyLog.open(store, signer)


def test_a_stray_checkpoint_stops_the_log_from_opening(svc, journal, signer):
    journal.create("checkpoint/latest", b"x")
    with pytest.raises(LogError, match="not a checkpoint"):
        TransparencyLog.open(journal, signer)


def test_a_service_signer_needs_a_service_key(researcher_key):
    with pytest.raises(ValueError):
        LocalSigner(researcher_key)


# --- rebuild ---------------------------------------------------------------------------


def test_a_cache_rebuilt_from_the_journal_equals_the_original(svc, journal, signer, researcher_key, chain):
    svc.register(wire.registration(researcher_key))
    recs = chain("s-1", 8)
    svc.ingest(wire.batch(researcher_key, recs[:4]))
    svc.ingest(wire.batch(researcher_key, recs[4:], prev_head=recs[3]["head"]))
    again = Service(TransparencyLog.open(journal, signer))
    assert again.log.entries == svc.log.entries
    assert again.sessions == svc.sessions and set(again.keys) == set(svc.keys)
    assert again.batches == svc.batches
    # And the rebuilt service carries on where the first left off.
    more = chain("s-1", 2, start=8)
    again.ingest(wire.batch(researcher_key, more[8:], prev_head=more[7]["head"]))


# --- tamper detection --------------------------------------------------------------------


def test_an_altered_leaf_stops_the_log_from_opening(svc, journal, signer, researcher_key):
    svc.register(wire.registration(researcher_key))
    path = journal.root / leaf_key(1)
    stored = json.loads(path.read_bytes())
    stored["entry"]["ts"] += 1
    from crucible_core.canonical import canonicalize

    path.chmod(0o644)
    path.write_bytes(canonicalize(stored))
    with pytest.raises(LogError, match="altered"):
        TransparencyLog.open(journal, signer)


def test_a_hole_in_the_leaves_stops_the_log_from_opening(svc, journal, signer, researcher_key, other_researcher):
    svc.register(wire.registration(researcher_key))
    svc.register(wire.registration(other_researcher))
    (journal.root / leaf_key(1)).unlink()
    with pytest.raises(LogError, match="is missing"):
        TransparencyLog.open(journal, signer)


def test_an_altered_batch_object_is_refused_when_read(svc, journal, researcher_key, chain):
    svc.register(wire.registration(researcher_key))
    receipt = svc.ingest(wire.batch(researcher_key, chain("s-1", 3)))
    digest = receipt["entry"]["payload"]["batch"]
    obj = journal.root / "object" / digest.removeprefix("sha256:")
    obj.write_bytes(obj.read_bytes() + b"x")
    with pytest.raises(LogError, match="altered"):
        svc.log.get_object(digest)


# --- a journal that cannot be written ------------------------------------------------------


class FailingStore(DirStore):
    def create(self, key, data):
        if key.startswith("leaf/"):
            raise JournalError("the bucket is unreachable")
        return super().create(key, data)


def test_a_failed_create_issues_no_receipt_and_appends_nothing(tmp_path, signer, researcher_key, chain):
    good = DirStore(tmp_path / "j")
    TransparencyLog.create(good, signer, service="test.service")
    svc = Service(TransparencyLog.open(FailingStore(tmp_path / "j"), signer))
    with pytest.raises(JournalError):
        svc.register(wire.registration(researcher_key))
    assert good.list("leaf/") == [leaf_key(0)]


# --- stateless: independent processes racing on one journal ---------------------------------


def _node(journal_root, signer):
    return Service(TransparencyLog.open(DirStore(journal_root), signer))


def test_two_ingest_nodes_racing_never_fork_the_log(svc, journal, signer, researcher_key, service_key, chain):
    svc.register(wire.registration(researcher_key))
    a, b = _node(journal.root, signer), _node(journal.root, signer)
    sessions = {f"s-{i}": chain(f"s-{i}", 6) for i in range(8)}
    jobs = []
    with cf.ThreadPoolExecutor(8) as pool:
        for i, (s, recs) in enumerate(sessions.items()):
            node = a if i % 2 else b
            jobs.append((s, recs, pool.submit(node.ingest, wire.batch(researcher_key, recs[:3]))))
            jobs.append((s, recs, pool.submit((b if i % 2 else a).ingest, wire.batch(researcher_key, recs[:3]))))
    receipts = {}
    for s, recs, fut in jobs:
        rc = fut.result()
        res = check_receipt(rc, session=s, heads={r["seq"]: r["head"] for r in recs}, service_key=service_key.public())
        assert res.check.state == State.PASS, res.check.reason
        receipts.setdefault(s, set()).add(rc["entry_hash"])
    # Each session's batch was sent through both nodes; it is in the log once.
    assert all(len(v) == 1 for v in receipts.values())
    fresh = TransparencyLog.open(journal, signer)
    batch_leaves = [e for e in fresh.entries if e["kind"] == "batch"]
    assert len(batch_leaves) == len(sessions)
    assert [int(k.rsplit("/", 1)[1]) for k in journal.list("leaf/")] == list(range(fresh.size))


def test_racing_different_batches_at_one_position_admits_exactly_one(svc, journal, signer, researcher_key, chain):
    import copy

    svc.register(wire.registration(researcher_key))
    recs = chain("s-1", 4)
    variant = copy.deepcopy(recs)
    variant[0]["event"]["body"] = {"variant": True}
    from crucible_chain.chain import heads

    for r, h in zip(variant, heads([v["event"] for v in variant])):
        r["head"] = h
    a, b = _node(journal.root, signer), _node(journal.root, signer)
    with cf.ThreadPoolExecutor(2) as pool:
        fa = pool.submit(a.ingest, wire.batch(researcher_key, recs))
        fb = pool.submit(b.ingest, wire.batch(researcher_key, variant))
    outcomes = []
    for f in (fa, fb):
        try:
            outcomes.append(("ok", f.result()))
        except Refusal as exc:
            outcomes.append(("refused", exc.code))
    assert sorted(o[0] for o in outcomes) == ["ok", "refused"]
    assert [o[1] for o in outcomes if o[0] == "refused"] == ["position_held"]
    fresh = TransparencyLog.open(journal, signer)
    assert sum(1 for e in fresh.entries if e["kind"] == "batch") == 1


_NODE = """
import json, sys
from crucible_core.keys import PrivateKey
from crucible_service.journal import DirStore
from crucible_service.log import TransparencyLog
from crucible_service.service import Service
from crucible_service.signer import LocalSigner
journal, key, batches = sys.argv[1], sys.argv[2], json.loads(open(sys.argv[3]).read())
svc = Service(TransparencyLog.open(DirStore(journal), LocalSigner(PrivateKey.read(key))))
print(json.dumps([svc.ingest(b)["entry_hash"] for b in batches]))
"""


def test_two_ingest_processes_on_one_journal_never_fork_it(tmp_path, svc, journal, signer, service_key, researcher_key, chain):
    """Two OS processes, each with only the journal in common, ingest at once."""
    import subprocess
    import sys

    svc.register(wire.registration(researcher_key))
    keyfile = tmp_path / "service.key.json"
    service_key.write(keyfile)
    sessions = {f"p-{i}": chain(f"p-{i}", 4) for i in range(12)}
    halves = [[], []]
    for i, recs in enumerate(sessions.values()):
        halves[i % 2].append(wire.batch(researcher_key, recs))
        halves[(i + 1) % 2].append(wire.batch(researcher_key, recs))  # every batch is sent by both
    files = []
    for n, h in enumerate(halves):
        f = tmp_path / f"batches-{n}.json"
        f.write_text(json.dumps(h))
        files.append(f)
    procs = [subprocess.Popen([sys.executable, "-c", _NODE, str(journal.root), str(keyfile), str(f)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) for f in files]
    outs = [p.communicate(timeout=120) for p in procs]
    assert all(p.returncode == 0 for p in procs), [o[1].decode() for o in outs]
    fresh = TransparencyLog.open(journal, signer)
    batches = [e for e in fresh.entries if e["kind"] == "batch"]
    assert len(batches) == len(sessions)
    assert sorted(e["payload"]["session"] for e in batches) == sorted(sessions)
    # Both processes got the same receipt for each batch they both sent.
    a, b = (set(json.loads(o[0])) for o in outs)
    assert a == b and len(a) == len(sessions)


# --- a leaf nobody with the service key wrote is not signed over -----------------------------


def _plant(journal, index, entry, *, signer=None):
    """Create a leaf directly in the journal: bare, or signed with ``signer`` (the
    service key, as a buggy release of the service might have written it)."""
    from crucible_core.canonical import canonicalize

    if signer is None:
        stored = canonicalize({"entry": entry, "signature": "AAAA"})
    else:
        stored = TransparencyLog.open(journal, signer)._wrap(index, entry)
    assert journal.create(leaf_key(index), stored)


def test_a_planted_leaf_without_the_service_signature_is_refused_whatever_it_says(svc, journal, signer, researcher_key, chain):
    """A real batch of the attacker's own, its object stored, its leaf backdated:
    everything checks except that the service never signed the leaf."""
    svc.register(wire.registration(researcher_key))
    raw = base64.b64decode(wire.batch(researcher_key, chain("att-1", 2)))
    digest = svc.log.put_object(raw)
    batch = json.loads(__import__("crucible_core.cose", fromlist=["decode"]).decode(raw).payload_bytes)
    leaf = {"v": 2, "kind": "batch", "ts": 1_767_225_600_000_000, "payload": {
        "session": "att-1", "key_id": researcher_key.key_id, "from_seq": 0, "to_seq": 1,
        "head": batch["head"], "last_ts": batch["events"][-1]["ts"], "batch": digest}}
    size = svc.log.size
    _plant(journal, size, leaf)
    with pytest.raises(LogError, match="not signed by this log's key"):
        svc.log.refresh()
    assert svc.log.size == size
    with pytest.raises(LogError, match="not signed by this log's key"):
        TransparencyLog.open(journal, signer)


def test_a_signed_leaf_naming_a_batch_the_journal_does_not_hold_is_refused(svc, journal, signer, researcher_key, chain):
    svc.register(wire.registration(researcher_key))
    recs = chain("victim", 3)
    leaf = {"v": 2, "kind": "batch", "ts": 1, "payload": {
        "session": "victim", "key_id": researcher_key.key_id, "from_seq": 0, "to_seq": 41,
        "head": "sha256:" + "ab" * 32, "last_ts": 5, "batch": "sha256:" + "cd" * 32}}
    size = svc.log.size
    _plant(journal, size, leaf, signer=signer)
    with pytest.raises(LogError, match="not in the journal"):
        svc.log.refresh()
    assert svc.log.size == size  # not adopted
    with pytest.raises(LogError):
        Service(TransparencyLog.open(journal, signer))
    with pytest.raises(LogError):  # and the running process will not sign over it either
        svc.ingest(wire.batch(researcher_key, recs))


def test_a_real_batch_replayed_into_a_new_leaf_is_refused(svc, journal, signer, researcher_key, chain):
    svc.register(wire.registration(researcher_key))
    recs = chain("s-1", 3)
    receipt = svc.ingest(wire.batch(researcher_key, recs))
    _plant(journal, svc.log.size, {**receipt["entry"], "ts": receipt["entry"]["ts"] + 1}, signer=signer)
    with pytest.raises(LogError, match="would have been refused"):
        svc.log.refresh()


def test_a_malformed_leaf_is_a_log_error_not_a_crash(svc, journal, signer):
    _plant(journal, svc.log.size, {"v": 2, "kind": "batch", "ts": 1, "payload": {}})
    with pytest.raises(LogError):
        Service(TransparencyLog.open(journal, signer))


def test_a_leaf_written_by_another_honest_process_is_admitted(svc, journal, signer, researcher_key, chain):
    other = Service(TransparencyLog.open(journal, signer))
    other.register(wire.registration(researcher_key))
    recs = chain("s-1", 4)
    other.ingest(wire.batch(researcher_key, recs[:2]))
    svc.ingest(wire.batch(researcher_key, recs[2:], prev_head=recs[1]["head"]))  # sees other's leaves, admits them
    assert svc.sessions["s-1"].next_seq == 4


def test_a_registration_is_stored_and_its_leaf_names_it(svc, researcher_key):
    receipt = svc.register(wire.registration(researcher_key))
    digest = receipt["entry"]["payload"]["registration"]
    assert svc.log.get_object(digest) is not None


# --- checkpoints are verified before they are written or handed out ---------------------------


class WrongSigner(LocalSigner):
    """Signs with another key but names this one: a KMS key or version mix-up."""

    def __init__(self, key, wrong):
        super().__init__(key)
        self._wrong = wrong

    def sign(self, payload):
        from crucible_core.cose import sign_with

        return sign_with(payload, self.key_id, self._wrong.obj.sign)


def test_a_signer_that_signs_with_the_wrong_key_writes_nothing(svc, journal, signer, service_key, researcher_key):
    from crucible_service.log import ReceiptPending

    from crucible_service.log import SignerError

    bad = Service(TransparencyLog.open(journal, WrongSigner(service_key, PrivateKey.generate("service"))))
    before = (set(journal.list("leaf/")), set(journal.list("checkpoint/")))
    with pytest.raises(SignerError):
        bad.register(wire.registration(researcher_key))
    assert (set(journal.list("leaf/")), set(journal.list("checkpoint/"))) == before  # nothing unverifiable was written
    good = Service(TransparencyLog.open(journal, signer))  # the journal still opens
    receipt = good.register(wire.registration(researcher_key))
    assert receipt["leaf_index"] == 1


def test_a_junk_checkpoint_in_the_journal_is_never_handed_out(svc, journal, signer, researcher_key):
    from crucible_service.log import ReceiptPending

    journal.create(checkpoint_key(svc.log.size + 1), b"junk")
    with pytest.raises(ReceiptPending):
        svc.register(wire.registration(researcher_key))


def test_a_receipt_is_a_copy_the_caller_may_edit(svc, researcher_key, chain):
    svc.register(wire.registration(researcher_key))
    rc = svc.ingest(wire.batch(researcher_key, chain("s-1", 2)))
    rc["entry"]["payload"]["head"] = "sha256:" + "ee" * 32
    again = svc.receipt_for(rc["leaf_index"])
    assert again["entry"]["payload"]["head"] != rc["entry"]["payload"]["head"]


# --- opening beside a running writer ------------------------------------------------------------------


_WRITER = """
import json, sys
from crucible_chain import wire
from crucible_chain.events import draft
from crucible_chain.store import ChainStore
from crucible_core.keys import PrivateKey
from crucible_service.journal import DirStore
from crucible_service.log import TransparencyLog
from crucible_service.service import Service
from crucible_service.signer import LocalSigner
journal, key, rkey, db, n = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
svc = Service(TransparencyLog.open(DirStore(journal), LocalSigner(PrivateKey.read(key))))
researcher = PrivateKey.read(rkey)
store = ChainStore(db)
prev = None
for i in range(n):
    rec = store.append("w-1", draft("tool.result", "tool:Bash", "witnessed", {"i": i}, content=i))
    svc.ingest(wire.batch(researcher, [rec.as_record()], prev_head=prev))
    prev = rec.head
print("done")
"""


def test_a_process_opening_beside_a_running_writer_never_mistakes_growth_for_tampering(tmp_path, svc, journal, signer, service_key, researcher_key):
    import subprocess
    import sys

    svc.register(wire.registration(researcher_key))
    keyfile, rkeyfile = tmp_path / "s.key.json", tmp_path / "r.key.json"
    service_key.write(keyfile)
    researcher_key.write(rkeyfile)
    writer = subprocess.Popen([sys.executable, "-c", _WRITER, str(journal.root), str(keyfile), str(rkeyfile),
                               str(tmp_path / "w.sqlite"), "300"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    opened, refused = 0, []
    while writer.poll() is None:
        try:
            Service(TransparencyLog.open(journal, signer))
            opened += 1
        except LogError as exc:
            refused.append(str(exc))
    out, err = writer.communicate()
    assert writer.returncode == 0, err.decode()
    assert refused == [] and opened > 0


def test_a_malformed_leaf_under_a_valid_checkpoint_is_a_log_error_not_a_crash(svc, journal, signer):
    _plant(journal, svc.log.size, {"v": 2, "kind": "batch", "ts": 1, "payload": {}}, signer=signer)
    bare = TransparencyLog.open(journal, signer)  # no service attached, so nothing admits or refuses it
    bare.checkpoint()  # and the service key signs over it, as a bug in an earlier release might have
    with pytest.raises(LogError, match="not an entry this service writes"):
        Service(TransparencyLog.open(journal, signer))


# --- from the fresh review of the fixes ----------------------------------------------------------


def test_a_failed_checkpoint_write_hands_out_nothing_another_process_could_contradict(tmp_path, signer, researcher_key):
    from crucible_core.canonical import canonicalize
    from crucible_service.log import ReceiptPending

    class Flaky(DirStore):
        fail = False

        def create(self, key, data):
            if self.fail and key.startswith("checkpoint/"):
                raise JournalError("the bucket is unreachable")
            return super().create(key, data)

    store = Flaky(tmp_path / "j")
    TransparencyLog.create(store, signer, service="test.service")
    first = Service(TransparencyLog.open(store, signer, clock=lambda: 1_800_000_000_000_000))
    store.fail = True
    with pytest.raises(ReceiptPending):
        first.register(wire.registration(researcher_key))
    with pytest.raises(ReceiptPending):  # the resend: still pending, never a receipt the journal lacks
        first.register(wire.registration(researcher_key))
    store.fail = False
    a = first.register(wire.registration(researcher_key))
    b = Service(TransparencyLog.open(DirStore(store.root), signer, clock=lambda: 1_900_000_000_000_000)).receipt_for(a["leaf_index"])
    assert canonicalize(a) == canonicalize(b)
    held = (store.root / checkpoint_key(a["leaf_index"] + 1)).read_bytes()
    assert base64.b64decode(a["checkpoint"]) == held


class Unordered(DirStore):
    """Lists the way a directory may while files are being created: out of order, and
    missing the newest leaf below one it does show."""

    def list(self, prefix):
        keys = super().list(prefix)
        if prefix == "leaf/" and len(keys) > 3:
            keys = keys[:-2] + keys[-1:]  # leaf n-2 created but not yet listed; n-1 is
            keys.reverse()
        return keys


def test_a_listing_out_of_order_is_growth_not_a_hole(svc, journal, signer, researcher_key, other_researcher):
    svc.register(wire.registration(researcher_key))
    svc.register(wire.registration(other_researcher))
    svc.register(wire.registration(PrivateKey.generate("researcher")))
    log = TransparencyLog.open(Unordered(journal.root), signer)
    assert log.size == svc.log.size


def test_a_registration_whose_key_label_is_not_a_short_string_writes_nothing(svc, journal, researcher_key):
    from crucible_core.cose import sign

    before = journal.list("")
    for label in [{"x": 1}, ["a"] * 3, "x" * 1000, 7]:
        public = {**researcher_key.public().to_dict(), "label": label}
        payload = {"v": 2, "kind": "register", "public_key": public}
        with pytest.raises(Refusal) as exc:
            svc.register(base64.b64encode(sign(payload, researcher_key)).decode())
        assert exc.value.status == 400
    assert journal.list("") == before


def test_a_registration_nested_deep_anywhere_is_a_400_at_any_stack_depth(svc, journal, researcher_key):
    import cbor2

    from crucible_core.canonical import canonicalize
    from crucible_core.cose import CONTENT_TYPE

    before = journal.list("")
    for depth in (65, 956, 983, 5000):
        text = canonicalize({"v": 2, "kind": "register", "public_key": researcher_key.public().to_dict()}).decode()
        text = text.replace('"label":"test-researcher"', '"label":' + "[" * depth + "]" * depth)
        body = text.encode()
        protected = cbor2.dumps({1: -8, 4: researcher_key.key_id.encode(), 3: CONTENT_TYPE})
        sig = researcher_key.obj.sign(cbor2.dumps(["Signature1", protected, b"", body]))
        env = base64.b64encode(cbor2.dumps(cbor2.CBORTag(18, [protected, {}, body, sig]))).decode()
        with pytest.raises(Refusal) as exc:
            svc.register(env)
        assert exc.value.status == 400, depth
    assert journal.list("") == before


def test_a_resend_whose_checkpoint_still_cannot_be_signed_says_receipt_pending(tmp_path, signer, researcher_key):
    from crucible_service.log import ReceiptPending

    class Fickle(LocalSigner):
        fail = False

        def sign(self, payload):
            if self.fail and payload.get("kind") == "checkpoint":
                raise TimeoutError("the key service timed out")
            return super().sign(payload)

    s = Fickle(signer._key)
    store = DirStore(tmp_path / "j")
    TransparencyLog.create(store, s, service="test.service")
    svc = Service(TransparencyLog.open(store, s))
    s.fail = True
    for _ in range(2):
        with pytest.raises(ReceiptPending) as exc:
            svc.register(wire.registration(researcher_key))
        assert exc.value.index == 1


@pytest.mark.parametrize("payload_change", [{"batch": 7}, {"batch": ["x"]}])
def test_a_signed_leaf_with_a_malformed_digest_is_a_log_error(svc, journal, signer, researcher_key, payload_change):
    svc.register(wire.registration(researcher_key))
    entry = {"v": 2, "kind": "batch", "ts": 1, "payload": {"session": "s", "key_id": researcher_key.key_id, "from_seq": 0,
             "to_seq": 0, "head": "sha256:" + "ab" * 32, "last_ts": 1, "batch": "sha256:" + "cd" * 32, **payload_change}}
    _plant(journal, svc.log.size, entry, signer=signer)
    with pytest.raises(LogError):
        svc.log.refresh()
