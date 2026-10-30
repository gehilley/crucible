"""The S3 journal and the KMS signer, against in-memory fakes of the two APIs
that keep their semantics: S3's 412 on ``If-None-Match: *``, versions and
delete markers, and KMS's DER public key and raw Ed25519 signatures. The real
services are exercised at step 12, against the deployed key and bucket."""

from __future__ import annotations

import base64
import concurrent.futures as cf
import hashlib
import io
import threading

import pytest
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from crucible_chain import wire
from crucible_core.keys import PrivateKey
from crucible_service.journal import JournalError
from crucible_service.kms import LOG_TAG, KmsSigner
from crucible_service.log import TransparencyLog
from crucible_service.s3store import S3Store
from crucible_service.service import Service
from crucible_service.signer import LocalSigner


def _error(status: int, code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}, "ResponseMetadata": {"HTTPStatusCode": status}}, "op")


class _Pager:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, *, Bucket, Prefix=""):
        return iter(self.pages(Prefix))


GOVERNANCE = {"Mode": "GOVERNANCE", "Days": 3650}


class FakeS3:
    def __init__(self, *, locked=True, retention: dict | None = GOVERNANCE):
        self.objects: dict[str, bytes] = {}
        self.archives: dict[tuple[str, str], bytes] = {}  # other buckets' objects, by (bucket, key)
        self.versions: list[str] = []
        self.delete_markers: list[str] = []
        self.locked = locked
        self.retention = retention
        self.lock = threading.Lock()
        self.puts = []

    def put_object(self, *, Bucket, Key, Body, IfNoneMatch=None, ChecksumAlgorithm=None):
        assert IfNoneMatch == "*" and ChecksumAlgorithm == "SHA256"
        self.puts.append(Key)
        with self.lock:
            if Key in self.objects:
                raise _error(412, "PreconditionFailed")
            self.objects[Key] = bytes(Body)
            self.versions.append(Key)

    def get_object(self, *, Bucket, Key):
        if Key not in self.objects:
            raise _error(404, "NoSuchKey")
        return {"Body": io.BytesIO(self.objects[Key])}

    def get_paginator(self, name):
        if name == "list_objects_v2":
            def pages(prefix):
                keys = sorted(k for k in self.objects if k.startswith(prefix))
                return [{"Contents": [{"Key": k} for k in keys[i:i + 3]]} for i in range(0, len(keys), 3)] or [{}]
            return _Pager(pages)
        return _Pager(lambda prefix: [{"Versions": [{"Key": k} for k in self.versions if k.startswith(prefix)],
                                       "DeleteMarkers": [{"Key": k} for k in self.delete_markers if k.startswith(prefix)]}])

    def head_object(self, *, Bucket, Key, ChecksumMode=None):
        assert ChecksumMode == "ENABLED"  # without it S3 leaves the checksum out
        if (Bucket, Key) not in self.archives:
            raise _error(404, "NotFound")
        digest = base64.b64encode(hashlib.sha256(self.archives[(Bucket, Key)]).digest()).decode()
        return {"ChecksumSHA256": digest, "ChecksumType": "FULL_OBJECT"}

    def get_object_lock_configuration(self, *, Bucket):
        config = {"ObjectLockEnabled": "Enabled" if self.locked else "Disabled"}
        if self.retention is not None:  # S3 leaves out Rule when the bucket has no default retention
            config["Rule"] = {"DefaultRetention": self.retention}
        return {"ObjectLockConfiguration": config}


class FakeKMS:
    def __init__(self, seed: bytes = bytes(range(32, 64))):
        self.priv = Ed25519PrivateKey.from_private_bytes(seed)
        self.tags: list[dict] = []
        self.signed = 0

    def get_public_key(self, *, KeyId):
        der = self.priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return {"PublicKey": der, "KeySpec": "ECC_NIST_EDWARDS25519", "SigningAlgorithms": ["ED25519_SHA_512"]}

    def sign(self, *, KeyId, Message, MessageType, SigningAlgorithm):
        assert (MessageType, SigningAlgorithm) == ("RAW", "ED25519_SHA_512") and len(Message) <= 4096
        self.signed += 1
        return {"Signature": self.priv.sign(Message)}

    def list_resource_tags(self, *, KeyId):
        return {"Tags": list(self.tags)}

    def tag_resource(self, *, KeyId, Tags):
        if any(t["TagKey"] == LOG_TAG for t in self.tags):  # the role's policy: the log tag is set once
            raise _error(400, "AccessDeniedException")
        self.tags = [t for t in self.tags if t["TagKey"] not in {x["TagKey"] for x in Tags}] + list(Tags)


# --- the S3 journal ------------------------------------------------------------------


def test_a_log_on_the_s3_journal_ingests_reopens_and_never_forks(service_key, researcher_key, chain):
    s3 = FakeS3()
    store = S3Store("crucible-journal-test", client=s3)
    signer = LocalSigner(service_key)
    svc = Service(TransparencyLog.create(store, signer, service="test.service"))
    svc.register(wire.registration(researcher_key))
    recs = chain("s-1", 6)
    svc.ingest(wire.batch(researcher_key, recs[:3]))
    again = Service(TransparencyLog.open(S3Store("crucible-journal-test", client=s3), signer))
    again.ingest(wire.batch(researcher_key, recs[3:], prev_head=recs[2]["head"]))
    nodes = [Service(TransparencyLog.open(S3Store("crucible-journal-test", client=s3), signer)) for _ in range(2)]
    more = {f"r-{i}": chain(f"r-{i}", 2) for i in range(6)}
    with cf.ThreadPoolExecutor(6) as pool:
        list(pool.map(lambda kv: nodes[hash(kv[0]) % 2].ingest(wire.batch(researcher_key, kv[1])), more.items()))
    fresh = TransparencyLog.open(S3Store("crucible-journal-test", client=s3), signer)
    assert sum(1 for e in fresh.entries if e["kind"] == "batch") == 2 + 6
    assert len([k for k in s3.objects if k.startswith("leaf/")]) == fresh.size  # one leaf per index, no fork


def test_create_is_false_when_the_key_exists():
    s3 = FakeS3()
    store = S3Store("b", client=s3)
    assert store.create("leaf/000000000000", b"a") is True
    assert store.create("leaf/000000000000", b"b") is False
    assert s3.objects["leaf/000000000000"] == b"a"


def test_an_unreachable_bucket_is_a_journal_error():
    class Down(FakeS3):
        def put_object(self, **kw):
            raise _error(503, "SlowDown")

    with pytest.raises(JournalError, match="SlowDown"):
        S3Store("b", client=Down()).create("leaf/000000000000", b"a")


def test_a_bucket_that_is_not_write_once_refuses_to_serve():
    with pytest.raises(JournalError, match="Object Lock"):
        S3Store("b", client=FakeS3(locked=False)).check_write_once()


@pytest.mark.parametrize("retention", [None, {"Mode": "GOVERNANCE"}, {"Mode": "GOVERNANCE", "Days": 0},
                                       {"Days": 30}, {"Mode": "OFF", "Years": 1}, {"Mode": "GOVERNANCE", "Days": True}])
def test_a_bucket_with_object_lock_but_no_default_retention_refuses_to_serve(retention):
    # Object Lock enabled with no default rule retains nothing: a leaf could be deleted without a bypass.
    with pytest.raises(JournalError, match="no default Object Lock retention"):
        S3Store("b", client=FakeS3(retention=retention)).check_write_once()


@pytest.mark.parametrize("retention", [GOVERNANCE, {"Mode": "COMPLIANCE", "Years": 10}])
def test_a_bucket_with_default_retention_serves(retention):
    S3Store("b", client=FakeS3(retention=retention)).check_write_once()


def test_the_s3_journal_reports_the_digest_s3_holds_for_an_object_for_genesis_to_check():
    s3 = FakeS3()
    s3.archives[("crucible-archive-test", "crucible-v1-archive.tar.gz")] = b"the v1 archive"
    store = S3Store("crucible-journal-test", client=s3)
    assert store.object_sha256("crucible-archive-test", "crucible-v1-archive.tar.gz") == \
        "sha256:" + hashlib.sha256(b"the v1 archive").hexdigest()
    for bucket, key in (("crucible-archive-test", "missing.tar.gz"), ("crucible-journal-test", "crucible-v1-archive.tar.gz")):
        with pytest.raises(JournalError, match="cannot read"):  # the bucket asked for, not the journal's
            store.object_sha256(bucket, key)
    full = base64.b64encode(hashlib.sha256(b"the v1 archive").digest()).decode()
    for head in ({"ChecksumSHA256": full + "-3", "ChecksumType": "COMPOSITE"},  # a multipart upload's
                 {"ChecksumSHA256": full, "ChecksumType": "COMPOSITE"},
                 {"ChecksumSHA256": full + "-3"},
                 {}):  # stored with no SHA-256 checksum
        s3.head_object = lambda head=head, **kw: head
        assert store.object_sha256("crucible-archive-test", "crucible-v1-archive.tar.gz") is None, head


def test_the_s3_journal_reports_its_default_retention_for_genesis_to_check():
    assert S3Store("b", client=FakeS3(retention={"Mode": "GOVERNANCE", "Years": 10})).default_retention() == \
        {"Mode": "GOVERNANCE", "Years": 10}


@pytest.mark.parametrize("damage", ["delete-marker", "second-version"])
def test_a_journal_with_something_removed_or_overwritten_refuses_to_serve(damage):
    s3 = FakeS3()
    store = S3Store("b", client=s3)
    store.create("leaf/000000000000", b"a")
    store.check_write_once()
    if damage == "delete-marker":
        s3.delete_markers.append("leaf/000000000001")
    else:
        s3.versions.append("leaf/000000000000")
    with pytest.raises(JournalError, match="removed|overwritten"):
        store.check_write_once()


# --- the KMS signer --------------------------------------------------------------------


def test_kms_envelopes_are_byte_identical_to_the_file_keys_for_the_same_key_bytes(service_key):
    kms = KmsSigner("alias/crucible-test", client=FakeKMS(bytes(range(32, 64))))
    local = LocalSigner(service_key)  # the conftest service key is seeded bytes(range(32, 64))
    assert kms.key_id == local.key_id
    payload = {"v": 2, "kind": "checkpoint", "tree_size": 1}
    assert kms.sign(payload) == local.sign(payload)


def test_a_log_signed_in_kms_verifies_with_the_independent_verifier(researcher_key, chain):
    from crucible_verify.receipts import check_receipt
    from crucible_verify.results import State

    signer = KmsSigner("k", client=FakeKMS(bytes(range(100, 132))))
    svc = Service(TransparencyLog.create(S3Store("b", client=FakeS3()), signer, service="test.service"))
    svc.register(wire.registration(researcher_key))
    recs = chain("s-1", 3)
    rc = svc.ingest(wire.batch(researcher_key, recs))
    res = check_receipt(rc, session="s-1", heads={r["seq"]: r["head"] for r in recs}, service_key=signer.public())
    assert res.check.state == State.PASS, res.check.reason


def test_one_kms_key_signs_one_log():
    kms = FakeKMS()
    signer = KmsSigner("k", client=kms)
    signer.bind("log-a", genesis=True)
    assert kms.tags == [{"TagKey": LOG_TAG, "TagValue": "log-a"}]
    signer.bind("log-a", genesis=False)
    with pytest.raises(JournalError, match="one key signs one log"):
        signer.bind("log-b", genesis=True)
    with pytest.raises(JournalError, match="bound to log"):
        signer.bind("log-b", genesis=False)


def test_a_genesis_that_cannot_be_written_binds_nothing(tmp_path):
    from crucible_service.__main__ import build
    from crucible_service.journal import DirStore
    from crucible_service.log import LogError, SignerError

    kms = FakeKMS()
    with pytest.raises(LogError, match="could not read back"):  # JCS refuses 2**60: leaf 0 could never be read
        build(DirStore(tmp_path / "j"), KmsSigner("k", client=kms), "s", genesis=True, genesis_payload={"n": 2**60})
    assert kms.tags == [] and not (tmp_path / "j" / "leaf").exists()

    class Down(FakeKMS):
        def sign(self, **kw):
            raise _error(503, "KMSInternalException")

    down = Down()
    with pytest.raises(SignerError):
        build(DirStore(tmp_path / "k"), KmsSigner("k", client=down), "s", genesis=True)
    assert down.tags == []
    build(DirStore(tmp_path / "j"), KmsSigner("k", client=kms), "s", genesis=True)  # the key is still free
    assert [t["TagKey"] for t in kms.tags] == [LOG_TAG]


def test_the_kms_client_is_made_in_the_keys_region(monkeypatch):
    import boto3

    from crucible_service import kms as kms_module

    made = []
    monkeypatch.setattr(boto3, "client", lambda name, region_name=None: made.append((name, region_name)) or FakeKMS())
    KmsSigner("arn:aws:kms:us-west-2:111122223333:key/00000000-0000-0000-0000-000000000000")
    assert made == [("kms", "us-west-2")]
    kms_module._client("alias/local")
    assert made[-1] == ("kms", None)


def test_a_kms_key_that_is_not_ed25519_is_refused():
    class Rsa(FakeKMS):
        def get_public_key(self, *, KeyId):
            return {**super().get_public_key(KeyId=KeyId), "KeySpec": "RSA_2048", "SigningAlgorithms": ["RSASSA_PSS_SHA_256"]}

    with pytest.raises(ValueError, match="not an Ed25519"):
        KmsSigner("k", client=Rsa())


def test_a_genesis_whose_leaf_could_not_be_written_resumes_in_its_own_journal_and_nowhere_else(tmp_path):
    from crucible_service.__main__ import build
    from crucible_service.journal import DirStore

    class FailsOnce(DirStore):
        failing = True

        def create(self, key, data):
            if key.startswith("leaf/") and self.failing:
                self.failing = False
                raise JournalError(f"cannot create {key}: AccessDenied")
            return super().create(key, data)

    kms = FakeKMS()
    with pytest.raises(JournalError, match="AccessDenied"):
        build(FailsOnce(tmp_path / "j"), KmsSigner("k", client=kms), "s", genesis=True)
    [bound] = [t["TagValue"] for t in kms.tags if t["TagKey"] == LOG_TAG]  # the key was claimed; leaf 0 is missing
    with pytest.raises(JournalError, match="did not start"):
        build(DirStore(tmp_path / "other"), KmsSigner("k", client=kms), "s", genesis=True)
    svc = build(DirStore(tmp_path / "j"), KmsSigner("k", client=kms), "s", genesis=True)  # the same journal resumes
    assert svc.log.log_id == bound and svc.log.size == 1
    assert build(DirStore(tmp_path / "j"), KmsSigner("k", client=kms), "s", genesis=False).log.log_id == bound


def test_a_claim_copied_or_planted_in_another_journal_does_not_resume(tmp_path):
    from crucible_service.__main__ import build
    from crucible_service.log import claim_key

    s3, kms = FakeS3(), FakeKMS()
    live = build(S3Store("b", prefix="j1/", client=s3), KmsSigner("k", client=kms), "s", genesis=True)
    claim = s3.objects["j1/" + claim_key(live.log.log_id)]
    for planted in (claim, b"anything at all"):  # the claim copied to another prefix, or anything under its name
        s3.objects["j2/" + claim_key(live.log.log_id)] = planted
        with pytest.raises(JournalError, match="did not start"):
            build(S3Store("b", prefix="j2/", client=s3), KmsSigner("k", client=kms), "s", genesis=True)
        assert not any(k.startswith("j2/leaf/") for k in s3.objects)
