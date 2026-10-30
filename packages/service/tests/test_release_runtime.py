"""The service runs only from a release, and records the release it runs
(docs/v1-audit.md §5 step 9; SPEC.md §5 Deployment)."""

from __future__ import annotations

import subprocess
import sys

import pytest

from crucible_service import __main__ as entry
from crucible_service.journal import DirStore
from crucible_service.log import TransparencyLog
from crucible_service.service import Service
from crucible_service.signer import LocalSigner

A = "sha256:" + "aa" * 32
B = "sha256:" + "bb" * 32


def restart(journal, signer):
    return Service(TransparencyLog.open(DirStore(journal.root), signer))


def releases(svc):
    return [e["payload"] for e in svc.log.entries if e["kind"] == "release"]


def test_deploying_a_then_b_then_a_writes_three_releases_and_restarting_a_writes_none(svc, journal, signer):
    assert svc.record_release("v1", A) is not None
    s2 = restart(journal, signer)
    assert s2.record_release("v2", B) is not None
    s3 = restart(journal, signer)
    assert s3.record_release("v1", A) is not None  # a rollback is a deployment too
    s4 = restart(journal, signer)
    assert s4.record_release("v1", A) is None  # restarting the same digest appends nothing
    assert [r["digest"] for r in releases(restart(journal, signer))] == [A, B, A]


def test_a_release_entry_is_admitted_by_another_process_and_checked(svc, journal, signer):
    other = restart(journal, signer)
    other.record_release("v1", A)
    svc.log.refresh()
    assert svc.latest_release == {"tag": "v1", "digest": A}
    with pytest.raises(ValueError):
        svc.record_release("", "not-a-digest")


def test_a_platform_change_appends_one_host_entry(svc, journal, signer):
    facts = {"os": "Amazon Linux 2023.6", "kernel": "6.1.112", "docker": "25.0.6", "caddy": "sha256:" + "cc" * 32}
    assert svc.record_host(facts) is not None
    assert restart(journal, signer).record_host(facts) is None
    assert restart(journal, signer).record_host({**facts, "kernel": "6.1.115"}) is not None
    assert len([e for e in restart(journal, signer).log.entries if e["kind"] == "host"]) == 2


def test_an_editable_install_refuses_to_start(tmp_path, service_key):
    # This test environment is a uv workspace, so every crucible package is installed editable.
    assert "is an editable install" in entry.working_tree()
    key = tmp_path / "service.key.json"
    service_key.write(key)
    r = subprocess.run([sys.executable, "-m", "crucible_service", "--journal", str(tmp_path / "j"), "--key", str(key),
                        "--service", "test.service", "--genesis", "--release-tag", "v1", "--release-digest", A],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and "editable install" in r.stderr
    assert not (tmp_path / "j" / "leaf").exists()


def test_without_a_release_the_service_refuses_to_start(tmp_path, service_key, monkeypatch):
    monkeypatch.setattr(entry, "working_tree", lambda: None)  # as in a release image
    key = tmp_path / "service.key.json"
    service_key.write(key)
    assert entry.main(["--journal", str(tmp_path / "j"), "--key", str(key), "--service", "s", "--genesis"]) == 2


def test_dev_mode_is_refused_with_an_s3_journal(capsys):
    assert entry.main(["--journal", "s3://crucible-journal-x", "--key", "k", "--service", "s", "--dev"]) == 2
    assert "refused with an S3 journal" in capsys.readouterr().err


def test_a_release_start_records_the_release_and_host_facts(tmp_path, service_key, monkeypatch):
    import argparse
    import json

    monkeypatch.setattr(entry, "working_tree", lambda: None)
    key = tmp_path / "service.key.json"
    service_key.write(key)
    facts = tmp_path / "facts.json"
    facts.write_text(json.dumps({"os": "AL2023", "kernel": "6.1"}))
    args = argparse.Namespace(dev=False, journal=str(tmp_path / "j"), key=key, kms_key=None, service="s", genesis=True,
                              genesis_payload=None, release_tag="v1", release_digest=A, host_facts=facts)
    svc = entry.prepare(args)
    assert [e["kind"] for e in svc.log.entries] == ["service", "release", "host"]
    args.genesis = False
    again = entry.prepare(args)  # restarting the same release on the same host
    assert again.log.size == 3


def test_a_kms_key_bound_to_another_log_will_not_open_this_one(tmp_path):
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location("aws_fakes", Path(__file__).with_name("test_aws_adapters.py"))
    fakes = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fakes)  # the same fake KMS the adapter plants use
    from crucible_service.kms import KmsSigner

    FakeKMS = fakes.FakeKMS

    kms = FakeKMS()
    signer = KmsSigner("k", client=kms)
    store = DirStore(tmp_path / "j")
    entry.build(store, signer, "s", genesis=True)
    entry.build(DirStore(tmp_path / "j"), signer, "s", genesis=False)  # opens: the key is this log's
    from crucible_service.journal import JournalError

    with pytest.raises(JournalError, match="one key signs one log"):
        entry.build(DirStore(tmp_path / "k"), signer, "s", genesis=True)  # a second log under the same key
    kms.tags = [{"TagKey": "crucible:log_id", "TagValue": "another-log"}]
    with pytest.raises(JournalError, match="bound to log"):
        entry.build(DirStore(tmp_path / "j"), signer, "s", genesis=False)


def test_a_genesis_payload_joins_leaf_0_and_cannot_replace_what_it_names(tmp_path, service_key, monkeypatch):
    import argparse
    import json

    monkeypatch.setattr(entry, "working_tree", lambda: None)
    key = tmp_path / "service.key.json"
    service_key.write(key)
    payload = tmp_path / "genesis.json"
    archive = {"bucket": "crucible-archive-test", "key": "v1.tar.gz", "sha256": "sha256:" + "dd" * 32}
    payload.write_text(json.dumps({"predecessor": {"archive": archive}, "service": "evil", "key_id": "x"}))
    monkeypatch.setattr(entry, "open_store", lambda journal: LockedDir(journal, TEN_YEARS,
                                                                       {("crucible-archive-test", "v1.tar.gz"): archive["sha256"]}))
    args = argparse.Namespace(dev=False, journal=str(tmp_path / "j"), key=key, kms_key=None, service="log.test", genesis=True,
                              genesis_payload=payload, release_tag="v1", release_digest=A, host_facts=None)
    svc = entry.prepare(args)
    leaf0 = svc.log.entries[0]["payload"]
    assert leaf0["predecessor"] == {"archive": archive}
    assert leaf0["service"] == "log.test" and leaf0["key_id"] == service_key.key_id


class _Dist:
    """A distribution as importlib.metadata gives it: not editable, with the files it installed."""

    def __init__(self, files, direct_url="{}"):
        self.files, self.direct_url = files, direct_url

    def read_text(self, name):
        return self.direct_url if name == "direct_url.json" else None

    def locate_file(self, f):
        return f


def test_a_working_tree_anywhere_among_the_imports_refuses_to_start(monkeypatch):
    import crucible_chain
    import crucible_core
    import crucible_service
    import crucible_verify
    from importlib import metadata

    installed = {m.__name__.replace("_", "-"): _Dist([m.__file__]) for m in
                 (crucible_core, crucible_chain, crucible_verify, crucible_service)}
    monkeypatch.setattr(metadata, "distribution", lambda name: installed[name])
    assert entry.working_tree() is None  # every module is the file its non-editable distribution installed

    installed["crucible-core"] = _Dist([crucible_core.__file__], '{"url": "file:///src", "dir_info": {"editable": true}}')
    assert "crucible-core is an editable install" in entry.working_tree()
    installed["crucible-core"] = _Dist(["/elsewhere/site-packages/crucible_core/__init__.py"])
    assert "crucible_core is imported from" in entry.working_tree()  # a source tree on PYTHONPATH shadows the wheel

    def absent(name):
        if name == "crucible-chain":
            raise metadata.PackageNotFoundError(name)
        return installed[name]

    installed["crucible-core"] = _Dist([crucible_core.__file__])
    monkeypatch.setattr(metadata, "distribution", absent)
    assert "crucible-chain is not an installed distribution" in entry.working_tree()


def _release_args(tmp_path, service_key, **kw):
    import argparse

    key = tmp_path / "service.key.json"
    if not key.exists():
        service_key.write(key)
    base = dict(dev=False, journal=str(tmp_path / "j"), key=key, kms_key=None, service="s", genesis=True,
                genesis_payload=None, release_tag="v1", release_digest=A, host_facts=None, release_dir=None)
    return argparse.Namespace(**{**base, **kw})


def test_a_release_tag_that_is_not_the_images_own_refuses_to_start(tmp_path, service_key, monkeypatch):
    import json

    monkeypatch.setattr(entry, "working_tree", lambda: None)
    rel = tmp_path / "release"
    rel.mkdir()
    (rel / "RELEASE.json").write_text(json.dumps({"tag": "v1"}))
    with pytest.raises(entry.Refused, match="not this image's release"):
        entry.prepare(_release_args(tmp_path, service_key, release_tag="v2", release_dir=rel))
    assert not (tmp_path / "j" / "leaf").exists()
    assert entry.prepare(_release_args(tmp_path, service_key, release_dir=rel)).log.size == 2


@pytest.mark.parametrize("digest", ["sha256:" + "aa" * 31, "latest", "sha256:" + "AA" * 32, A + "\nIMAGE=x"])
def test_a_release_digest_that_is_not_an_image_digest_refuses_to_start(tmp_path, service_key, monkeypatch, digest):
    monkeypatch.setattr(entry, "working_tree", lambda: None)
    with pytest.raises(entry.Refused, match="not an image digest"):
        entry.prepare(_release_args(tmp_path, service_key, release_digest=digest))


def test_an_aws_error_at_start_is_reported_not_a_traceback(tmp_path, service_key, monkeypatch, capsys):
    from botocore.exceptions import ClientError, NoRegionError

    monkeypatch.setattr(entry, "working_tree", lambda: None)
    for exc in (NoRegionError(), ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "Sign")):
        def refuse(*_a, exc=exc):
            raise exc

        monkeypatch.setattr(entry, "open_signer", refuse)
        assert entry.main(["--journal", str(tmp_path / "j"), "--kms-key", "arn:aws:kms:us-west-2:1:key/x", "--service", "s",
                           "--genesis", "--release-tag", "v1", "--release-digest", A]) == 2
        assert type(exc).__name__ in capsys.readouterr().err


def test_prepare_only_starts_the_log_and_exits(tmp_path, service_key, monkeypatch, capsys):
    import json

    monkeypatch.setattr(entry, "working_tree", lambda: None)
    key = tmp_path / "service.key.json"
    service_key.write(key)
    argv = ["--journal", str(tmp_path / "j"), "--key", str(key), "--service", "s", "--release-tag", "v1",
            "--release-digest", A, "--prepare-only"]
    assert entry.main([*argv, "--genesis"]) == 0
    said = json.loads(capsys.readouterr().out)
    log = TransparencyLog.open(DirStore(tmp_path / "j"), LocalSigner(service_key))
    assert said == {"service": "s", "log_id": log.log_id, "key_id": service_key.key_id, "tree_size": 2}
    assert [e["kind"] for e in log.entries] == ["service", "release"]
    assert entry.main(argv) == 0 and json.loads(capsys.readouterr().out)["tree_size"] == 2  # the same release: nothing new


def test_a_release_dir_without_a_published_key_refuses_to_start(tmp_path, capsys):
    assert entry.main(["--journal", str(tmp_path / "j"), "--key", "k", "--service", "s", "--release-dir", str(tmp_path)]) == 2
    assert "--published" in capsys.readouterr().err


def test_a_malformed_kms_arn_is_refused_not_a_traceback(tmp_path, capsys):
    from crucible_service.kms import region_of

    assert region_of("arn:aws:kms:us-west-2:1:key/x") == "us-west-2" and region_of("alias/crucible") is None
    for bad in ("arn:aws", "arn:aws:s3:us-west-2:1:bucket", "arn:aws:kms::1:key/x"):
        with pytest.raises(ValueError, match="not a KMS key ARN"):
            region_of(bad)
    assert entry.main(["--dev", "--journal", str(tmp_path / "j"), "--kms-key", "arn:aws", "--service", "s", "--genesis"]) == 2
    assert "not a KMS key ARN" in capsys.readouterr().err


def test_a_checkpoint_that_could_not_be_signed_at_start_is_reported(tmp_path, service_key, monkeypatch, capsys):
    from crucible_service.signer import LocalSigner as Local

    class NoCheckpoints(Local):
        def sign(self, payload):
            if isinstance(payload, dict) and payload.get("kind") == "checkpoint":
                raise RuntimeError("throttled")
            return super().sign(payload)

    monkeypatch.setattr(entry, "open_signer", lambda key, kms: NoCheckpoints(service_key))
    assert entry.main(["--dev", "--journal", str(tmp_path / "j"), "--key", "k", "--service", "s", "--genesis",
                       "--prepare-only"]) == 2
    assert "next start signs its checkpoint (do not run genesis again)" in capsys.readouterr().err


def test_a_checkpoint_left_unsigned_at_one_start_is_signed_at_the_next(tmp_path, service_key, monkeypatch):
    from crucible_service.signer import LocalSigner as Local

    class NoCheckpoints(Local):
        def sign(self, payload):
            if isinstance(payload, dict) and payload.get("kind") == "checkpoint":
                raise RuntimeError("throttled")
            return super().sign(payload)

    monkeypatch.setattr(entry, "open_signer", lambda key, kms: NoCheckpoints(service_key))
    base = ["--dev", "--journal", str(tmp_path / "j"), "--key", "k", "--service", "s", "--prepare-only"]
    assert entry.main([*base, "--genesis"]) == 2
    assert not list((tmp_path / "j").glob("checkpoint/*"))  # leaf 0 is written; its checkpoint is not
    monkeypatch.setattr(entry, "open_signer", lambda key, kms: Local(service_key))
    assert entry.main(base) == 0
    assert (tmp_path / "j" / "checkpoint" / "000000000001").exists()


def test_genesis_left_unsigned_is_signed_at_a_release_start_and_an_outage_does_not_stop_a_start(tmp_path, service_key,
                                                                                               monkeypatch, capsys):
    from crucible_service.signer import LocalSigner as Local

    class NoCheckpoints(Local):
        def sign(self, payload):
            if isinstance(payload, dict) and payload.get("kind") == "checkpoint":
                raise RuntimeError("KMS unreachable")
            return super().sign(payload)

    monkeypatch.setattr(entry, "working_tree", lambda: None)
    base = ["--journal", str(tmp_path / "j"), "--key", "k", "--service", "s", "--release-tag", "v1",
            "--release-digest", A, "--prepare-only"]
    monkeypatch.setattr(entry, "open_signer", lambda key, kms: NoCheckpoints(service_key))
    assert entry.main([*base, "--genesis"]) == 2  # leaf 0 written, its checkpoint not
    assert entry.main(base) == 2  # the release entry, appended during the outage, is pending too
    assert entry.main(base) == 0  # nothing new to append: the outage no longer stops a start
    assert "not all signed yet" in capsys.readouterr().err
    monkeypatch.setattr(entry, "open_signer", lambda key, kms: Local(service_key))
    newer = [a if a != "v1" else "v2" for a in base]
    newer[newer.index(A)] = B
    assert entry.main(newer) == 0  # a new release's entry is appended, and signed, at this start
    for size in (1, 2, 3):  # genesis's own and the first release's, signed first, before the new entry
        assert (tmp_path / "j" / "checkpoint" / f"{size:012d}").exists(), size


class LockedDir(DirStore):
    """A directory journal reporting an S3 bucket's default retention, and the digests S3 holds
    for objects, as S3Store does."""

    def __init__(self, root, rule, digests=None):
        super().__init__(root)
        self.rule, self.digests = rule, digests or {}

    def default_retention(self):
        return self.rule

    def object_sha256(self, bucket, key):
        from crucible_service.journal import JournalError

        if (bucket, key) not in self.digests:
            raise JournalError(f"cannot read s3://{bucket}/{key}: NotFound")
        return self.digests[(bucket, key)]


TEN_YEARS = {"Mode": "GOVERNANCE", "Years": 10}


class RetentionOnlyDir(DirStore):
    """A journal that states its retention but cannot read S3 objects (a directory)."""

    def default_retention(self):
        return TEN_YEARS


ARCHIVE = ("crucible-archive-test", "v1.tar.gz")
ARCHIVE_SHA = "sha256:" + "ab" * 32


def genesis_args(tmp_path, service_key, payload):
    import argparse

    key = tmp_path / "service.key.json"
    service_key.write(key)
    return argparse.Namespace(dev=False, journal=str(tmp_path / "j"), key=key, kms_key=None, service="log.cruciblehub.org",
                              genesis=True, genesis_payload=payload, release_tag="v1", release_digest=A, host_facts=None)


def genesis_document() -> dict:
    """A genesis payload shaped like a deployment's template: a predecessor's archive, with the
    template's blank where its digest goes, and the journal's retention."""
    return {"predecessor": {"system": "a predecessor", "archive": {"bucket": ARCHIVE[0], "key": ARCHIVE[1],
                                                                    "sha256": entry.TEMPLATE_BLANK}},
            "journal": {"object_lock": "GOVERNANCE", "default_retention_years": 10}}


REFUSALS = {  # each case, and the reason genesis gives
    "unfilled": "template's blank", "base64": "wants an archive", "no-prefix": "wants an archive",
    "no-key": "wants an archive", "wrong-digest": "but S3 holds sha256:", "wrong-bucket": "cannot be read",
    "no-checksum": "no full-object SHA-256", "directory-journal": "only an S3 journal can check",
    "blank-elsewhere": "template's blank", "predecessor-string": "wants an archive", "shorter-retention": "default retention",
    "days": "default retention", "compliance": "default retention", "no-object-lock": "default retention",
}


@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_genesis_refuses_a_payload_that_would_make_leaf_0_say_something_untrue(tmp_path, service_key, monkeypatch, case):
    # Leaf 0 is written once and the key is bound to its log: a slip in the payload cannot be undone.
    import json

    doc = json.loads(json.dumps(genesis_document()).replace(entry.TEMPLATE_BLANK, ARCHIVE_SHA))
    rule, digests = TEN_YEARS, {ARCHIVE: ARCHIVE_SHA}
    if case == "unfilled":
        doc = genesis_document()
    elif case == "base64":  # what the put-object answer gives as ChecksumSHA256
        doc["predecessor"]["archive"]["sha256"] = "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s="
    elif case == "no-prefix":
        doc["predecessor"]["archive"]["sha256"] = "ab" * 32
    elif case == "no-key":
        del doc["predecessor"]["archive"]["key"]
    elif case == "wrong-digest":  # well formed, but not what S3 holds: a slip copying it by hand
        doc["predecessor"]["archive"]["sha256"] = "sha256:" + "cd" * 32
    elif case == "wrong-bucket":
        doc["predecessor"]["archive"]["bucket"] = "crucible-archiv-test"
    elif case == "no-checksum":  # S3 holds no full-object SHA-256 for it
        digests = {ARCHIVE: None}
    elif case == "blank-elsewhere":
        doc["note"] = entry.TEMPLATE_BLANK
    elif case == "predecessor-string":
        doc["predecessor"] = "Crucible v1, sha256:" + "ab" * 32
    elif case == "shorter-retention":
        rule = {"Mode": "GOVERNANCE", "Years": 1}
    elif case == "days":
        rule = {"Mode": "GOVERNANCE", "Days": 3650}
    elif case == "compliance":
        rule = {"Mode": "COMPLIANCE", "Years": 10}
    elif case == "no-object-lock":
        rule = None
    payload = tmp_path / "genesis.json"
    payload.write_text(json.dumps(doc))
    monkeypatch.setattr(entry, "working_tree", lambda: None)
    monkeypatch.setattr(entry, "open_store", RetentionOnlyDir if case == "directory-journal" else
                        (lambda journal: LockedDir(journal, rule, digests)))
    with pytest.raises(entry.Refused, match="genesis payload") as refused:
        entry.prepare(genesis_args(tmp_path, service_key, payload))
    assert REFUSALS[case] in str(refused.value)
    assert not [f for f in (tmp_path / "j").rglob("*") if f.is_file()]  # refused before anything was written
