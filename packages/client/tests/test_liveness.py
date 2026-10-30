"""The liveness probe against a real service (docs/v1-audit.md §5 step 10): it passes
while the service anchors what it sends, and stops passing when ingest stops."""

from __future__ import annotations

import json

import pytest

from crucible_client import liveness


def test_the_probe_passes_while_the_service_anchors_its_events(tmp_path, ephemeral_service):
    home = tmp_path / "probe"
    liveness.setup(ephemeral_service.url, home)
    first = liveness.probe(home)
    assert first["ok"], first["detail"]
    second = liveness.probe(home)
    assert second["ok"] and second["last_pass"] >= first["last_pass"]
    assert json.loads(liveness.status_path(home).read_text()) == second
    assert ephemeral_service.service.log.size >= 4  # genesis, the probe's key, two batches


def test_stop_ingest_and_the_probe_stops_passing_keeping_the_last_pass(tmp_path, ephemeral_service):
    home = tmp_path / "probe"
    liveness.setup(ephemeral_service.url, home)
    passed = liveness.probe(home)
    ephemeral_service.stop()
    failed = liveness.probe(home)
    assert not failed["ok"] and failed["last_pass"] == passed["last_pass"] and failed["detail"]
    ephemeral_service.start()
    again = liveness.probe(home)  # the queued event goes too, and the whole day's session verifies
    assert again["ok"], again["detail"]


def test_a_probe_that_was_never_set_up_does_not_pass(tmp_path):
    status = liveness.probe(tmp_path / "nothing")
    assert not status["ok"] and status["last_pass"] is None and "crucible install" in status["detail"]


def test_an_earlier_days_refused_session_does_not_fail_todays_pass(tmp_path, ephemeral_service, monkeypatch):
    from crucible_chain.events import draft
    from crucible_chain.store import ChainStore
    from crucible_client import paths
    from crucible_client.sender import Sender, Stuck

    home = tmp_path / "probe"
    liveness.setup(ephemeral_service.url, home)
    with ChainStore(paths.chain_path(home)) as store:
        store.append("liveness-2020-01-01", draft("prompt", liveness.ACTOR, "witnessed", {"probe": "liveness"}, content={"at": 1}))
    original = Sender._drain_session

    def refuse_the_old_day(self, store, session, until):
        if session == "liveness-2020-01-01":
            raise Stuck("the service refuses events 0..0 (chain_break, next expected 1)")
        return original(self, store, session, until)

    monkeypatch.setattr(Sender, "_drain_session", refuse_the_old_day)
    status = liveness.probe(home)
    assert status["ok"] and status["detail"] == "intact", status["detail"]


def test_setup_pins_only_the_expected_key_and_never_moves_a_probe(tmp_path, ephemeral_service, make_service, service_key):
    from crucible_client import config
    from crucible_client.cli import Refused
    from crucible_core.keys import PrivateKey

    home = tmp_path / "probe"
    other = PrivateKey.generate("service").public()
    with pytest.raises(Refused, match="not the expected"):
        liveness.setup(ephemeral_service.url, home, expect=other)
    assert not config.config_path(home).exists()
    liveness.setup(ephemeral_service.url, home, expect=service_key.public())
    assert liveness.probe(home)["ok"]
    elsewhere = make_service()
    with pytest.raises(Refused, match="already sends to"):
        liveness.setup(elsewhere.url, home)
    assert config.load(home).service == ephemeral_service.url


def test_the_metric_and_the_status_are_published_independently():
    sent = []

    class Client:
        def __init__(self, name, fail):
            self.name, self.fail = name, fail

        def put_metric_data(self, **kw):
            if self.fail:
                raise OSError("cloudwatch down")
            sent.append(("metric", kw["MetricData"][0]["Value"]))

        def put_object(self, **kw):
            if self.fail:
                raise OSError("s3 down")
            sent.append(("status", kw["Key"]))

    status = {"ok": True}
    for failing, expect in ((None, [("metric", 1.0), ("status", "status.json")]), ("s3", [("metric", 1.0)]),
                            ("cloudwatch", [("status", "status.json")])):
        sent.clear()
        failures = liveness.publish(status, bucket="b", metric_region="us-east-1",
                                    client=lambda name, region_name=None: Client(name, name == failing))
        assert sent == expect and len(failures) == (failing is not None)


def test_the_expected_key_is_read_from_kms():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from crucible_core.keys import compute_key_id

    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    class Kms:
        def get_public_key(self, KeyId):
            return {"PublicKey": priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)}

    key = liveness.kms_public_key("arn:aws:kms:us-west-2:1:key/x", client=Kms())
    assert (key.role, key.key_id, key.public_bytes) == ("service", compute_key_id(raw), raw)


def test_a_surprise_in_todays_session_is_not_a_pass(tmp_path, ephemeral_service, monkeypatch):
    from crucible_client.sender import Sender

    home = tmp_path / "probe"
    liveness.setup(ephemeral_service.url, home)

    def explodes(self, store, session, until):
        raise OverflowError("something unexpected")

    monkeypatch.setattr(Sender, "_drain_session", explodes)
    status = liveness.probe(home)
    assert not status["ok"] and "OverflowError" in status["detail"]


def test_the_probe_sends_only_the_days_session(tmp_path, ephemeral_service):
    from crucible_chain.events import draft
    from crucible_chain.store import ChainStore
    from crucible_client import paths

    home = tmp_path / "probe"
    liveness.setup(ephemeral_service.url, home)
    with ChainStore(paths.chain_path(home)) as store:
        store.append("liveness-2020-01-01", draft("prompt", liveness.ACTOR, "witnessed", {"probe": "liveness"}, content={"at": 1}))
    assert liveness.probe(home)["ok"]
    with ChainStore(paths.chain_path(home)) as store:
        assert store.last_receipted_seq("liveness-2020-01-01") == -1  # an old day is not the probe's to send


@pytest.mark.parametrize("arn", ["arn:aws", "arn:aws:s3:us-west-2:1:bucket", "arn:aws:kms::1:key/x"])
def test_a_malformed_kms_arn_is_refused_before_kms_is_asked(arn, monkeypatch):
    import boto3

    class Never:
        def get_public_key(self, KeyId):
            raise AssertionError("KMS was asked")

    monkeypatch.setattr(boto3, "client", lambda *a, **k: Never())  # a regression fails here, never on real AWS
    with pytest.raises(ValueError, match="not a KMS key ARN"):
        liveness.kms_public_key(arn)
