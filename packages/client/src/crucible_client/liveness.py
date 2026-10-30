"""``crucible-liveness``: the service checking itself the way a stranger would (SPEC.md §5 Liveness;
docs/v1-audit.md §5 step 10).

    crucible-liveness --setup https://log.cruciblehub.org --expect-kms-key ARN   # once
    crucible-liveness                                    # every 15 minutes (a systemd timer)

Setup gives the probe a key, pins the service key, and registers, with the same
checks as ``crucible install``; with ``--expect-kms-key`` the key the address
presents must be the KMS key's own, so the probe never pins whatever the
address happens to present. A probe already set up is never moved to another
service or key.

Each run records one known event -- a ``prompt`` by ``tool:crucible-liveness``
-- in the probe's own session for the day, through this client's store and
sender, to the service's public address, and sends that session only. It
passes when the session's every event is anchored by receipts that check
against the pinned service key: the day's record verifies intact. An earlier
day's session the service refused does not fail today's pass. It then writes
``status.json``
(``{v, service, last_pass, last_attempt, ok, detail}``, times in microseconds)
to the probe's home, and, when asked, publishes it to the status page's bucket
and a ``LivenessPass`` metric (1 on a pass) that the heartbeat alarm watches.

The probe's home is its own (``$CRUCIBLE_HOME``); it installs no hooks and
starts no sender: it sends what it records itself, then exits.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from crucible_chain.events import draft
from crucible_chain.export import loads, write
from crucible_chain.store import ChainStore
from crucible_core import atomic
from crucible_core.keys import PrivateKey, PublicKey, compute_key_id
from crucible_verify.report import verify_record
from crucible_verify.results import State

from . import config, paths
from .sender import Sender

ACTOR = "tool:crucible-liveness"


def now_us() -> int:
    return time.time_ns() // 1000


def status_path(home: Path) -> Path:
    return home / "status.json"


def setup(address: str, home: Path, *, expect: PublicKey | None = None) -> str:
    """Give the probe a key, pin the service key (``expect``, when given), and register."""
    from .cli import _address, register  # the install command's own checks

    service = _address(address)
    home.mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)
    key_file = config.key_path(home)
    if key_file.exists():
        key = PrivateKey.read(key_file)
    else:
        key = PrivateKey.generate("researcher", label="liveness probe")
        key.write(key_file)
    register(service, home, key, expect=expect)
    return key.key_id


def kms_public_key(arn: str, *, client=None) -> PublicKey:
    """The service key as KMS holds it (the region is the ARN's)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

    if client is None:
        import boto3

        parts = arn.split(":")
        if arn.startswith("arn:") and (len(parts) < 6 or parts[2] != "kms" or not parts[3]):
            raise ValueError(f"{arn!r} is not a KMS key ARN")
        client = boto3.client("kms", region_name=parts[3] if arn.startswith("arn:") else None)
    public = load_der_public_key(client.get_public_key(KeyId=arn)["PublicKey"])
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError(f"KMS key {arn} does not hold an Ed25519 public key")
    raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return PublicKey(role="service", key_id=compute_key_id(raw), public_bytes=raw)


def probe(home: Path, *, clock=now_us) -> dict:
    """One pass: record, send, verify. Returns the status written."""
    previous = _read(status_path(home))
    at = clock()
    session = "liveness-" + datetime.fromtimestamp(at / 1e6, UTC).strftime("%Y-%m-%d")
    ok, detail = False, ""
    try:
        cfg = config.load(home)
        with ChainStore(paths.chain_path(home)) as store:
            seq = store.append(session, draft("prompt", ACTOR, "witnessed", {"probe": "liveness"}, content={"at": at})).seq
            earlier = set(store.sessions()) - {session}
        out = Sender(cfg).drain(until={session: seq})  # today's session only: an old refusal is not today's failure
        failed = [*(r for r in out.retried if r.split(": ", 1)[0] not in earlier),
                  *(f"{s}: {w}" for s, w in {**out.stuck, **out.failed}.items() if s == session)]
        if failed:
            detail = "; ".join(failed)[:500]
        else:
            with ChainStore(paths.chain_path(home)) as store:
                exported = write(store, session, home / "liveness-export.jsonl")
            ex = loads(exported.read_text(encoding="utf-8"))
            report = verify_record(ex.records, [x["receipt"] for x in ex.receipts], service_key=cfg.service_key,
                                   session=session, declared_count=ex.header["count"], declared_head=ex.header["head"])
            ok = report.verdict.state == State.PASS
            detail = report.says if ok else f"{report.says}: {report.verdict.reason}"[:500]
    except Exception as exc:  # noqa: BLE001 -- a probe that fails says so in its status
        detail = f"{type(exc).__name__}: {exc}"[:500]
    status = {
        "v": 1,
        "service": _service(home),
        "last_attempt": at,
        "last_pass": at if ok else previous.get("last_pass"),
        "ok": ok,
        "detail": detail,
    }
    atomic.write_json(status_path(home), status, sort_keys=True)
    return status


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _service(home: Path) -> str | None:
    try:
        return config.load(home).service
    except config.ConfigError:
        return None


def publish(status: dict, *, bucket: str | None, metric_region: str | None, bucket_region: str | None = None,
            client=None) -> list[str]:
    """Send the metric, then the status object, each whatever the other does; return the failures."""
    if client is None:
        import boto3

        client = boto3.client
    failures = []
    if metric_region:
        try:
            client("cloudwatch", region_name=metric_region).put_metric_data(Namespace="Crucible", MetricData=[
                {"MetricName": "LivenessPass", "Value": 1.0 if status["ok"] else 0.0, "Unit": "Count"}])
        except Exception as exc:  # noqa: BLE001
            failures.append(f"the LivenessPass metric: {type(exc).__name__}: {exc}")
    if bucket:
        try:
            client("s3", region_name=bucket_region).put_object(
                Bucket=bucket, Key="status.json", Body=json.dumps(status, sort_keys=True).encode(),
                ContentType="application/json", CacheControl="no-store")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"status.json to {bucket}: {type(exc).__name__}: {exc}")
    return failures


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="crucible-liveness")
    ap.add_argument("--setup", metavar="ADDRESS", help="give the probe a key and register it with the service")
    ap.add_argument("--expect-kms-key", metavar="ARN", help="with --setup: the service key must be this KMS key's")
    ap.add_argument("--status-bucket", help="publish status.json to this bucket (the status page)")
    ap.add_argument("--status-region", help="the status bucket's region")
    ap.add_argument("--metric-region", help="publish the LivenessPass metric in this region")
    args = ap.parse_args(argv)
    home = paths.client_home()
    if args.setup:
        from .cli import Refused

        try:
            expect = kms_public_key(args.expect_kms_key) if args.expect_kms_key else None
            print(f"crucible-liveness: probe key {setup(args.setup, home, expect=expect)}")
        except Exception as exc:  # noqa: BLE001 -- Refused, OSError, ValueError, and the AWS SDK's own errors
            print(f"crucible-liveness: {type(exc).__name__ if not isinstance(exc, Refused) else 'refused'}: {exc}",
                  file=sys.stderr)
            return 2
        return 0
    status = probe(home)
    print(json.dumps(status, sort_keys=True))
    failures = publish(status, bucket=args.status_bucket, metric_region=args.metric_region,
                       bucket_region=args.status_region) if (args.status_bucket or args.metric_region) else []
    for f in failures:
        print(f"crucible-liveness: could not publish {f}", file=sys.stderr)
    return 0 if status["ok"] and not failures else 1


if __name__ == "__main__":
    sys.exit(main())
