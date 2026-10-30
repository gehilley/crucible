"""``crucible-service``: run the service over a journal.

    crucible-service --journal DIR | s3://BUCKET[/PREFIX]
                     --key SERVICE.key.json | --kms-key KEY-ARN
                     --service NAME [--genesis [--genesis-payload FILE]] [--prepare-only]
                     --release-tag TAG --release-digest sha256:...   (or --dev)
                     [--host-facts FILE] [--release-dir DIR --published URL]
                     [--host 127.0.0.1] [--port 8788]

``--genesis`` starts a new log in an empty journal and is refused on one that
already holds a log; without it, an empty journal is refused. A lost cache can
therefore never mint a second genesis over an existing record. With a KMS key,
genesis also binds the key to the new log -- once leaf 0 is known to be
writable and signable, and before it is written -- and opening refuses a key
bound to another. ``--genesis-payload`` names a JSON object added to leaf 0
(the predecessor archive, the independence statement); it cannot replace the
service, log id or key that leaf 0 names. ``--prepare-only`` does everything a
start does (genesis, the release and host entries) and exits without serving:
the deployment's one-off genesis run.

**The service runs only from a release** (docs/v1-audit.md §5 step 9). It
refuses to start when any crucible package it imports is not an installed,
non-editable distribution, and when ``--release-tag`` is not the tag of the
release in ``--release-dir``. It records the release it runs: when the digest
starting up differs from the log's latest ``release`` entry -- a rollback
included -- it appends one; restarting the same digest appends nothing. ``--host-facts`` names a JSON object of platform facts (the
host's OS, kernel, container runtime, TLS terminator); a change appends a
``host`` entry. ``--dev`` is for running a working tree locally: it allows an
editable install and needs no release, and it is refused with an S3 journal.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from importlib import metadata
from pathlib import Path

from crucible_core.keys import KeyError_, PrivateKey

from .journal import DirStore, JournalError
from .log import LogError, ReceiptPending, TransparencyLog
from .service import Service
from .signer import LocalSigner


class Refused(Exception):
    pass


DISTRIBUTIONS = ("crucible-core", "crucible-chain", "crucible-verify", "crucible-service")


def working_tree() -> str | None:
    """Why this process may be importing crucible code from a working tree, or None.

    Each crucible package the service imports must be an installed distribution
    that is not editable (PEP 610 ``direct_url.json``), and its module must be
    the file that distribution installed (not one found on ``PYTHONPATH``)."""
    import importlib

    for name in DISTRIBUTIONS:
        module = importlib.import_module(name.replace("-", "_"))
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            return f"{name} is not an installed distribution; {module.__name__} comes from {module.__file__}"
        try:
            info = json.loads(dist.read_text("direct_url.json") or "{}")
        except ValueError:
            return f"{name}'s direct_url.json cannot be read"
        if not isinstance(info, dict) or info.get("dir_info", {}).get("editable"):
            return f"{name} is an editable install"
        installed = {Path(dist.locate_file(f)).resolve() for f in (dist.files or ())}
        if Path(module.__file__).resolve() not in installed:
            return f"{module.__name__} is imported from {module.__file__}, not from the installed {name}"
    return None


def aws_errors() -> tuple[type[BaseException], ...]:
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return ()
    return (BotoCoreError, ClientError)


def open_store(journal: str):
    if journal.startswith("s3://"):
        from .s3store import S3Store

        bucket, _, prefix = journal.removeprefix("s3://").partition("/")
        store = S3Store(bucket, prefix=prefix + "/" if prefix else "")
        store.check_write_once()
        return store
    return DirStore(Path(journal))


def open_signer(key: Path | None, kms_key: str | None):
    if (key is None) == (kms_key is None):
        raise Refused("give exactly one of --key and --kms-key")
    if kms_key is not None:
        from .kms import KmsSigner

        return KmsSigner(kms_key)  # in the key's own region, which its ARN names
    return LocalSigner(PrivateKey.read(key))


def build(store, signer, service: str, *, genesis: bool, genesis_payload: dict | None = None) -> Service:
    bind = getattr(signer, "bind", None)
    if genesis:
        claim = None if bind is None else (lambda log_id: bind(log_id, genesis=True))
        claimed = signer.bound_to() if bind is not None else None
        log = TransparencyLog.create(store, signer, service=service, genesis_payload=genesis_payload, claim=claim,
                                     claimed=claimed)
    else:
        log = TransparencyLog.open(store, signer)
        if log.service != service:
            raise LogError(f"this journal's log is {log.service!r}, not {service!r}")
        if bind is not None:
            bind(log.log_id, genesis=False)
    return Service(log)


def read_facts(path: Path) -> dict:
    """A JSON object from ``path`` (host facts, or a genesis payload)."""
    try:
        facts = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Refused(f"cannot read {path}: {exc}") from exc
    if not isinstance(facts, dict):
        raise Refused(f"{path} is not a JSON object")
    return facts


TEMPLATE_BLANK = "SHA256_FROM_ARCHIVE_V1"  # the one blank in a deployment's genesis payload template


def check_genesis_payload(payload: dict, store) -> None:
    """Leaf 0 is written once, and genesis binds the key to its log, so refuse a payload that would
    make it say something untrue: the template's blank left in it; a predecessor without its
    archive's bucket, key and digest (``sha256:<64 hex>``, the object's full-object SHA-256), or
    with a digest that is not the one S3 holds for that object; or a retention mode and period the
    journal does not have."""
    if TEMPLATE_BLANK in json.dumps(payload):
        raise Refused(f"the genesis payload still holds the template's blank {TEMPLATE_BLANK}")
    if "predecessor" in payload:
        predecessor = payload["predecessor"]
        archive = predecessor.get("archive") if isinstance(predecessor, dict) else None
        if not (isinstance(archive, dict) and all(isinstance(archive.get(k), str) and archive[k] for k in ("bucket", "key"))
                and isinstance(archive.get("sha256"), str) and re.fullmatch(r"sha256:[0-9a-f]{64}", archive["sha256"])):
            raise Refused("the genesis payload's predecessor wants an archive with bucket, key and sha256 (sha256:<64 hex>, "
                          f"the archive object's full-object SHA-256), not {predecessor!r}")
        where = f"s3://{archive['bucket']}/{archive['key']}"
        digest_of = getattr(store, "object_sha256", None)
        if digest_of is None:
            raise Refused(f"the genesis payload names the archive {where}, whose digest only an S3 journal can check")
        try:
            held = digest_of(archive["bucket"], archive["key"])
        except JournalError as exc:
            raise Refused(f"the genesis payload names the archive {where}, which cannot be read: {exc}") from exc
        if held != archive["sha256"]:
            raise Refused(f"the genesis payload says {where} is {archive['sha256']}, "
                          f"but S3 holds {held or 'no full-object SHA-256'} for it")
    if "journal" in payload:
        journal, stated = payload["journal"], None
        if isinstance(journal, dict) and type(journal.get("default_retention_years")) is int:
            stated = {"Mode": journal.get("object_lock"), "Years": journal["default_retention_years"]}
        held = getattr(store, "default_retention", lambda: None)()
        if stated is None or held != stated:
            raise Refused(f"the genesis payload says the journal's default retention is {stated or journal!r}, "
                          f"but the journal has {held or 'none'}")


def prepare(args) -> Service:
    if args.dev:
        if args.journal.startswith("s3://"):
            raise Refused("--dev runs a working tree locally; it is refused with an S3 journal")
    else:
        if why := working_tree():
            raise Refused(f"{why}; the service runs only from a release (or --dev, locally)")
        if not (args.release_tag and args.release_digest):
            raise Refused("give --release-tag and --release-digest: the service records the release it runs")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.release_digest):
            raise Refused(f"--release-digest {args.release_digest!r} is not an image digest (sha256:<64 hex>)")
        release_dir = getattr(args, "release_dir", None)
        if release_dir is not None:
            tag = read_facts(release_dir / "RELEASE.json").get("tag")
            if tag != args.release_tag:
                raise Refused(f"--release-tag {args.release_tag!r} is not this image's release ({tag!r})")
    payload = None
    if args.genesis_payload is not None:
        if not args.genesis:
            raise Refused("--genesis-payload is only for --genesis")
        payload = read_facts(args.genesis_payload)
    store = open_store(args.journal)
    if payload is not None:
        check_genesis_payload(payload, store)
    service = build(store, open_signer(args.key, args.kms_key), args.service, genesis=args.genesis, genesis_payload=payload)
    sign_missing(service)  # as opened: the checkpoints earlier starts could not sign
    if not args.dev:
        service.record_release(args.release_tag, args.release_digest)
    if args.host_facts is not None:
        service.record_host(read_facts(args.host_facts))
    sign_missing(service)
    return service


def sign_missing(service: Service) -> None:
    """Sign every checkpoint missing above the last one the journal holds (an earlier start's
    ReceiptPending leaves one or more). An unreachable signer does not stop a start: the service
    still serves what is signed, and each missing checkpoint is signed when first asked for."""
    log = service.log
    try:
        for size in range(max(log.vouched, 0) + 1, log.size + 1):
            log.checkpoint(size)
    except JournalError as exc:  # SignerError is one
        print(f"crucible-service: checkpoints above size {log.vouched} are not all signed yet ({exc}); "
              "each is signed when first asked for", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="crucible-service")
    ap.add_argument("--journal", required=True, help="a directory, or s3://bucket[/prefix]")
    ap.add_argument("--key", type=Path, help="the service's private key file (tests and local runs)")
    ap.add_argument("--kms-key", help="the service's KMS signing key (production)")
    ap.add_argument("--service", required=True, help="the name the record carries, e.g. log.cruciblehub.org")
    ap.add_argument("--genesis", action="store_true", help="start a new log in an empty journal")
    ap.add_argument("--genesis-payload", type=Path, help="a JSON object for leaf 0, with --genesis")
    ap.add_argument("--prepare-only", action="store_true", help="start (genesis, release and host entries), then exit")
    ap.add_argument("--release-tag")
    ap.add_argument("--release-digest")
    ap.add_argument("--host-facts", type=Path)
    ap.add_argument("--dev", action="store_true", help="run a working tree locally: editable allowed, no release")
    ap.add_argument("--liveness-status", type=Path, help="the liveness probe's status.json; health follows it")
    ap.add_argument("--liveness-interval", type=float, default=3600.0, help="seconds a pass stays fresh")
    ap.add_argument("--release-dir", type=Path, help="serve this release's README and client wheels (the image's /release)")
    ap.add_argument("--published", help="with --release-dir: where the service key and log id are published apart from "
                                        "this machine (e.g. https://status.cruciblehub.org)")
    ap.add_argument("--trusted-proxy", action="append", default=[], metavar="CIDR",
                    help="a proxy whose X-Forwarded-For names the client, for the rate limits (Caddy's bridge)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8788)
    args = ap.parse_args(argv)
    from .api import Liveness, Release, create_app
    from .limits import Limits

    if args.release_dir is not None and not args.published:
        print("crucible-service: --release-dir needs --published: the README tells strangers where the key is "
              "published apart from this machine", file=sys.stderr)
        return 2
    try:
        served = Release(args.release_dir, published=args.published) if args.release_dir else None
    except (OSError, ValueError, KeyError) as exc:
        print(f"crucible-service: cannot serve the release at {args.release_dir}: {exc}", file=sys.stderr)
        return 2
    try:
        service = prepare(args)
    except ReceiptPending as exc:
        print(f"crucible-service: {exc.detail}. The entry is in the journal; the service's next start signs "
              "its checkpoint (do not run genesis again)", file=sys.stderr)
        return 2
    except (Refused, LogError, JournalError, KeyError_, ValueError, *aws_errors()) as exc:
        print(f"crucible-service: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if args.prepare_only:
        log = service.log
        print(json.dumps({"service": log.service, "log_id": log.log_id, "key_id": log.signer.key_id, "tree_size": log.size}))
        return 0
    import uvicorn

    gate = Liveness(args.liveness_status, args.liveness_interval) if args.liveness_status else None
    try:
        limits = Limits(trusted_proxies=tuple(args.trusted_proxy))
    except ValueError as exc:
        print(f"crucible-service: --trusted-proxy: {exc}", file=sys.stderr)
        return 2
    uvicorn.run(create_app(service, liveness=gate, release=served, limits=limits), host=args.host, port=args.port,
                log_level="info", proxy_headers=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
