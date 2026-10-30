"""``crucible-verify``: verify an exported record (SPEC.md §7).

    crucible-verify RECORD [--service-key SERVICE.pub.json ...] [--json]

RECORD is an exported session (crucible-chain/2 JSON lines): a file, or an
``http(s)://`` URL such as a service's ``/v2/sessions/<id>/export``. The service
public key is given out of band, and may be given more than once (a service
whose key changed); this command never fetches a key from the service whose
receipts it is checking. Exit status names the verdict (0 intact, 1 broken,
2 could_not_check, 3 not_applicable); anything else is not a verdict (4 the
record or a key could not be read, 5 this program failed, 64 usage). The report
is the evidence: a status code is not a record.
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from crucible_chain.export import ExportError, loads, read
from crucible_core.keys import KeyError_, PublicKey

from .report import verify_record
from .results import State

EXIT = {State.PASS: 0, State.FAIL: 1, State.COULD_NOT_CHECK: 2, State.NOT_APPLICABLE: 3}
UNREADABLE, FAILED, USAGE = 4, 5, 64
MAX_FETCH = 256 * 1024 * 1024


def _seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number of seconds") from None
    if not (0 < value <= 3600):  # also refuses nan and inf
        raise argparse.ArgumentTypeError("a timeout is more than 0 and at most 3600 seconds")
    return value


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # usage errors must not look like a verdict
        self.print_usage(sys.stderr)
        print(f"{self.prog}: {message}", file=sys.stderr)
        sys.exit(USAGE)


def _read(record: str, timeout: float):
    if record.startswith(("http://", "https://")):
        with urllib.request.urlopen(record, timeout=timeout) as resp:
            declared = resp.headers.get("content-length")
            body = resp.read(MAX_FETCH + 1)
        if len(body) > MAX_FETCH:
            raise ExportError(f"the export is larger than {MAX_FETCH} bytes")
        # A connection that drops early ends the body without an error; a cut
        # record must not be verified as if it were the whole one.
        if declared is not None and (not declared.isdigit() or int(declared) != len(body)):
            raise ExportError(f"the export arrived as {len(body)} of {declared} bytes")
        try:
            return loads(body.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise ExportError(f"the export is not UTF-8: {exc}") from exc
    return read(Path(record))


def run(argv: list[str] | None = None) -> int:
    ap = _Parser(prog="crucible-verify", description=__doc__.split("\n\n")[0])
    ap.add_argument("record", help="an exported session: a file, or an http(s) URL")
    ap.add_argument("--service-key", type=Path, action="append", default=[], help="a service public key file (repeatable)")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--timeout", type=_seconds, default=300.0, help="seconds to wait for a record fetched by URL")
    args = ap.parse_args(argv)
    try:
        ex = _read(args.record, args.timeout)
    except (OSError, ExportError, urllib.error.URLError, http.client.HTTPException, ValueError, RecursionError) as exc:
        print(f"crucible-verify: cannot read {args.record}: {exc}", file=sys.stderr)
        return UNREADABLE
    keys = []
    for path in args.service_key:
        try:
            key = PublicKey.read(path)
        except (KeyError_, OSError, ValueError, RecursionError) as exc:
            print(f"crucible-verify: cannot read the service key {path}: {exc}", file=sys.stderr)
            return UNREADABLE
        if key.role != "service":
            print(f"crucible-verify: {path} is a {key.role} key, not a service key", file=sys.stderr)
            return UNREADABLE
        keys.append(key)
    report = verify_record(
        ex.records,
        [r["receipt"] for r in ex.receipts],
        service_key=keys or None,
        session=ex.header.get("session"),
        declared_count=ex.header.get("count"),
        declared_head=ex.header.get("head"),
    )
    if args.json:
        print(json.dumps(report.to_json(), indent=2, sort_keys=True))
    else:
        sys.stdout.write(report.render())
    return EXIT[report.verdict.state]


def main(argv: list[str] | None = None) -> int:
    try:
        return run(argv)
    except SystemExit:
        raise
    except Exception as exc:  # a crash is not a verdict
        print(f"crucible-verify: internal error, no verdict: {type(exc).__name__}: {exc}", file=sys.stderr)
        return FAILED


if __name__ == "__main__":
    sys.exit(main())
