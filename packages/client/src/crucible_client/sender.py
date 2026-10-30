"""The background sender: drain the local chain to the service, retry, keep receipts
(SPEC.md §3 Sending; docs/v1-audit.md §5 step 7).

The queue is the chain store itself: a session's unsent events are the ones no
held receipt covers. For each such session the sender ships the next batch of
consecutive events, signed by the researcher's key, and stores the receipt the
service returns. A receipt is stored only after it checks, against the service
key pinned at install, as anchoring the batch's own last head
(`crucible_verify.receipts`): the store treats a held receipt as "sent", so a
receipt that anchored nothing would empty the queue of events nobody holds.

**A lost receipt is recovered, not resent differently.** Before a batch is
posted its span is written down (``<home>/sending.json``). If the answer never
arrives, the next attempt -- in this process or the next one -- sends that same
span again; Ed25519 is deterministic, so the bytes are identical and the
service returns the original receipt. A span that was answered with a refusal
is forgotten.

**What is retried.** No answer, a 5xx, and a 503 (after its ``Retry-After``) are
retried with backoff (no answer on a session's recovery read is that session's
own failure, retried on its own clock); ``unregistered_key`` registers the key and retries; a
413 halves the batch. A refusal that sending again cannot change (another key's
session, a chain the service will not accept) stops that session and is
written to the local log; the other sessions keep draining. A session that
raises something unexpected is tried again after ``SURPRISE_RETRY``, on its
own: it does not set the backoff of the sessions that are fine. When the
service holds more of a session than our receipts say, its export is read for
the receipts -- after every other session has had its turn in that drain, so a
slow read holds up no other session's send in it (the next drain still waits
for it, as one sender drains a home at a time).

    crucible-send            # run until stopped (the installed user service)
    crucible-send --once     # drain what is queued now, then exit
"""

from __future__ import annotations

import argparse
import fcntl
import http.client
import json
import math
import os
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from crucible_chain import wire
from crucible_chain.chain import GENESIS
from crucible_chain.export import ExportError, loads
from crucible_chain.store import ChainStore, StoreError
from crucible_core import atomic
from crucible_verify.receipts import check_receipt
from crucible_verify.results import State

from . import paths
from .config import Config, ConfigError, load

MAX_EVENTS = 500
MIN_DELAY = 1.0
STUCK_RETRY = 600.0  # a refused session is tried again after this long, never given up on
MAX_BODY = 2 * 1024 * 1024 - 4096  # the service's limit, less room for the JSON around the batch
IDLE = 2.0
BACKOFF = (1.0, 2.0, 5.0, 10.0, 30.0, 60.0)
TIMEOUT = 30
RECOVER_TIMEOUT = 300  # a long session's export is read whole
SURPRISE_RETRY = 60.0  # a session that raised something unexpected waits this long, alone

#: (status, headers, json body or None); raises OSError when there is no answer.
Transport = Callable[[str, dict], tuple[int, dict, dict | None]]


def http_post(url: str, body: dict) -> tuple[int, dict, dict | None]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            status, headers, raw = resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        status, headers = exc.code, dict(exc.headers or {})
        try:
            raw = exc.read()
        except (http.client.HTTPException, OSError):  # an error answer cut short: its status still stands
            raw = b""
    except http.client.HTTPException as exc:  # an answer cut short, or not HTTP: no answer
        raise ConnectionError(f"{type(exc).__name__}: {exc}") from exc
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = None
    return status, {k.lower(): v for k, v in headers.items()}, parsed if isinstance(parsed, dict) else None


def http_get(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=RECOVER_TIMEOUT) as resp:
            return resp.read()
    except http.client.HTTPException as exc:
        raise ConnectionError(f"{type(exc).__name__}: {exc}") from exc


class _Recover(Exception):
    """The service holds more of this session than our receipts say (``position_held``,
    ``chain_break``): its export is read for the receipts, after the other sessions."""

    def __init__(self, code: str, span: tuple[int, int], body: dict | None) -> None:
        super().__init__(code)
        self.code, self.span, self.body = code, span, body or {}


class Unanswered(Exception):
    """A read for one session got no answer: that session is tried again after ``SURPRISE_RETRY``,
    on its own, so a read that never finishes slows no other session."""


class Retry(Exception):
    """Try again later; ``after`` seconds if the service said so."""

    def __init__(self, reason: str, after: float | None = None) -> None:
        super().__init__(reason)
        self.after = after


class Stuck(Exception):
    """Sending again cannot change the answer for this session."""


@dataclass
class Outcome:
    sent: dict[str, int] = field(default_factory=dict)  # session -> events newly receipted
    stuck: dict[str, str] = field(default_factory=dict)
    retry_after: float | None = None
    retried: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)  # session -> the unexpected error it raised


class Sender:
    def __init__(self, config: Config, *, post: Transport = http_post, get: Callable[[str], bytes] | None = None) -> None:
        self.config = config
        self.post = post
        self.get = get or http_get
        self.stuck: dict[str, tuple[str, float]] = {}  # session -> (why, when to try again)
        self._failing: dict[str, tuple[str, int]] = {}  # session -> (its unexpected error, how many times in a row)

    # --- the span being sent, kept across processes --------------------------------
    def _sending_path(self) -> Path:
        return self.config.home / "sending.json"

    def _pending(self) -> dict:
        try:
            data = json.loads(self._sending_path().read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _remember(self, session: str, span: tuple[int, int] | None) -> None:
        pending = self._pending()
        if span is None:
            pending.pop(session, None)
        else:
            pending[session] = list(span)
        atomic.write_json(self._sending_path(), pending, sort_keys=True, mode=0o600)

    # --- one drain -------------------------------------------------------------------------
    def drain(self, *, until: dict[str, int] | None = None, wait: bool = True) -> Outcome:
        """Send everything queued now (up to ``until``'s seq per session, if given).

        One sender drains a home at a time: the drain holds ``<home>/sender.lock``.
        With ``wait`` false, a drain another sender holds is skipped, not waited for.
        Raises nothing for a session that fails; says so.
        """
        out = Outcome()
        with _locked(self.config.home / "sender.lock", wait=wait) as held:
            if not held:
                out.retried.append("another sender is draining this home")
                return out
            with ChainStore(paths.chain_path(self.config.home)) as store:
                deferred: list[tuple[str, _Recover]] = []
                for session in store.sessions():
                    why, when = self.stuck.get(session, ("", 0.0))
                    if when > time.monotonic():
                        continue
                    self.stuck.pop(session, None)
                    bound = None if until is None else until.get(session, -1)
                    self._attempt(out, session, lambda: self._drain_session(store, session, bound), deferred)
                for session, refused in deferred:  # last: a recovery reads a whole export
                    self._attempt(out, session, lambda: self._settle(store, session, refused), None)
        return out

    def _attempt(self, out: Outcome, session: str, step: Callable[[], int], deferred: list | None) -> None:
        """Run one session's ``step``, and say in ``out`` how it went."""
        try:
            if n := step():
                out.sent[session] = out.sent.get(session, 0) + n
            self._failing.pop(session, None)
        except _Recover as exc:
            assert deferred is not None
            deferred.append((session, exc))
        except Retry as exc:
            self._failing.pop(session, None)
            out.retried.append(f"{session}: {exc}")
            if exc.after is not None:
                out.retry_after = max(out.retry_after or 0, exc.after)
        except Stuck as exc:
            self._failing.pop(session, None)
            self.stuck[session] = (str(exc), time.monotonic() + STUCK_RETRY)
            out.stuck[session] = str(exc)
            self._log({"session": session, "stuck": str(exc), "retry_in": STUCK_RETRY})
        except Exception as exc:  # noqa: BLE001 -- one session's surprise does not stop or slow the others
            why = f"{type(exc).__name__}: {exc}"
            self.stuck[session] = (why, time.monotonic() + SURPRISE_RETRY)
            out.failed[session] = why
            seen, times = self._failing.get(session, ("", 0))
            times = times + 1 if seen == why else 1
            self._failing[session] = (why, times)
            hourly = max(1, round(3600 / SURPRISE_RETRY)) if SURPRISE_RETRY > 0 else 60
            if times == 1 or times % hourly == 0:  # the first time, then about hourly: the log is not flooded
                self._log({"session": session, "failed": why, "retry_in": SURPRISE_RETRY, "times": times})

    def _settle(self, store: ChainStore, session: str, refused: _Recover) -> int:
        """After ``position_held``/``chain_break``: keep the service's own receipts, or stop the session."""
        self._remember(session, None)
        if self._recover(store, session) > 0:
            raise Retry(f"recovered the service's receipts for {session} after {refused.code}")
        span = refused.span
        raise Stuck(f"the service refuses events {span[0]}..{span[1]} ({refused.code}, next expected "
                    f"{refused.body.get('next_expected_seq')}): {refused.body.get('detail', '')}")

    def _drain_session(self, store: ChainStore, session: str, until: int | None) -> int:
        sent = 0
        while True:
            queued = store.unsent(session, MAX_EVENTS)
            if until is not None:
                queued = [r for r in queued if r.seq <= until]
            if not queued:
                return sent
            first = queued[0].seq
            span = self._pending().get(session)
            if span and span[0] == first and span[1] <= queued[-1].seq:
                count = span[1] - first + 1  # the span whose answer was lost: the same bytes again
            elif span and span[0] == first and span[1] - first < MAX_EVENTS:
                queued = store.records(session, first, span[1] - first + 1)
                count = len(queued)
            else:
                count = len(queued)
            sent += self._send(store, session, [r.as_record() for r in queued[:count]])

    def _send(self, store: ChainStore, session: str, records: list[dict]) -> int:
        first = records[0]["seq"]
        prev = GENESIS if first == 0 else store.record(session, first - 1).head
        batch = wire.batch(self.config.key, records, prev_head=prev)
        if len(batch) > MAX_BODY and len(records) > 1:
            return self._send(store, session, records[: len(records) // 2])
        span = (first, records[-1]["seq"])
        self._remember(session, span)
        try:
            status, headers, body = self.post(f"{self.config.service}/v2/batches", {"batch": batch})
        except OSError as exc:
            raise Retry(f"no answer from {self.config.service}: {exc}") from exc
        code = (body or {}).get("error")
        detail = (body or {}).get("detail", "")
        if status == 200:
            receipt = (body or {}).get("receipt")
            if not isinstance(receipt, dict):
                raise Retry(f"the service answered 200 for events {span[0]}..{span[1]} without a receipt")  # span kept
            heads = {r["seq"]: r["head"] for r in records}
            check = check_receipt(receipt, session=session, heads=heads, service_key=self.config.service_key)
            if check.check.state != State.PASS or (check.from_seq, check.to_seq) != span:
                raise Retry(f"the service's receipt for events {span[0]}..{span[1]} does not check: {check.check.reason}")
            try:
                store.add_receipt(session, span[1], receipt)
            except StoreError as exc:
                raise Stuck(f"the receipt for events {span[0]}..{span[1]} cannot be kept: {exc}") from exc
            self._remember(session, None)
            return len(records)
        if status >= 500 or status in (408, 429):
            raise Retry(f"the service is unavailable ({status} {code}): {detail}", _retry_after(headers))
        if status == 413 and len(records) > 1:
            self._remember(session, None)
            return self._send(store, session, records[: len(records) // 2])
        if status == 403 and code == "unregistered_key":
            self.register()
            raise Retry("the key was not registered; registered it")
        if status == 409 and code in ("position_held", "chain_break"):
            # The service holds more of this session than our receipts say: an answer
            # was lost, perhaps by another sender. Its own export carries the receipts.
            raise _Recover(code, span, body)
        if code is None:  # not an answer from the service: nothing says the batch was refused
            raise Retry(f"an answer for events {span[0]}..{span[1]} that is not the service's ({status})")
        self._remember(session, None)
        raise Stuck(f"the service refuses events {span[0]}..{span[1]} ({status} {code}): {detail}")

    def _recover(self, store: ChainStore, session: str) -> int:
        """Keep the service's receipts for ``session`` that check against our own heads,
        in order, from where our receipts stop. Returns how many were kept."""
        try:
            ex = loads(self.get(f"{self.config.service}/v2/sessions/{session}/export").decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code >= 500 or exc.code in (408, 429):  # busy or limited: ask again, do not give up on it
                headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
                raise Retry(f"the service could not give {session}'s export yet ({exc.code})", _retry_after(headers)) from exc
            return 0
        except OSError as exc:  # no answer: this session tries again on its own clock; nothing was refused
            raise Unanswered(f"no answer for {session}'s export from {self.config.service}: {exc}") from exc
        except (ExportError, UnicodeDecodeError, ValueError):
            return 0
        kept = 0
        head = store.head(session)
        top = head.seq if head else -1
        lines = sorted((x for x in ex.receipts if x["to_seq"] <= top), key=lambda line: line["to_seq"])  # none past what we hold
        for line in lines:
            last = store.last_receipted_seq(session)
            if line["to_seq"] <= last:
                continue
            records = store.records(session, last + 1, line["to_seq"] - last)
            heads = {r.seq: r.head for r in records}
            check = check_receipt(line["receipt"], session=session, heads=heads, service_key=self.config.service_key)
            if check.check.state != State.PASS or check.from_seq != last + 1:
                break
            try:
                store.add_receipt(session, line["to_seq"], line["receipt"])
            except StoreError:
                break
            kept += 1
        return kept

    def register(self) -> dict:
        try:
            status, headers, body = self.post(f"{self.config.service}/v2/keys", {"registration": wire.registration(self.config.key)})
        except OSError as exc:
            raise Retry(f"no answer from {self.config.service}: {exc}") from exc
        if status == 200 and isinstance((body or {}).get("receipt"), dict):
            return body["receipt"]
        if status >= 500 or status in (408, 429) or (body or {}).get("error") is None:
            raise Retry(f"the service is unavailable ({status})", _retry_after(headers))
        raise Stuck(f"the service refuses the key registration ({status}): {(body or {}).get('detail', '')}")

    def _log(self, entry: dict) -> None:
        path = self.config.home / "sender.jsonl"
        line = (json.dumps({"at": time.time_ns() // 1000, **entry}, sort_keys=True) + "\n").encode()
        try:
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        except OSError:
            return
        try:
            os.write(fd, line)
        finally:
            os.close(fd)

    # --- running ------------------------------------------------------------------------------
    def run(self, *, stop: Callable[[], bool] = lambda: False, sleep: Callable[[float], None] = time.sleep) -> None:
        """Drain, wait, repeat, until ``stop()``; back off while the service does not answer.

        Holds ``<home>/sender.run.lock`` for as long as it runs, so an install can tell
        a running sender from a stale pid."""
        failures = 0
        # A moment's patience: an install checking whether a sender runs holds the lock for an instant.
        with _locked(self.config.home / "sender.run.lock", wait=False, patience=1.0) as running:
            if not running:
                raise SystemExit("crucible-send: another sender is already running for this home")
            while not stop():
                try:
                    out = self.drain()
                except Exception as exc:  # noqa: BLE001 -- a sender that dies drains nothing
                    out = Outcome(retried=[f"{type(exc).__name__}: {exc}"])
                if out.retried:
                    delay = max(out.retry_after if out.retry_after is not None else BACKOFF[min(failures, len(BACKOFF) - 1)], MIN_DELAY)
                    failures += 1
                    if failures <= 3 or failures % 20 == 0:  # the log says it is retrying, not every time
                        self._log({"retry_in": delay, "why": out.retried[:3], "failures": failures})
                else:
                    failures, delay = 0, IDLE
                sleep(delay)


@contextmanager
def _locked(path: Path, *, wait: bool, patience: float = 0.0):
    """An exclusive flock on ``path``; yields whether it was taken (trying for ``patience``
    seconds when not waiting)."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + patience
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    yield False
                    return
                time.sleep(0.02)
        try:
            yield True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def sender_running(home: Path) -> bool:
    """Whether a `Sender.run` holds this home's run lock."""
    path = home / "sender.run.lock"
    if not path.exists():
        return False
    with _locked(path, wait=False) as free:
        return not free


def _retry_after(headers: dict) -> float | None:
    value = headers.get("retry-after")
    try:
        after = float(value) if value is not None else None
    except ValueError:
        return None
    if after is None or not math.isfinite(after):
        return None
    return max(MIN_DELAY, min(after, 3600.0))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="crucible-send", description="Send the local chain to the service.")
    ap.add_argument("--once", action="store_true", help="drain what is queued now, then exit")
    args = ap.parse_args(argv)
    try:
        sender = Sender(load())
    except ConfigError as exc:
        print(f"crucible-send: {exc}", file=sys.stderr)
        return 2
    if args.once:
        with ChainStore(paths.chain_path(sender.config.home)) as store:  # what is queued now, not what arrives meanwhile
            until = {s: (h.seq if (h := store.head(s)) else -1) for s in store.sessions()}
        out = sender.drain(until=until)
        for s, n in sorted(out.sent.items()):
            print(f"{s}: {n} events receipted")
        for line in out.retried + [f"{s}: {why}" for s, why in {**out.stuck, **out.failed}.items()]:
            print(f"crucible-send: {line}", file=sys.stderr)
        return 0 if not (out.retried or out.stuck or out.failed) else 1
    try:
        sender.run()
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
