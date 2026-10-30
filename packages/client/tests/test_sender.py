"""The sender drains the local chain to a real service, retries, and keeps
every receipt (docs/v1-audit.md §5 step 7). Runs against the root conftest's
``ephemeral_service``: real uvicorn on a real socket, restartable."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from crucible_chain.events import draft
from crucible_chain.export import loads, write
from crucible_chain.store import ChainStore
from crucible_client import config, paths
from crucible_client.sender import Retry, Sender, http_post
from crucible_core.keys import PrivateKey
from crucible_verify.report import verify_record
from crucible_verify.results import State

SESSION = "5a1c3e2b-0000-4000-8000-0000000000aa"


@pytest.fixture
def home(tmp_path, ephemeral_service, researcher_key, service_key):
    h = tmp_path / "client"
    h.mkdir()
    researcher_key.write(config.key_path(h))
    config.save(h, ephemeral_service.url, service_key.public())
    from crucible_chain import wire

    status, _h, _b = http_post(ephemeral_service.url + "/v2/keys", {"registration": wire.registration(researcher_key)})
    assert status == 200  # as install does
    return h


@pytest.fixture
def other_researcher():
    return PrivateKey.generate("researcher", label="someone else")


def queue(home, n, session=SESSION, start=0):
    with ChainStore(paths.chain_path(home)) as store:
        for i in range(start, start + n):
            store.append(session, draft("tool.result", "tool:Bash", "witnessed", {"i": i}, content={"out": i}))


def held(home, session=SESSION):
    with ChainStore(paths.chain_path(home)) as store:
        return store.last_receipted_seq(session), [r.as_record() for r in store.records(session)], store.receipts(session)


def intact_locally(home, service_key, session=SESSION) -> bool:
    with ChainStore(paths.chain_path(home)) as store:
        path = write(store, session, home / "export.jsonl")
    ex = loads(path.read_text())
    r = verify_record(ex.records, [x["receipt"] for x in ex.receipts], service_key=service_key.public(), session=session,
                      declared_count=ex.header["count"], declared_head=ex.header["head"])
    return r.verdict.state == State.PASS, r.verdict.reason


def test_the_queue_drains_and_every_receipt_is_held_and_verifies(home, service_key):
    queue(home, 7)
    out = Sender(config.load(home)).drain()
    assert out.sent == {SESSION: 7} and not out.retried and not out.stuck
    last, records, receipts = held(home)
    assert last == 6 and len(receipts) == 1
    assert intact_locally(home, service_key) == (True, "7 events replay intact and every one is anchored")


def test_stop_the_service_restart_it_and_the_queue_drains_with_every_receipt_held(home, ephemeral_service, service_key):
    s = Sender(config.load(home))
    queue(home, 3)
    assert s.drain().sent == {SESSION: 3}
    ephemeral_service.stop()
    queue(home, 4, start=3)
    out = s.drain()
    assert out.sent == {} and out.retried and not out.stuck  # no answer: retried, not refused
    queue(home, 2, start=7)
    ephemeral_service.start()  # same port, rebuilt from its journal
    assert s.drain().sent == {SESSION: 6}
    last, _records, receipts = held(home)
    assert last == 8 and [to for to, _ in receipts] == [2, 6, 8]  # the span that got no answer goes again as it was
    assert intact_locally(home, service_key)[0]
    status, body = _get(ephemeral_service.url, f"/v2/sessions/{SESSION}/verify")
    assert body["verdict"]["says"] == "intact"


def _get(url, path):
    import urllib.request

    with urllib.request.urlopen(url + path, timeout=30) as resp:
        return resp.status, json.loads(resp.read())


def test_a_503_with_retry_after_is_retried_after_that_long_not_refused(home):
    calls = []

    def flaky(url, body):
        calls.append(url)
        if len(calls) == 1:
            return 503, {"retry-after": "7"}, {"error": "journal_unavailable", "detail": "no receipt was issued"}
        return http_post(url, body)

    queue(home, 2)
    s = Sender(config.load(home), post=flaky)
    slept = []
    s.run(stop=lambda: len(slept) >= 2, sleep=slept.append)
    assert slept[0] == 7.0
    assert held(home)[0] == 1 and not s.stuck


def test_an_answer_lost_in_transit_is_recovered_by_sending_the_same_bytes(home, ephemeral_service):
    sent = []

    def lossy(url, body):
        sent.append(body.get("batch"))
        answer = http_post(url, body)
        if len(sent) == 1:
            raise ConnectionResetError("the answer never arrived")  # but the service did append it
        return answer

    queue(home, 3)
    s = Sender(config.load(home), post=lossy)
    assert s.drain().retried
    queue(home, 2, start=3)  # more events arrive before the retry
    out = s.drain()
    assert out.sent == {SESSION: 5} and not out.stuck
    assert sent[1] == sent[0]  # the lost span went again, byte for byte
    last, _r, receipts = held(home)
    assert last == 4 and [to for to, _ in receipts] == [2, 4]
    assert ephemeral_service.service.log.size == 1 + 1 + 2  # genesis, registration, two batches: nothing twice


def test_a_lost_answer_is_recovered_by_the_next_process_too(home):
    def dies(url, body):
        http_post(url, body)
        raise TimeoutError("the process was killed while waiting")

    queue(home, 3)
    assert Sender(config.load(home), post=dies).drain().retried
    queue(home, 1, start=3)
    out = Sender(config.load(home)).drain()  # a fresh process
    assert out.sent == {SESSION: 4} and not out.stuck


def test_a_receipt_that_does_not_check_against_the_pinned_key_is_not_kept(home):
    config.save(home, config.load(home).service, PrivateKey.generate("service").public())
    queue(home, 2)
    out = Sender(config.load(home)).drain()
    assert out.retried and "does not check" in out.retried[0]
    assert held(home)[0] == -1  # still queued


def test_an_unregistered_key_is_registered_and_the_queue_then_drains(home):
    config.key_path(home).unlink()
    PrivateKey.generate("researcher").write(config.key_path(home))  # a key the service has never seen
    queue(home, 2)
    out = Sender(config.load(home)).drain()
    assert out.retried and "registered it" in out.retried[0]
    assert Sender(config.load(home)).drain().sent == {SESSION: 2}


def test_a_long_queue_goes_in_several_batches(home, monkeypatch):
    import crucible_client.sender as sender

    monkeypatch.setattr(sender, "MAX_EVENTS", 4)
    queue(home, 10)
    assert Sender(config.load(home)).drain().sent == {SESSION: 10}
    assert [to for to, _ in held(home)[2]] == [3, 7, 9]


def test_a_batch_over_the_body_limit_is_halved(home, monkeypatch):
    import crucible_client.sender as sender

    monkeypatch.setattr(sender, "MAX_BODY", 3000)
    queue(home, 8)
    assert Sender(config.load(home)).drain().sent == {SESSION: 8}
    assert len(held(home)[2]) > 1


def test_a_session_another_key_owns_is_stuck_and_the_others_still_drain(home, ephemeral_service, other_researcher):
    from crucible_chain import wire

    with ChainStore(paths.chain_path(home)) as store:
        store.append("taken-0001", draft("prompt", "human", "witnessed", {}, content="x"))
        squat = [r.as_record() for r in store.records("taken-0001")]
    http_post(ephemeral_service.url + "/v2/keys", {"registration": wire.registration(other_researcher)})
    assert http_post(ephemeral_service.url + "/v2/batches", {"batch": wire.batch(other_researcher, squat)})[0] == 200
    queue(home, 2)
    s = Sender(config.load(home))
    out = s.drain()
    assert "taken-0001" in out.stuck and "session_owner" in out.stuck["taken-0001"]
    assert out.sent == {SESSION: 2}
    assert "taken-0001" in (home / "sender.jsonl").read_text()


def test_the_send_command_without_a_configuration_refuses(tmp_path):
    r = subprocess.run([sys.executable, "-m", "crucible_client.sender", "--once"], capture_output=True, text=True,
                       env={**os.environ, "CRUCIBLE_HOME": str(tmp_path / "nothing")}, timeout=60)
    assert r.returncode == 2 and "crucible install" in r.stderr


def test_the_send_command_drains_once(home):
    queue(home, 3)
    r = subprocess.run([sys.executable, "-m", "crucible_client.sender", "--once"], capture_output=True, text=True,
                       env={**os.environ, "CRUCIBLE_HOME": str(home)}, timeout=60)
    assert r.returncode == 0 and f"{SESSION}: 3 events receipted" in r.stdout


# --- from the fresh review of steps 7-8 ----------------------------------------------------------


def test_a_lost_answer_whose_span_was_also_lost_is_recovered_from_the_services_export(home, ephemeral_service):
    def lossy(url, body):
        http_post(url, body)
        raise ConnectionResetError("the answer never arrived")

    queue(home, 3)
    Sender(config.load(home), post=lossy).drain()  # the service holds 0..2; we hold no receipt
    (home / "sending.json").unlink()  # and the record of the span is gone too (another sender, a crash)
    queue(home, 4, start=3)
    s = Sender(config.load(home))
    first = s.drain()  # sends 0..6, is told position_held, takes the service's receipt for 0..2
    assert first.retried and "recovered" in first.retried[0] and not first.stuck
    assert s.drain().sent == {SESSION: 4}
    last, _r, receipts = held(home)
    assert last == 6 and [to for to, _ in receipts] == [2, 6]


def test_a_200_without_a_receipt_keeps_the_span_and_gets_the_original_receipt(home):
    calls = []

    def blank(url, body):
        calls.append(body.get("batch"))
        status, headers, answer = http_post(url, body)
        return (status, headers, None) if len(calls) == 1 else (status, headers, answer)

    queue(home, 3)
    s = Sender(config.load(home), post=blank)
    assert s.drain().retried and not s.stuck
    assert s.drain().sent == {SESSION: 3} and calls[0] == calls[1]


def test_rate_limits_are_retried_not_refused(home):
    calls = []

    def limited(url, body):
        calls.append(url)
        if len(calls) == 1:
            return 429, {"retry-after": "3"}, {"error": "rate_limited", "detail": "slow down"}
        return http_post(url, body)

    queue(home, 2)
    s = Sender(config.load(home), post=limited)
    out = s.drain()
    assert out.retried and out.retry_after == 3.0 and not s.stuck
    assert s.drain().sent == {SESSION: 2}


@pytest.mark.parametrize("value", ["0", "-5", "nan", "inf"])
def test_a_retry_after_that_is_not_a_wait_still_waits(home, value):
    from crucible_client.sender import MIN_DELAY

    def busy(url, body):
        return 503, {"retry-after": value}, {"error": "journal_unavailable", "detail": ""}

    queue(home, 1)
    slept = []
    Sender(config.load(home), post=busy).run(stop=lambda: len(slept) >= 3, sleep=slept.append)
    assert all(d >= MIN_DELAY for d in slept)


def test_an_answer_cut_short_is_retried_and_the_sender_survives(home):
    import http.client

    import crucible_client.sender as sender_module

    def cut(url, body):
        raise ConnectionError(f"IncompleteRead: {http.client.IncompleteRead(b'abc', 10)}")

    queue(home, 1)
    assert Sender(config.load(home), post=cut).drain().retried

    calls = []

    def explodes():
        calls.append(1)
        raise RuntimeError("something unexpected")

    s = Sender(config.load(home))
    s.drain = explodes
    slept = []
    s.run(stop=lambda: len(slept) >= 2, sleep=slept.append)
    assert len(calls) == 2  # it kept going


def test_two_drains_of_one_home_do_not_overlap(home):
    from crucible_client.sender import _locked

    queue(home, 1)
    with _locked(home / "sender.lock", wait=False) as taken:
        assert taken
        out = Sender(config.load(home)).drain(wait=False)
    assert out.retried == ["another sender is draining this home"] and held(home)[0] == -1


def test_a_running_sender_is_visible_through_its_run_lock(home):
    import threading

    from crucible_client.sender import sender_running

    assert not sender_running(home)
    started, done = threading.Event(), threading.Event()
    s = Sender(config.load(home))
    t = threading.Thread(target=s.run, kwargs={"stop": done.is_set, "sleep": lambda _d: (started.set(), done.wait(5))})
    t.start()
    assert started.wait(10)
    assert sender_running(home)
    with pytest.raises(SystemExit):
        Sender(config.load(home)).run(stop=lambda: True)
    done.set()
    t.join(10)
    assert not sender_running(home)


def test_a_stuck_session_is_tried_again_later(home, monkeypatch, ephemeral_service):
    import crucible_client.sender as sender_module

    monkeypatch.setattr(sender_module, "STUCK_RETRY", 0.0)
    answers = []

    def refuses_once(url, body):
        answers.append(url)
        if len(answers) == 1:
            return 403, {}, {"error": "session_owner", "detail": "not yours"}
        return http_post(url, body)

    queue(home, 2)
    s = Sender(config.load(home), post=refuses_once)
    assert SESSION in s.drain().stuck
    assert s.drain().sent == {SESSION: 2}


def test_send_once_drains_what_was_queued_when_it_started(home):
    queue(home, 2)
    with ChainStore(paths.chain_path(home)) as store:
        until = {SESSION: store.head(SESSION).seq}
    queue(home, 3, start=2)  # arrives after the snapshot
    out = Sender(config.load(home)).drain(until=until)
    assert out.sent == {SESSION: 2} and held(home)[0] == 1


def test_an_export_line_past_what_we_hold_cannot_stop_the_drain(home, ephemeral_service):
    from crucible_chain.export import dumps

    def lossy(url, body):
        http_post(url, body)
        raise ConnectionResetError("lost")

    queue(home, 2, session="aaaa-0001")
    Sender(config.load(home), post=lossy).drain()
    (home / "sending.json").unlink()
    queue(home, 2, session="aaaa-0001", start=2)
    queue(home, 2, session="bbbb-0002")

    def hostile_export(url):
        header = dumps("aaaa-0001", []).split("\n")[0]  # a valid header, then a line JCS could not even write
        return (header + "\n" + json.dumps({"kind": "receipt", "receipt": {}, "to_seq": 2**63}, separators=(",", ":"), sort_keys=True) + "\n").encode()

    out = Sender(config.load(home), get=hostile_export).drain()
    assert out.sent.get("bbbb-0002") == 2  # the other session still drains
    assert not any("Overflow" in r for r in [*out.retried, *out.failed.values()])  # the line past what we hold was never queried


def test_an_error_answer_cut_short_is_retried(home):
    import socket
    import threading

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        conn.recv(65536)
        conn.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 200\r\nConnection: close\r\n\r\n{\"error\": \"jou")
        conn.close()
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    status, _headers, body = http_post(f"http://127.0.0.1:{srv.getsockname()[1]}/v2/batches", {"batch": "x"})
    assert status == 503 and body is None


def test_one_sessions_persistent_surprise_does_not_slow_the_others(home, monkeypatch):
    import crucible_client.sender as sender_module

    queue(home, 1, session="aaaa-0001")
    original = Sender._drain_session

    def explodes_for_aaaa(self, store, session, until):
        if session == "aaaa-0001":
            raise OverflowError("something unexpected, every time")
        return original(self, store, session, until)

    monkeypatch.setattr(Sender, "_drain_session", explodes_for_aaaa)
    s = Sender(config.load(home))
    delays = []

    def tick(d):
        delays.append(d)
        queue(home, 1, session="bbbb-0002", start=len(delays) - 1)

    s.run(stop=lambda: len(delays) >= 6, sleep=tick)
    assert delays == [sender_module.IDLE] * 6  # the healthy session is sent at the idle pace
    assert held(home, "bbbb-0002")[0] == 4
    s.stuck.clear()
    out = s.drain()
    assert "aaaa-0001" in out.failed and not out.retried  # its own failure, not the sender's
    monkeypatch.setattr(sender_module, "SURPRISE_RETRY", 0.0)
    s.stuck.clear()
    assert "aaaa-0001" in s.drain().failed  # and it is tried again, on its own clock


def test_a_recovery_read_waits_until_the_other_sessions_have_had_their_turn(home):
    calls = []

    def lossy(url, body):
        http_post(url, body)
        raise ConnectionResetError("the answer never arrived")

    queue(home, 2, session="aaaa-0001")
    Sender(config.load(home), post=lossy).drain()  # the service holds aaaa 0..1; we hold no receipt
    (home / "sending.json").unlink()
    queue(home, 1, session="aaaa-0001", start=2)
    queue(home, 2, session="bbbb-0002")

    def post(url, body):
        calls.append("post")
        return http_post(url, body)

    def slow_export(url):
        calls.append("export " + url.rsplit("/", 2)[-2])
        from crucible_client.sender import http_get

        return http_get(url)

    out = Sender(config.load(home), post=post, get=slow_export).drain()
    assert calls == ["post", "post", "export aaaa-0001"]  # aaaa's refused send, bbbb's send, then aaaa's read
    assert out.sent == {"bbbb-0002": 2} and "recovered" in out.retried[0]


def test_the_recovery_read_has_its_own_longer_timeout(monkeypatch):
    import io
    import urllib.request

    import crucible_client.sender as sender_module

    seen = []

    def urlopen(url, timeout=None):
        seen.append(timeout)
        return io.BytesIO(b"x")

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    assert sender_module.http_get("http://127.0.0.1:1/v2/sessions/s/export") == b"x"
    assert seen == [sender_module.RECOVER_TIMEOUT] and sender_module.RECOVER_TIMEOUT > sender_module.TIMEOUT


def test_a_session_that_keeps_failing_is_logged_once_then_when_its_error_changes(home, monkeypatch):
    import crucible_client.sender as sender_module

    queue(home, 1, session="aaaa-0001")
    errors = iter(["one"] * 5 + ["two"] * 3)

    def explodes(self, store, session, until):
        raise OverflowError(next(errors))

    monkeypatch.setattr(Sender, "_drain_session", explodes)
    monkeypatch.setattr(sender_module, "SURPRISE_RETRY", 0.0)
    s = Sender(config.load(home))
    for _ in range(8):
        assert "aaaa-0001" in s.drain().failed
    logged = [json.loads(line) for line in (home / "sender.jsonl").read_text().splitlines()]
    assert [(e["failed"], e["times"]) for e in logged if "failed" in e] == [("OverflowError: one", 1), ("OverflowError: two", 1)]


def test_a_failure_after_a_stuck_or_retried_turn_is_logged_again(home, monkeypatch):
    import crucible_client.sender as sender_module
    from crucible_client.sender import Retry, Stuck

    queue(home, 1, session="aaaa-0001")
    turns = iter([OverflowError("x"), Stuck("st"), OverflowError("x"), Retry("rt"), OverflowError("x")])

    def turn(self, store, session, until):
        raise next(turns)

    monkeypatch.setattr(Sender, "_drain_session", turn)
    monkeypatch.setattr(sender_module, "SURPRISE_RETRY", 0.0)
    monkeypatch.setattr(sender_module, "STUCK_RETRY", 0.0)
    s = Sender(config.load(home))
    for _ in range(5):
        s.drain()
    logged = [json.loads(line) for line in (home / "sender.jsonl").read_text().splitlines()]
    assert [e.get("times") for e in logged if "failed" in e] == [1, 1, 1]  # each failure after another outcome is news


def test_a_failing_session_is_logged_about_hourly_whatever_its_retry_interval(home, monkeypatch):
    import crucible_client.sender as sender_module

    queue(home, 1, session="aaaa-0001")

    def explodes(self, store, session, until):
        raise OverflowError("x")

    monkeypatch.setattr(Sender, "_drain_session", explodes)
    monkeypatch.setattr(sender_module, "SURPRISE_RETRY", 600.0)  # ten minutes apart: six a hour
    s = Sender(config.load(home))
    for _ in range(12):
        s.stuck.clear()  # as if the ten minutes had passed
        s.drain()
    logged = [json.loads(line) for line in (home / "sender.jsonl").read_text().splitlines()]
    assert [e["times"] for e in logged if "failed" in e] == [1, 6, 12]


@pytest.mark.parametrize("status", [429, 503])
def test_a_limited_or_busy_recovery_read_is_retried_not_a_refusal(home, status):
    import email.message
    import urllib.error

    def lossy(url, body):
        http_post(url, body)
        raise ConnectionResetError("the answer never arrived")

    queue(home, 2, session="aaaa-0001")
    Sender(config.load(home), post=lossy).drain()
    (home / "sending.json").unlink()
    queue(home, 1, session="aaaa-0001", start=2)
    headers = email.message.Message()
    headers["Retry-After"] = "7"

    def limited(url):
        raise urllib.error.HTTPError(url, status, "busy", headers, None)

    out = Sender(config.load(home), get=limited).drain()
    assert not out.stuck and out.retry_after == 7.0 and "could not give" in out.retried[0]


@pytest.mark.parametrize("failure", ["refused", "timeout", "reset"])
def test_no_answer_on_the_recovery_read_is_retried_not_a_refusal(home, failure):
    import urllib.error

    def lossy(url, body):
        http_post(url, body)
        raise ConnectionResetError("the answer never arrived")

    queue(home, 2, session="aaaa-0001")
    Sender(config.load(home), post=lossy).drain()
    (home / "sending.json").unlink()
    queue(home, 1, session="aaaa-0001", start=2)
    error = {"refused": urllib.error.URLError(ConnectionRefusedError("refused")), "timeout": TimeoutError("timed out"),
             "reset": ConnectionResetError("reset")}[failure]

    def silent(url):
        raise error

    out = Sender(config.load(home), get=silent).drain()
    assert not out.stuck and not out.retried and "no answer" in out.failed["aaaa-0001"]  # its own clock, nobody else's


def test_a_sender_starting_while_its_lock_is_held_for_an_instant_still_starts(home):
    import fcntl
    import threading

    path = home / "sender.run.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)  # as an install checking sender_running() would, for a moment
    threading.Timer(0.3, lambda: (fcntl.flock(fd, fcntl.LOCK_UN), os.close(fd))).start()
    ran = []
    Sender(config.load(home)).run(stop=lambda: bool(ran), sleep=ran.append)  # no "another sender is already running"
    assert ran
