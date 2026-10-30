"""The hook command never stops a session, drift never blocks, and what a hook
cannot see honestly it does not record."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from crucible_chain.chain import replay
from crucible_chain.store import ChainStore
from crucible_client import hooks, paths, transcript

SESSION = "5a1c3e2b-0000-4000-8000-000000000001"


def env(event: str, tmp_path: Path, **fields) -> dict:
    base = {"hook_event_name": event, "session_id": SESSION, "cwd": str(tmp_path), "transcript_path": str(tmp_path / "t.jsonl")}
    return {**base, **fields}


def run_hook(stdin: str, home: Path) -> subprocess.CompletedProcess:
    e = {**os.environ, "CRUCIBLE_HOME": str(home)}
    return subprocess.run([sys.executable, "-m", "crucible_client.hooks"], input=stdin, capture_output=True, text=True, env=e, timeout=60)


def chain(home: Path, session: str = SESSION) -> list[dict]:
    with ChainStore(paths.chain_path(home)) as store:
        return [r.as_record() for r in store.records(session)]


# --- exit 0, always ------------------------------------------------------------------


@pytest.mark.parametrize("stdin", ["", "not json", "[]", "{}", "null", '{"hook_event_name": 7}', "{" * 5000])
def test_the_hook_command_exits_0_on_anything(tmp_path, stdin):
    r = run_hook(stdin, tmp_path / "home")
    assert r.returncode == 0 and r.stdout == "" and "Traceback" not in r.stderr


def test_the_hook_command_exits_0_when_it_cannot_write_at_all(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("not a directory")
    r = run_hook(json.dumps(env("SessionStart", tmp_path, source="startup")), blocker / "home")
    assert r.returncode == 0 and "Traceback" not in r.stderr


def test_a_hook_that_fails_says_why_in_the_local_error_log(tmp_path, monkeypatch):
    home = tmp_path / "home"

    def boom(*_a, **_k):
        raise RuntimeError("the disk is full")

    monkeypatch.setattr(hooks, "record", boom)
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO("{}"))
    monkeypatch.setenv("CRUCIBLE_HOME", str(home))
    assert hooks.main() == 0
    assert "the disk is full" in paths.error_log(home).read_text()


# --- drift is reported, never blocking -----------------------------------------------


def test_an_envelope_with_a_new_field_is_logged_and_still_recorded(tmp_path):
    home = tmp_path / "home"
    hooks.record(env("UserPromptSubmit", tmp_path, prompt="hi", prompt_id="p1", brand_new_field=1), home=home)
    assert [r["event"]["type"] for r in chain(home)] == ["prompt"]
    logged = [json.loads(line) for line in paths.drift_log(home).read_text().splitlines()]
    assert logged[0]["event"] == "UserPromptSubmit" and "brand_new_field" in logged[0]["problems"][0]


def test_an_envelope_missing_what_the_event_would_say_is_logged_and_not_recorded(tmp_path):
    home = tmp_path / "home"
    hooks.record(env("UserPromptSubmit", tmp_path, prompt_id="p1"), home=home)  # no prompt
    hooks.record(env("PreToolUse", tmp_path, tool_name="Read", tool_use_id="t1"), home=home)  # no tool_input
    assert chain(home) == []
    assert len(paths.drift_log(home).read_text().splitlines()) == 2


def test_a_hook_the_client_does_not_record_is_logged_as_drift(tmp_path):
    home = tmp_path / "home"
    assert hooks.record(env("Notification", tmp_path, message="x"), home=home) == []
    assert "not one this client records" in paths.drift_log(home).read_text()


# --- concurrent hooks ------------------------------------------------------------------


def test_hooks_fired_at_once_all_land_in_one_intact_chain(tmp_path):
    home = tmp_path / "home"
    procs = [
        subprocess.Popen([sys.executable, "-m", "crucible_client.hooks"], stdin=subprocess.PIPE, text=True,
                         env={**os.environ, "CRUCIBLE_HOME": str(home)})
        for _ in range(12)
    ]
    for i, p in enumerate(procs):
        p.communicate(json.dumps(env("PostToolUseFailure", tmp_path, tool_name="Bash", tool_input={"i": i},
                                     tool_use_id=f"t{i}", error="Exit code 1")), timeout=60)
    assert all(p.returncode == 0 for p in procs)
    records = chain(home)
    assert len(records) == 12 and replay(records).intact
    assert sorted(r["event"]["body"]["tool_use_id"] for r in records) == sorted(f"t{i}" for i in range(12))


# --- what a body says about paths, and files that cannot be read --------------------------


def test_a_body_path_is_home_relative_or_absolute_never_relative_to_a_moving_cwd(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home" / "proj" / "sub").mkdir(parents=True)
    proj = tmp_path / "home" / "proj"
    assert hooks._shown_path(str(proj / "a.txt"), str(proj)) == "~/proj/a.txt"
    assert hooks._shown_path("a.txt", str(proj / "sub")) == "~/proj/sub/a.txt"  # the same name after a cd is another file
    assert hooks._shown_path("~/.claude/CLAUDE.md", str(proj)) == "~/.claude/CLAUDE.md"
    assert hooks._shown_path("/etc/hosts", str(proj)) == "/etc/hosts"


def test_a_home_relative_tool_path_is_sealed_from_the_home_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home" / ".claude").mkdir(parents=True)
    (tmp_path / "home" / ".claude" / "CLAUDE.md").write_text("real")
    proj = tmp_path / "proj"
    (proj / "~" / ".claude").mkdir(parents=True)
    (proj / "~" / ".claude" / "CLAUDE.md").write_text("decoy")  # a literal ~ directory in the project
    home = tmp_path / "state"
    hooks.record(env("PostToolUse", proj, tool_name="Read", tool_input={"file_path": "~/.claude/CLAUDE.md"}, tool_use_id="t1",
                     tool_response={}, duration_ms=1), home=home)
    sealed = [r for r in chain(home) if r["event"]["type"] == "file.read"]
    import hashlib

    assert sealed[0]["event"]["digest"] == "sha256:" + hashlib.sha256(b"real").hexdigest()


def test_a_read_of_a_file_that_is_gone_records_the_tool_result_and_no_file_event(tmp_path):
    home = tmp_path / "home"
    gone = tmp_path / "gone.txt"
    hooks.record(env("PostToolUse", tmp_path, tool_name="Read", tool_input={"file_path": str(gone)}, tool_use_id="t1",
                     tool_response={"file": {}}, duration_ms=1), home=home)
    assert [r["event"]["type"] for r in chain(home)] == ["tool.result"]


def test_instructions_that_cannot_be_read_are_witnessed_not_sealed(tmp_path):
    home = tmp_path / "home"
    hooks.record(env("InstructionsLoaded", tmp_path, file_path=str(tmp_path / "CLAUDE.md"), memory_type="Project"), home=home)
    [r] = chain(home)
    assert (r["event"]["type"], r["event"]["class"]) == ("context.injected", "witnessed")


# --- the model, from the transcript -----------------------------------------------------------


def _write(path: Path, records: list, tail: str = "") -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records) + tail, encoding="utf-8")


def test_the_model_is_the_last_assistant_records(tmp_path):
    t = tmp_path / "t.jsonl"
    _write(t, [{"type": "assistant", "message": {"model": "claude-a"}}, {"type": "user"},
               {"type": "assistant", "message": {"model": "claude-b"}}], tail='{"type": "assistant", "mess')
    assert transcript.latest_model(t) == "claude-b"  # a half-written last line is skipped
    assert transcript.model_actor(t) == "model:claude-b"


@pytest.mark.parametrize("content", [None, "", '{"type": "user"}\n', '{"type": "assistant", "message": {"model": "has space"}}\n'])
def test_no_readable_model_is_model_unknown(tmp_path, content):
    t = tmp_path / "t.jsonl"
    if content is not None:
        t.write_text(content)
    assert transcript.model_actor(t) == transcript.UNKNOWN


def test_the_transcript_is_read_backwards_a_bounded_amount(tmp_path, monkeypatch):
    t = tmp_path / "t.jsonl"
    _write(t, [{"type": "assistant", "message": {"model": "claude-early"}}] + [{"type": "user", "pad": "x" * 1000}] * 200)
    monkeypatch.setattr(transcript, "MAX_READ", 64 * 1024)
    assert transcript.latest_model(t) is None
    monkeypatch.setattr(transcript, "MAX_READ", 8 * 1024 * 1024)
    assert transcript.latest_model(t) == "claude-early"


def test_a_tool_call_waits_for_the_record_that_holds_it(tmp_path):
    """2.1.281 writes the assistant record a moment after PreToolUse fires; the
    first call of a session finds no assistant record at all."""
    import threading
    import time

    t = tmp_path / "t.jsonl"
    t.write_text('{"type": "user"}\n')

    def later():
        time.sleep(0.3)
        with open(t, "a") as fh:
            fh.write(json.dumps({"type": "assistant", "message": {"model": "claude-x", "content": [{"type": "tool_use", "id": "toolu_1"}]}}) + "\n")

    threading.Thread(target=later).start()
    assert transcript.tool_call_actor(t, "toolu_1", wait=5) == "model:claude-x"


def test_a_tool_call_whose_record_never_comes_is_model_unknown_not_a_guess(tmp_path):
    t = tmp_path / "t.jsonl"
    _write(t, [{"type": "assistant", "message": {"model": "claude-prev", "content": [{"type": "tool_use", "id": "toolu_0"}]}}])
    assert transcript.tool_call_actor(t, "toolu_9", wait=0.2) == transcript.UNKNOWN
    assert transcript.tool_call_actor(tmp_path / "none.jsonl", "toolu_9", wait=0.1) == transcript.UNKNOWN


def test_a_subagents_tool_call_is_read_from_its_own_transcript(tmp_path):
    main = tmp_path / "s.jsonl"
    _write(main, [{"type": "assistant", "message": {"model": "claude-main", "content": [{"type": "tool_use", "id": "toolu_A"}]}}])
    sub = tmp_path / "s" / "subagents" / "agent-abc123.jsonl"
    sub.parent.mkdir(parents=True)
    _write(sub, [{"type": "assistant", "message": {"model": "claude-sub", "content": [{"type": "tool_use", "id": "toolu_S"}]}}])
    assert transcript.tool_call_actor(main, "toolu_S", agent_id="abc123", wait=0) == "model:claude-sub"
    assert transcript.tool_call_actor(main, "toolu_S", wait=0) == transcript.UNKNOWN  # not in the main transcript
    assert transcript.tool_call_actor(main, "toolu_S", agent_id="../../etc", wait=0) == transcript.UNKNOWN


def test_a_transcript_that_is_a_fifo_does_not_hang_the_hook(tmp_path):
    import time

    fifo = tmp_path / "t.jsonl"
    os.mkfifo(fifo)
    t0 = time.monotonic()
    assert transcript.tool_call_actor(fifo, "toolu_1", wait=0.2) == transcript.UNKNOWN
    assert transcript.model_actor(fifo) == transcript.UNKNOWN
    assert time.monotonic() - t0 < 3


def _sha(b: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(b).hexdigest()


def _write_event(tmp_path, tool, target, args, response=None):
    home = tmp_path / "state"
    hooks.record(env("PostToolUse", tmp_path, tool_name=tool, tool_input={"file_path": str(target), **args},
                     tool_use_id="t1", tool_response=response or {}, duration_ms=1), home=home)
    return [r["event"] for r in chain(home)]


@pytest.mark.parametrize("case,disk,args,response", [
    # What Claude Code 2.1.281 leaves on disk, which no reconstruction from the envelope gives.
    ("crlf-edit", b"alpha\r\ngamma\r\n", {"old_string": "beta\n", "new_string": ""}, {"originalFile": "alpha\nbeta\ngamma\n"}),
    ("delete-line", b"alpha\ngamma\n", {"old_string": "beta", "new_string": ""}, {"originalFile": "alpha\nbeta\ngamma\n"}),
    ("curly-quotes", "say \u201chi\u201d\n".encode(), {"old_string": '"x"', "new_string": '"hi"'}, {"originalFile": "say \u201cx\u201d\n"}),
    ("edit-create", b"x=1\n", {"old_string": "", "new_string": "x = 1\n"}, {"originalFile": None}),
])
def test_an_edit_is_sealed_as_the_disk_holds_it(tmp_path, case, disk, args, response):
    target = tmp_path / "f.txt"
    target.write_bytes(disk)
    _result, write = _write_event(tmp_path, "Edit", target, args, response)
    assert (write["type"], write["class"], write["digest"]) == ("file.write", "sealed", _sha(disk))
    assert "matches_tool_input" not in write["body"] and "disk_differs" not in write["body"]


@pytest.mark.parametrize("case,disk,content", [
    ("formatted after", b"x = 1\n", "x=1\n"),  # a formatter hook ran beside this one
    ("crlf file", b"a\r\nb\r\n", "a\nb\n"),
    ("utf-16 file", "a\nb\n".encode("utf-16-le"), "a\nb\n"),
    ("lone surrogate", "a\ufffdb".encode(), "a\ud800b"),
])
def test_a_write_is_sealed_as_the_disk_holds_it_and_claims_nothing_else(tmp_path, case, disk, content):
    target = tmp_path / "w.txt"
    target.write_bytes(disk)
    _result, write = _write_event(tmp_path, "Write", target, {"content": content})
    assert (write["type"], write["class"], write["digest"]) == ("file.write", "sealed", _sha(disk))
    assert set(write["body"]) == {"path", "tool_use_id"}


def test_the_surface_version_comes_from_the_transcript_record(tmp_path):
    home = tmp_path / "state"
    t = tmp_path / "t.jsonl"
    _write(t, [{"type": "assistant", "version": "2.1.281", "message": {"model": "claude-x", "content": [{"type": "tool_use", "id": "toolu_1"}]}}])
    hooks.record(env("PreToolUse", tmp_path, tool_name="Read", tool_input={}, tool_use_id="toolu_1"), home=home)
    hooks.record(env("Stop", tmp_path, last_assistant_message="done"), home=home)
    hooks.record(env("SessionStart", tmp_path, source="startup"), home=home)
    got = [(r["event"]["type"], r["event"]["body"].get("version")) for r in chain(home)]
    assert got == [("tool.call", "2.1.281"), ("response", "2.1.281"), ("session.start", None)]


def test_a_lookup_that_fails_costs_only_its_own_event(tmp_path, monkeypatch):
    home = tmp_path / "state"

    def broken(*_a, **_k):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(hooks, "response_source", broken)
    (tmp_path / "f.txt").write_text("x")
    hooks.record(env("Stop", tmp_path, last_assistant_message="done"), home=home)
    hooks.record(env("PostToolUse", tmp_path, tool_name="Read", tool_input={"file_path": str(tmp_path / "f.txt")}, tool_use_id="t2",
                     tool_response={}, duration_ms=1), home=home)
    assert [r["event"]["type"] for r in chain(home)] == ["tool.result", "file.read"]
    assert "UnicodeDecodeError" in paths.error_log(home).read_text()


def test_a_value_jcs_cannot_encode_is_still_recorded(tmp_path):
    home = tmp_path / "state"
    (tmp_path / "f.txt").write_text("data")
    hooks.record(env("PreToolUse", tmp_path, tool_name="mcp__db__get", tool_input={"row": 2**60}, tool_use_id="t1"), home=home)
    hooks.record(env("PostToolUse", tmp_path, tool_name="Read", tool_input={"file_path": str(tmp_path / "f.txt")}, tool_use_id="t2",
                     tool_response={"stdout": "cut \ud83c", "n": 2**61}, duration_ms=1), home=home)
    got = [(r["event"]["type"], r["event"]["note"]["of"]) for r in chain(home)]
    assert got == [("tool.call", "json-text"), ("tool.result", "json-text"), ("file.read", "bytes")]


def test_drift_that_cannot_be_logged_does_not_cost_the_event(tmp_path):
    home = tmp_path / "state"
    home.mkdir()
    paths.drift_log(home).write_text("")
    paths.drift_log(home).chmod(0o400)
    hooks.record(env("UserPromptSubmit", tmp_path, prompt="hi", prompt_id="p1", brand_new_field=1), home=home)
    assert [r["event"]["type"] for r in chain(home)] == ["prompt"]



def test_a_tool_id_mentioned_elsewhere_does_not_name_the_model(tmp_path):
    t = tmp_path / "t.jsonl"
    _write(t, [{"type": "assistant", "message": {"model": "claude-wrong", "content": [{"type": "text", "text": "toolu_7"}]}},
               {"type": "assistant", "message": {"model": "claude-right", "content": [{"type": "tool_use", "id": "toolu_7"}]}},
               {"type": "assistant", "message": {"model": "claude-later", "content": [{"type": "text", "text": "about toolu_7"}]}}])
    assert transcript.tool_use_model(t, "toolu_7", wait=0) == "claude-right"


def test_a_failed_tool_on_a_file_that_exists_records_no_file_event(tmp_path):
    home = tmp_path / "state"
    (tmp_path / "big.txt").write_text("exists")
    hooks.record(env("PostToolUseFailure", tmp_path, tool_name="Read", tool_input={"file_path": str(tmp_path / "big.txt")},
                     tool_use_id="t1", error="File content exceeds maximum allowed size"), home=home)
    assert [r["event"]["type"] for r in chain(home)] == ["tool.result"]
