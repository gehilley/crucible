"""The capture tool's last check before a fixture is written (scripts/capture_hooks.py,
check_scrubbed): the user's name as a word anywhere refuses it, and the pinned schemas'
own field names never do."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = Path(__file__).parent / "fixtures" / "hooks"
spec = importlib.util.spec_from_file_location("capture_hooks", ROOT / "scripts" / "capture_hooks.py")
capture = importlib.util.module_from_spec(spec)
sys.modules["capture_hooks"] = capture  # its dataclasses look themselves up there
spec.loader.exec_module(capture)


@pytest.fixture(autouse=True)
def account(monkeypatch, tmp_path):
    """The account's names pinned, so no test depends on the machine that runs it: a USER, no
    LOGNAME, a password entry and a home with names no capture holds, and a plain host name."""
    import pwd
    import socket

    monkeypatch.setenv("USER", "zqxdefault")  # a test that needs another name sets or deletes it
    monkeypatch.delenv("LOGNAME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "zqxhomedir"))
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: type("Entry", (), {"pw_name": "zqxpwname", "pw_dir": "/home/zqxpwname"})())
    monkeypatch.setattr(socket, "gethostname", lambda: "zqxhost.example")


def envelope(**extra):
    return [{"hook_event_name": "PostToolUse", "session_id": "s", "transcript_path": "/TRANSCRIPTS/0.jsonl",
             "cwd": capture.WORKSPACE, "tool_name": "Bash", "tool_input": {"command": "ls -l"}, "tool_use_id": "t",
             "tool_response": {"stdout": "total 0"}, **extra}]


@pytest.mark.parametrize("where", ["tool output", "a key", "an encoded path", "an identifier", "a scratch path",
                                   "dunder"])
def test_the_user_name_anywhere_refuses_the_capture(tmp_path, monkeypatch, where):
    monkeypatch.setenv("USER", "zqxuser")
    out = {"tool output": "drwx------ 2 zqxuser zqxuser 40 notes", "an identifier": "conda activate zqxuser_env",
           "a scratch path": "/tmp/zqxuser_scratch/run.log", "dunder": "__zqxuser__",
           "an encoded path": "/HOME/.claude/projects/-home-zqxuser-work/x.jsonl"}
    events = envelope(tool_response={"zqxuser": 1} if where == "a key" else {"stdout": out[where]})
    with pytest.raises(capture.CaptureError, match="user name 'zqxuser'"):
        capture.check_scrubbed(events, tmp_path / "ws", {})


@pytest.mark.parametrize("user", ["tool", "model", "session"])
def test_a_user_named_like_a_field_is_not_named_by_the_field(tmp_path, monkeypatch, user):
    monkeypatch.setenv("USER", user)
    events = envelope(tool_calls=[{"tool_name": "Read"}], session_crons=[])
    capture.check_scrubbed(events, tmp_path / "ws", {"/TRANSCRIPTS/0.jsonl": [
        {"type": "assistant", "version": "2.1.281", "message": {"model": "m", "content": [{"type": "tool_use", "id": "t"}]}}]})


@pytest.mark.parametrize("key", ["prompt", "tool_input"])
def test_a_free_form_key_named_like_a_field_and_the_user_still_refuses(tmp_path, monkeypatch, key):
    monkeypatch.setenv("USER", key)  # the key is both a schema field's name and the user's
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(envelope(tool_response={key: "x"}), tmp_path / "ws", {})


@pytest.mark.parametrize("user, out", [
    ("ec2-user", "drwx 2 ec2-user ec2-user notes"), ("john.doe", "/Users/john.doe/notes"), ("jörg", "/tmp/jörg/x"),
    ("prompt", "uid=1000(prompt) gid=1000(prompt)"), ("source", "drwx 2 source source notes"),
    ("id-svc", "/home/id-svc/x"), ("svc.id", "uid=1001(svc.id)"), ("model-x", "drwx 2 model-x model-x n"),
    ("first.last", "/HOME/.claude/projects/-home-first-last-work/x.jsonl"),  # Claude Code's own project slug
    ("tool_input", "/home/tool_input/x"),
])
def test_a_name_with_separators_or_named_like_a_field_is_found_in_tool_output(tmp_path, monkeypatch, user, out):
    monkeypatch.setenv("USER", user)
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(envelope(tool_response={"stdout": out}), tmp_path / "ws", {})


def test_a_word_in_some_tools_own_keys_refuses_the_captures_by_design(tmp_path, monkeypatch):
    # ToolSearch's `max_results` is free-form tool input, not a pinned schema field: USER=max refuses. Fail closed.
    monkeypatch.setenv("USER", "max")
    doc = json.loads((FIXTURES / "edit-failure-notebook.json").read_text())
    with pytest.raises(capture.CaptureError, match="tool_input/<key>"):
        capture.check_scrubbed(doc["events"], tmp_path / "ws", doc["transcripts"])


@pytest.mark.parametrize("user", ["hook", "cwd", "calls", "crons", "hilley", "george", "root", "ubuntu"])
def test_a_user_named_like_a_schema_field_does_not_refuse_the_committed_captures(tmp_path, monkeypatch, user):
    # Names that are words the captures use -- "tool", "model", "id", "max", "name" -- refuse them: by design.
    monkeypatch.setenv("USER", user)
    for fixture in ("edit-failure-notebook.json", "subagent.json", "tool-failure.json", "toy-analysis.json"):
        doc = json.loads((FIXTURES / fixture).read_text())
        capture.check_scrubbed(doc["events"], tmp_path / "ws", doc["transcripts"])


@pytest.mark.parametrize("user", ["assistant", "tool_use"])
def test_the_transcript_reductions_own_constants_never_name_the_user(tmp_path, monkeypatch, user):
    monkeypatch.setenv("USER", user)
    capture.check_scrubbed(envelope(), tmp_path / "ws", {"/TRANSCRIPTS/0.jsonl": [
        {"type": "assistant", "message": {"model": "m", "content": [{"type": "tool_use", "id": "t"}]}}]})


def test_a_key_at_a_schema_position_is_skipped_only_when_it_is_exactly_a_field(tmp_path, monkeypatch):
    monkeypatch.setenv("USER", "prompt")
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed([{**envelope()[0], "/home/prompt/x": 1}], tmp_path / "ws", {})


def test_a_file_the_run_wrote_is_checked_too(tmp_path, monkeypatch):
    monkeypatch.setenv("USER", "zqxuser")
    with pytest.raises(capture.CaptureError, match="files_after"):
        capture.check_scrubbed(envelope(), tmp_path / "ws", {}, {"out.txt": "written by zqxuser\n"})


def test_a_machine_path_with_letters_outside_ascii_is_found(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", "/srv/hömé")
    monkeypatch.setenv("USER", "zz")
    with pytest.raises(capture.CaptureError, match="machine-specific"):
        capture.check_scrubbed(envelope(tool_response={"stdout": "cat /srv/hömé/.ssh/config"}), tmp_path / "ws", {})


def test_scrub_replaces_the_workspace_in_the_files_the_run_wrote_too(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    _e, _t, files = capture.scrub([], root, {"notes.txt": f"cwd is {root}\n"})
    assert files == {"notes.txt": f"cwd is {capture.WORKSPACE}\n"}


def test_a_free_form_key_containing_the_name_refuses_even_when_it_is_a_schema_word(tmp_path, monkeypatch):
    monkeypatch.setenv("USER", "tool")  # keys are scanned whole: only a schema position exempts `tool_input`
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(envelope(tool_response={"tool_input": "x"}), tmp_path / "ws", {})


def test_a_name_in_a_transcripts_copied_values_is_found(tmp_path, monkeypatch):
    monkeypatch.setenv("USER", "cwd")
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(envelope(), tmp_path / "ws", {"/TRANSCRIPTS/0.jsonl": [
            {"type": "assistant", "message": {"model": "claude-x /home/cwd/x", "content": []}}]})


@pytest.mark.parametrize("user, out", [("zqxuser", "/home/ZqxUser/x"), ("jörg", "/Users/jörg/x")])
def test_a_name_in_another_case_or_unicode_form_is_found(tmp_path, monkeypatch, user, out):
    monkeypatch.setenv("USER", user)
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(envelope(tool_response={"stdout": out}), tmp_path / "ws", {})


def test_with_no_user_set_the_accounts_other_names_are_still_looked_for(tmp_path, monkeypatch):
    monkeypatch.delenv("USER", raising=False)
    monkeypatch.delenv("LOGNAME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "zqxhome"))
    with pytest.raises(capture.CaptureError, match="user name 'zqxhome'"):
        capture.check_scrubbed(envelope(tool_response={"stdout": "owner zqxhome"}), tmp_path / "ws", {})


def test_with_no_name_at_all_the_capture_is_refused(tmp_path, monkeypatch):
    import pwd

    monkeypatch.delenv("USER", raising=False)
    monkeypatch.setenv("HOME", "/")
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: (_ for _ in ()).throw(KeyError(uid)))
    with pytest.raises(capture.CaptureError, match="cannot tell this account's name"):
        capture.check_scrubbed(envelope(), tmp_path / "ws", {})


@pytest.mark.parametrize("home, out", [
    ("/home/o\"q", "cat /home/o\"q/.ssh/config"),                            # JSON escapes it
    ("/home/george.hilley", "/HOME/.claude/projects/-home-george-hilley-work/x"),  # Claude Code's slug of it
])
def test_the_home_directory_as_json_writes_it_or_as_a_slug_is_found(tmp_path, monkeypatch, home, out):
    monkeypatch.setenv("HOME", home)
    monkeypatch.setenv("USER", "zz")
    with pytest.raises(capture.CaptureError, match="machine-specific"):
        capture.check_scrubbed(envelope(tool_response={"stdout": out}), tmp_path / "ws", {})


def test_a_key_inside_a_batchs_calls_is_skipped_only_when_it_is_exactly_a_field(tmp_path, monkeypatch):
    monkeypatch.setenv("USER", "prompt")
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(envelope(tool_calls=[{"tool_name": "Read", "/home/prompt/x": 1}]), tmp_path / "ws", {})


def test_the_files_the_run_wrote_are_checked_by_name_and_for_machine_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("USER", "zz")
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(envelope(), tmp_path / "ws", {}, {"notes-zz.txt": "x"})
    with pytest.raises(capture.CaptureError, match="machine-specific"):
        capture.check_scrubbed(envelope(), tmp_path / "ws", {}, {"notes.txt": f"in {tmp_path / 'ws'}\n"})


@pytest.mark.parametrize("where", ["LOGNAME", "pwd"])
def test_every_name_the_account_goes_by_is_looked_for(tmp_path, monkeypatch, where):
    import pwd

    monkeypatch.setenv("USER", "zz")
    if where == "LOGNAME":
        monkeypatch.setenv("LOGNAME", "prompt")  # named like a schema field, too
        out = "uid=1000(prompt)"
    else:
        monkeypatch.setattr(pwd, "getpwuid", lambda uid: type("Entry", (), {"pw_name": "zqxlogin", "pw_dir": "/home/zqxlogin"})())
        out = "drwx 2 zqxlogin zqxlogin notes"
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(envelope(tool_response={"stdout": out}), tmp_path / "ws", {})


@pytest.mark.parametrize("where", ["envelope", "batch call"])
def test_a_key_that_is_not_exactly_a_field_is_scanned_whole_at_a_schema_position(tmp_path, monkeypatch, where):
    monkeypatch.setenv("USER", "tool")
    events = [{**envelope()[0], "x-tool_input": 1}] if where == "envelope" else envelope(tool_calls=[{"x-tool_input": 1}])
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(events, tmp_path / "ws", {})


def test_a_name_in_a_transcript_key_is_found(tmp_path, monkeypatch):
    monkeypatch.setenv("USER", "zqxuser")
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(envelope(), tmp_path / "ws", {"/TRANSCRIPTS/0.jsonl": [{"type": "assistant", "zqxuser": 1}]})


@pytest.mark.parametrize("user, out", [
    ("jo\u0308rg", "/Users/jörg/x"),                                    # an NFD name, an NFC value
    ("jo\u0308rg", "/HOME/.claude/projects/-home-j-rg-work/x.jsonl"),   # and its slug
    ("Prompt", "uid=1000(prompt)"),                                      # a schema word, in another case
])
def test_a_name_differing_in_form_or_case_from_the_text_is_found(tmp_path, monkeypatch, user, out):
    monkeypatch.setenv("USER", user)
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(envelope(tool_response={"stdout": out}), tmp_path / "ws", {})


@pytest.mark.parametrize("host", ["pi", "x1.local"])
def test_a_short_host_name_is_found_as_a_word(tmp_path, monkeypatch, host):
    import socket

    monkeypatch.setenv("USER", "zz")
    monkeypatch.setattr(socket, "gethostname", lambda: host)
    with pytest.raises(capture.CaptureError, match="host name"):
        capture.check_scrubbed(envelope(tool_response={"stdout": f"connected to {host.split('.')[0]}.lan"}), tmp_path / "ws", {})


@pytest.mark.parametrize("home", ["/workspace", "/github/home", "/data/transcripts"])
def test_an_account_named_like_a_placeholder_does_not_refuse_the_placeholders(tmp_path, monkeypatch, home):
    monkeypatch.delenv("USER", raising=False)
    monkeypatch.setenv("HOME", home)
    for fixture in ("edit-failure-notebook.json", "subagent.json", "tool-failure.json", "toy-analysis.json"):
        doc = json.loads((FIXTURES / fixture).read_text())
        capture.check_scrubbed(doc["events"], tmp_path / "ws", doc["transcripts"])


def test_a_name_in_the_part_of_a_transcript_placeholder_the_scrub_copied_is_found(tmp_path, monkeypatch):
    monkeypatch.setenv("USER", "zqxuser")
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(envelope(), tmp_path / "ws", {"/TRANSCRIPTS/0/subagents/agent-zqxuser-review.jsonl": []})


@pytest.mark.parametrize("host, out", [
    ("3f4e5a6b7c8d", "0::/docker/3f4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6"),  # a container's id
    ("zqxbox", "Connected to ZQXBOX"),                                                                # another case
])
def test_a_host_name_run_into_more_characters_or_in_another_case_is_found(tmp_path, monkeypatch, host, out):
    import socket

    monkeypatch.setenv("USER", "zz")
    monkeypatch.setattr(socket, "gethostname", lambda: host)
    with pytest.raises(capture.CaptureError, match="host name"):
        capture.check_scrubbed(envelope(tool_response={"stdout": out}), tmp_path / "ws", {})


def test_a_short_host_name_does_not_refuse_the_committed_captures(tmp_path, monkeypatch):
    import socket

    monkeypatch.setenv("USER", "zz")
    monkeypatch.setattr(socket, "gethostname", lambda: "ool")  # a word, not a substring: every 'tool' holds it
    for fixture in ("edit-failure-notebook.json", "subagent.json", "tool-failure.json", "toy-analysis.json"):
        doc = json.loads((FIXTURES / fixture).read_text())
        capture.check_scrubbed(doc["events"], tmp_path / "ws", doc["transcripts"])


def test_the_scrubs_own_home_token_is_no_accounts_name(tmp_path, monkeypatch):
    monkeypatch.delenv("USER", raising=False)
    monkeypatch.setenv("HOME", "/github/home")
    capture.check_scrubbed(envelope(tool_response={"stdout": "read /HOME/.claude/settings.json"}), tmp_path / "ws", {})


@pytest.mark.parametrize("user, out", [
    ("jo\u0308rg", "/HOME/.claude/projects/-home-jo-rg-work/x.jsonl"),  # the raw (NFD) name's slug
    ("zqxuser", "x/HOMEzqxuser"),                                        # run into the scrub's own token
])
def test_a_name_next_to_the_scrubs_tokens_or_slugged_raw_is_found(tmp_path, monkeypatch, user, out):
    monkeypatch.setenv("USER", user)
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(envelope(tool_response={"stdout": out}), tmp_path / "ws", {})


def test_a_home_of_slash_is_not_replaced_by_the_scrub(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", "/")
    root = tmp_path / "ws"
    root.mkdir()
    events, _t, _f = capture.scrub([{"cwd": str(root), "transcript_path": "/t.jsonl"}], root)
    assert events[0]["cwd"] == capture.WORKSPACE  # not /HOMEWORKSPACE



@pytest.mark.parametrize("host", ["Pre", "post"])
def test_a_short_host_starting_a_word_of_every_capture_does_not_refuse_them(tmp_path, monkeypatch, host):
    import socket

    monkeypatch.setenv("USER", "zz")
    monkeypatch.setattr(socket, "gethostname", lambda: host)  # PreToolUse, PostToolUse: in every fixture
    for fixture in ("edit-failure-notebook.json", "subagent.json", "tool-failure.json", "toy-analysis.json"):
        doc = json.loads((FIXTURES / fixture).read_text())
        capture.check_scrubbed(doc["events"], tmp_path / "ws", doc["transcripts"])


@pytest.mark.parametrize("user, transcripts", [("jsonl", {}), ("other", {"/TRANSCRIPTS/other-1.jsonl": []})])
def test_the_whole_of_the_scrubs_transcript_tokens_is_no_name(tmp_path, monkeypatch, user, transcripts):
    monkeypatch.setenv("USER", user)
    capture.check_scrubbed(envelope(), tmp_path / "ws", transcripts)  # envelope()'s transcript is /TRANSCRIPTS/0.jsonl


@pytest.mark.parametrize("user, out", [("homer", "ls /mnt/c/Users/HOMER/Desktop"), ("007bond", "/TRANSCRIPTS/007bond/x")])
def test_a_name_that_merely_starts_like_a_scrub_token_is_found(tmp_path, monkeypatch, user, out):
    monkeypatch.setenv("USER", user)
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(envelope(tool_response={"stdout": out}), tmp_path / "ws", {})


def test_the_password_databases_home_is_a_suspect_too(tmp_path, monkeypatch):
    import pwd

    monkeypatch.setenv("USER", "zz")
    monkeypatch.setenv("HOME", "/")
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: type("Entry", (), {"pw_name": "svc", "pw_dir": "/opt/app-data"})())
    with pytest.raises(capture.CaptureError, match="machine-specific"):
        capture.check_scrubbed(envelope(tool_response={"stdout": "see /opt/app-data/cfg"}), tmp_path / "ws", {})


def test_the_scrub_replaces_a_home_only_as_a_whole_path(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", "/home/al")
    root = tmp_path / "ws"
    root.mkdir()
    events, _t, _f = capture.scrub([{"cwd": str(root), "out": "ls /home/alice/notes; cat /home/al/x"}], root)
    assert events[0]["out"] == f"ls /home/alice/notes; cat {capture.HOME}/x"


@pytest.mark.parametrize("fixture", ["edit-failure-notebook.json", "subagent.json", "tool-failure.json", "toy-analysis.json"])
def test_each_committed_capture_scrubs_back_to_itself(tmp_path, fixture):
    """Put a real workspace, home and transcript paths back into a committed capture, scrub it
    again, and it must come out as committed, and pass the check."""
    doc = json.loads((FIXTURES / fixture).read_text())
    root = tmp_path / "crucible-capture-x" / "workspace"
    root.mkdir(parents=True)
    home = str(capture.Path.home())
    main = f"{home}/.claude/projects/-tmp-crucible-capture-x-workspace/5a1c3e2b-0000-4000-8000-0000000000ee"
    raw = json.dumps({"events": doc["events"], "files": doc["files_after"]}, ensure_ascii=False)
    raw = raw.replace("/TRANSCRIPTS/0", main).replace(capture.WORKSPACE, str(root)).replace(capture.HOME, home)
    real = json.loads(raw)
    events, _transcripts, files = capture.scrub(real["events"], root, real["files"])
    assert events == doc["events"] and files == doc["files_after"]
    capture.check_scrubbed(events, root, doc["transcripts"], files)


@pytest.mark.parametrize("home, out", [("/home/al", "your home is /home/al."), ("/home/jos", "ls /home/josé/x")])
def test_a_home_ending_a_sentence_is_replaced_and_one_before_another_letter_is_not(tmp_path, monkeypatch, home, out):
    monkeypatch.setenv("HOME", home)
    root = tmp_path / "ws"
    root.mkdir()
    events, _t, _f = capture.scrub([{"cwd": str(root), "out": out}], root)
    expect = "your home is /HOME." if out.endswith(".") else out  # /home/josé is not /home/jos's
    assert events[0]["out"] == expect


def test_the_password_databases_home_name_is_one_of_the_accounts_names(tmp_path, monkeypatch):
    import pwd

    monkeypatch.setenv("USER", "zz")
    monkeypatch.setenv("HOME", "/")
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: type("Entry", (), {"pw_name": "svc", "pw_dir": "/home/zqxsvc"})())
    with pytest.raises(capture.CaptureError, match="user name"):
        capture.check_scrubbed(envelope(tool_response={"stdout": "owner zqxsvc"}), tmp_path / "ws", {})


@pytest.mark.parametrize("host", ["workspace", "transcripts"])
def test_a_host_named_like_a_scrub_token_does_not_refuse_the_committed_captures(tmp_path, monkeypatch, host):
    import socket

    monkeypatch.setenv("USER", "zz")
    monkeypatch.setattr(socket, "gethostname", lambda: host)
    for fixture in ("edit-failure-notebook.json", "subagent.json", "tool-failure.json", "toy-analysis.json"):
        doc = json.loads((FIXTURES / fixture).read_text())
        capture.check_scrubbed(doc["events"], tmp_path / "ws", doc["transcripts"])



@pytest.mark.parametrize("home, out, expect", [
    ("/home/jörg", "cat /home/jörg/x", "cat /HOME/x"),           # a home with a letter outside ASCII is replaced
    ("/home/al", "cp /home/al.bak /home/al-old /tmp", "cp /home/al.bak /home/al-old /tmp"),  # other paths, left alone
])
def test_the_scrub_replaces_exactly_the_home_path(tmp_path, monkeypatch, home, out, expect):
    monkeypatch.setenv("HOME", home)
    root = tmp_path / "ws"
    root.mkdir()
    events, _t, _f = capture.scrub([{"cwd": str(root), "out": out}], root)
    assert events[0]["out"] == expect
