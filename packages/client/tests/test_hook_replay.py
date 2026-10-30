"""Each captured session replays through the hooks to its known event list
(docs/v1-audit.md §5 step 6).

The fixtures are real Claude Code 2.1.281 envelopes (scripts/capture_hooks.py).
Replay recreates the workspace and the transcripts the envelopes name, applies
each tool's effect on disk at the moment the client would have, and hands the
envelopes of the hooks the client installs to `hooks.record`, in the order the
client fired them. The known answers are written out below by hand: each
event's type, actor, class and body, and what each witnessed event commits to,
named by the envelope field it must come from.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from crucible_chain.chain import replay
from crucible_chain.events import digest_only
from crucible_chain.store import ChainStore
from crucible_client import envelopes as envelopes_
from crucible_client import hooks, paths

FIXTURES = Path(__file__).parent / "fixtures" / "hooks"
OPUS = "model:claude-opus-5-5"
V = "2.1.281"  # the version the surface writes on each transcript record
IDS = ("tool_use_id", "duration_ms", "prompt_id", "agent_id")  # checked against the envelope separately

#: (type, actor, class, body without IDS) for every event, in order.
KNOWN = {
    "toy-analysis": [
        ("session.start", "tool:claude-code", "witnessed", {"surface": "claude-code", "source": "startup"}),
        ("context.injected", "tool:claude-code", "sealed", {"path": "~/ws/CLAUDE.md", "memory_type": "Project", "load_reason": "session_start"}),
        ("prompt", "human", "witnessed", {}),
        ("tool.call", "model:claude-sonnet-5", "witnessed", {"tool": "Read", "version": V}),  # its transcript record names sonnet (see `edited`)
        ("tool.result", "tool:Read", "witnessed", {"tool": "Read"}),
        ("file.read", "tool:Read", "sealed", {"path": "~/ws/sample.txt"}),
        ("tool.call", OPUS, "witnessed", {"tool": "Bash", "version": V}),
        ("tool.result", "tool:Bash", "witnessed", {"tool": "Bash"}),
        ("tool.call", OPUS, "witnessed", {"tool": "Write", "version": V}),
        ("tool.result", "tool:Write", "witnessed", {"tool": "Write"}),
        ("file.write", "tool:Write", "sealed", {"path": "~/ws/count.txt"}),
        ("tool.call", OPUS, "witnessed", {"tool": "Edit", "version": V}),
        ("tool.result", "tool:Edit", "witnessed", {"tool": "Edit"}),
        ("file.write", "tool:Edit", "sealed", {"path": "~/ws/count.txt"}),
        ("response", OPUS, "witnessed", {"version": V}),
        ("session.end", "tool:claude-code", "witnessed", {"reason": "other"}),
    ],
    "tool-failure": [
        ("session.start", "tool:claude-code", "witnessed", {"surface": "claude-code", "source": "startup"}),
        ("prompt", "human", "witnessed", {}),
        ("tool.call", OPUS, "witnessed", {"tool": "Read", "version": V}),
        ("tool.result", "tool:Read", "witnessed", {"tool": "Read", "failed": True, "interrupted": False}),
        ("tool.call", OPUS, "witnessed", {"tool": "Bash", "version": V}),
        ("tool.result", "tool:Bash", "witnessed", {"tool": "Bash", "failed": True, "interrupted": False}),
        ("response", OPUS, "witnessed", {"version": V}),
        ("session.end", "tool:claude-code", "witnessed", {"reason": "other"}),
    ],
    "subagent": [
        ("session.start", "tool:claude-code", "witnessed", {"surface": "claude-code", "source": "startup"}),
        ("prompt", "human", "witnessed", {}),
        ("tool.call", OPUS, "witnessed", {"tool": "Agent", "version": V}),
        # The subagent's call: its model is in the subagent's own transcript (haiku, see `edited`).
        ("tool.call", "model:claude-haiku-4-5", "witnessed", {"tool": "Read", "agent_type": "general-purpose", "version": V}),
        ("tool.result", "tool:Read", "witnessed", {"tool": "Read", "agent_type": "general-purpose"}),
        ("file.read", "tool:Read", "sealed", {"path": "~/ws/sample.txt"}),
        ("tool.result", "tool:Agent", "witnessed", {"tool": "Agent"}),
        ("response", OPUS, "witnessed", {"version": V}),
        ("session.end", "tool:claude-code", "witnessed", {"reason": "other"}),
    ],
    "edit-failure-notebook": [  # the Edit refused by input validation fired no hook (the fixture's note)
        ("session.start", "tool:claude-code", "witnessed", {"surface": "claude-code", "source": "startup"}),
        ("prompt", "human", "witnessed", {}),
        ("tool.call", OPUS, "witnessed", {"tool": "Read", "version": V}),
        ("tool.result", "tool:Read", "witnessed", {"tool": "Read"}),
        ("file.read", "tool:Read", "sealed", {"path": "~/ws/notes.txt"}),
        ("tool.call", OPUS, "witnessed", {"tool": "Read", "version": V}),
        ("tool.result", "tool:Read", "witnessed", {"tool": "Read"}),
        ("file.read", "tool:Read", "sealed", {"path": "~/ws/analysis.ipynb"}),
        ("tool.call", OPUS, "witnessed", {"tool": "ToolSearch", "version": V}),
        ("tool.result", "tool:ToolSearch", "witnessed", {"tool": "ToolSearch"}),
        ("tool.call", OPUS, "witnessed", {"tool": "NotebookEdit", "version": V}),
        ("tool.result", "tool:NotebookEdit", "witnessed", {"tool": "NotebookEdit"}),
        ("file.write", "tool:NotebookEdit", "sealed", {"path": "~/ws/analysis.ipynb"}),
        ("response", OPUS, "witnessed", {"version": V}),
        ("session.end", "tool:claude-code", "witnessed", {"reason": "other"}),
    ],
}

#: The envelope field each witnessed event commits to, by event type.
FIELD = {
    "session.start": lambda env: {"cwd": env["cwd"]},
    "prompt": lambda env: env["prompt"],
    "tool.call": lambda env: env["tool_input"],
    "tool.result": lambda env: env["tool_response"] if env["hook_event_name"] == "PostToolUse" else {"error": env["error"]},
    "response": lambda env: env["last_assistant_message"],
}


def load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def _sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def edited(name: str, doc: dict) -> dict:
    """Give some transcript records another model, so the test can tell which record
    named the actor: the first tool call's record in toy-analysis, and every record in
    the subagent's own transcript."""
    for placeholder, records in doc["transcripts"].items():
        for i, r in enumerate(records):
            if name == "toy-analysis" and i == 0:
                r["message"]["model"] = "claude-sonnet-5"
            if "/subagents/" in placeholder:
                r["message"]["model"] = "claude-haiku-4-5"
    return doc


def _apply_tool(env: dict, files_after: dict, ws: Path) -> None:
    """Change the disk the way the tool did, before its PostToolUse fires."""
    args = env["tool_input"]
    if env["tool_name"] == "Write":
        Path(args["file_path"]).write_text(args["content"], encoding="utf-8")
    elif env["tool_name"] == "Edit":
        p = Path(args["file_path"])
        text = p.read_text(encoding="utf-8")
        p.write_text(text.replace(args["old_string"], args["new_string"], -1 if args.get("replace_all") else 1), encoding="utf-8")
    elif env["tool_name"] == "NotebookEdit":
        p = Path(args["notebook_path"])
        p.write_text(files_after[str(p.relative_to(ws))], encoding="utf-8")  # the fixture's only notebook edit


def replay_fixture(name: str, tmp_path: Path, monkeypatch) -> tuple[list, list, Path]:
    """(records, (envelope, its records) pairs, client home)."""
    doc = edited(name, load(name))
    monkeypatch.setenv("HOME", str(tmp_path))
    ws, tdir, home = tmp_path / "ws", tmp_path / "transcripts", tmp_path / "state"
    ws.mkdir()
    for rel, text in doc["files_before"].items():
        (ws / rel).parent.mkdir(parents=True, exist_ok=True)
        (ws / rel).write_text(text, encoding="utf-8")
    text = json.dumps(doc["events"])
    for placeholder, records in sorted(doc["transcripts"].items()):
        path = tdir / placeholder.removeprefix("/TRANSCRIPTS/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
        text = text.replace(placeholder, str(path))
    envs = json.loads(text.replace("/WORKSPACE", str(ws)).replace("/HOME", str(Path.home())))
    pairs = []
    for env in envs:
        if env["hook_event_name"] == "PostToolUse":
            _apply_tool(env, doc["files_after"], ws)
        if env["hook_event_name"] in envelopes_.HOOK_EVENTS:  # the client receives only the hooks it installs
            pairs.append((env, [r.as_record() for r in hooks.record(env, home=home)]))
    for rel, expected in doc["files_after"].items():
        assert (ws / rel).read_text(encoding="utf-8") == expected, f"the replayed workspace drifted from the capture at {rel}"
    with ChainStore(paths.chain_path(home)) as store:
        return [r.as_record() for r in store.records(envs[0]["session_id"])], pairs, home


@pytest.mark.parametrize("name", sorted(KNOWN))
def test_each_captured_session_replays_to_its_known_event_list(tmp_path, monkeypatch, name):
    assert load(name)["claude_code_version"] == "2.1.281"
    records, _pairs, home = replay_fixture(name, tmp_path, monkeypatch)
    got = [
        (r["event"]["type"], r["event"]["actor"], r["event"]["class"], {k: v for k, v in r["event"]["body"].items() if k not in IDS})
        for r in records
    ]
    assert got == KNOWN[name]
    assert replay(records).intact
    assert not paths.drift_log(home).exists(), paths.drift_log(home).read_text()
    assert not paths.error_log(home).exists()


@pytest.mark.parametrize("name", sorted(KNOWN))
def test_each_witnessed_event_commits_to_the_envelope_field_it_records(tmp_path, monkeypatch, name):
    _records, pairs, _home = replay_fixture(name, tmp_path, monkeypatch)
    checked = 0
    for env, recs in pairs:
        for r in recs:
            e = r["event"]
            if e["class"] == "witnessed" and e["type"] in FIELD:
                assert e["digest"] == digest_only(FIELD[e["type"]](env))["digest"], (e["type"], env["hook_event_name"])
                checked += 1
            for k in ("tool_use_id", "prompt_id", "agent_id", "duration_ms"):
                if k in e["body"]:
                    assert e["body"][k] == env[k]
            if env["hook_event_name"] == "UserPromptSubmit":
                assert e["body"]["prompt_id"] == env["prompt_id"]
            if env["hook_event_name"] in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
                assert e["body"]["tool_use_id"] == env["tool_use_id"]
    assert checked >= 5


@pytest.mark.parametrize("name", sorted(KNOWN))
def test_every_sealed_event_commits_to_the_file_as_it_stood(tmp_path, monkeypatch, name):
    doc = load(name)
    records, _pairs, _home = replay_fixture(name, tmp_path, monkeypatch)
    expected = {
        "toy-analysis": lambda: {1: b"# toy analysis\n\nCount the lines in sample.txt. Be brief.\n", 5: b"alpha\nbeta\ngamma\n", 10: b"3", 13: b"3 lines"},
        "tool-failure": lambda: {},
        "subagent": lambda: {5: b"alpha\nbeta\n"},
        "edit-failure-notebook": lambda: {4: b"alpha\n", 7: doc["files_before"]["analysis.ipynb"].encode(),
                                          12: doc["files_after"]["analysis.ipynb"].encode()},
    }[name]()
    sealed = {r["seq"]: r["event"]["digest"] for r in records if r["event"]["class"] == "sealed"}
    assert sealed == {seq: _sha(b) for seq, b in expected.items()}


@pytest.mark.parametrize("name", sorted(KNOWN))
def test_tool_events_carry_the_ids_that_pair_them(tmp_path, monkeypatch, name):
    records, _pairs, _home = replay_fixture(name, tmp_path, monkeypatch)
    calls = [r["event"]["body"]["tool_use_id"] for r in records if r["event"]["type"] == "tool.call"]
    results = [r["event"]["body"]["tool_use_id"] for r in records if r["event"]["type"] == "tool.result"]
    assert sorted(calls) == sorted(results) and len(set(calls)) == len(calls)
    for i, r in enumerate(records):
        if r["event"]["type"] in ("file.read", "file.write"):
            assert r["event"]["body"]["tool_use_id"] == records[i - 1]["event"]["body"]["tool_use_id"]  # right after its result


def test_the_installed_hooks_are_the_ones_the_capture_saw_fire_that_record_something():
    fired = {e["hook_event_name"] for name in KNOWN for e in load(name)["events"]}
    # PostToolBatch repeats the tool events; SubagentStart/Stop add nothing the subagent's own tool events do not
    assert set(envelopes_.HOOK_EVENTS) == fired - {"PostToolBatch", "SubagentStart", "SubagentStop"}


def test_phase_0_content_is_digests_only(tmp_path, monkeypatch):
    records, _pairs, _home = replay_fixture("toy-analysis", tmp_path, monkeypatch)
    for r in records:
        e = r["event"]
        assert ("digest" in e and "content" not in e) or (e["type"] == "session.end" and e["content"] is None), e
