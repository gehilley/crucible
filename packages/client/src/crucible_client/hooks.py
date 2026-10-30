"""Claude Code hooks that record SPEC.md §4 events (docs/v1-audit.md §5 step 6).

``crucible-hook`` is the command every hook runs. It reads one envelope from
stdin, appends the §4 events it shows to the client's local chain -- all of
one envelope's events in one transaction, so nothing lands between a tool's
result and its file event -- and **always exits 0**: there is no gate, no
session to open, no version guard and no identity check. A hook that fails
writes why to the local error log and the session goes on; an envelope that
has drifted from the pinned shape is recorded as far as it can be and the
drift written to the local drift log (`envelopes`).

What each hook records (phase 0: content as a digest and a note)::

    SessionStart          session.start     tool:claude-code  witnessed
    InstructionsLoaded    context.injected  tool:claude-code  sealed (the file as read from disk)
    UserPromptSubmit      prompt            human             witnessed
    PreToolUse            tool.call         model:<id>        witnessed
    PostToolUse           tool.result       tool:<name>       witnessed
                          file.read         tool:Read         sealed     (after Read)
                          file.write        tool:<name>       sealed     (after Write, Edit, NotebookEdit)
    PostToolUseFailure    tool.result       tool:<name>       witnessed  (body.failed true)
    Stop                  response          model:<id>        witnessed  (last_assistant_message)
    SessionEnd            session.end       tool:claude-code  witnessed

A tool call's model is the one in the transcript record that asked for it --
the subagent's own transcript for a subagent's call -- or ``model:unknown``; a
response's, the last assistant record's. ``body.version`` is the version the
surface itself writes on that record.

**A sealed file is the file as the hook found it on disk**, after the tool ran:
the bytes on disk, never a reconstruction. Claude Code itself does not write
exactly what a tool was given (it keeps a file's encoding, and for Edit its
line endings and quote style), and another hook running beside this one (a
formatter on every edit) may already have changed the file, so a sealed write
says what the disk held, and the tool call says what the tool was asked to
do.

The chain session is Claude Code's ``session_id``. A path in a body is written
as ``~/...`` under the home directory and as the absolute path elsewhere; a
path names a file, never its contents.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import time
import traceback
from pathlib import Path
from typing import Any

from crucible_chain.events import EventError, digest_only, draft
from crucible_chain.store import ChainStore

from . import envelopes, paths
from .transcript import response_source, tool_call_source

SURFACE = "tool:claude-code"
READS = ("Read",)
WRITES = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}
MAX_FILE = 256 * 1024 * 1024  # larger files are recorded by the tool event alone
CHUNK = 1024 * 1024


def _homes() -> list[Path]:
    home = Path.home()
    return [home] if home.resolve() == home else [home, home.resolve()]


def _shown_path(value: str, cwd: str) -> str:
    try:
        p = _resolve(value, cwd)
        for home in _homes():
            if p == home or home in p.parents:
                return "~" if p == home else "~/" + str(p.relative_to(home))
        return str(p)
    except (ValueError, OSError):
        return value


def _resolve(value: str, cwd: str) -> Path:
    """The file a tool's path names, as Claude Code expands it: ``~`` is the home directory."""
    if value == "~" or value.startswith("~/"):
        return Path.home() / value[2:]
    p = Path(value)
    return p if p.is_absolute() else Path(cwd) / p


def _file_digest(path: Path) -> dict | None:
    """``{digest, note}`` for the file's bytes as they are on disk now, streamed; or None."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
            return None
        h, size = hashlib.sha256(), 0
        while chunk := os.read(fd, CHUNK):
            h.update(chunk)
            size += len(chunk)
        return {"digest": "sha256:" + h.hexdigest(), "note": {"reason": "digest_only", "of": "bytes", "size": size}}
    except OSError:
        return None
    finally:
        os.close(fd)


def _content(value: Any) -> dict:
    """``{digest, note}`` for an envelope value: its JCS form, or, for a value JCS
    cannot encode (an integer past 2^53, a lone surrogate), its JSON text."""
    try:
        return digest_only(value)
    except EventError:
        text = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
        return {"digest": "sha256:" + hashlib.sha256(text).hexdigest(), "note": {"reason": "digest_only", "of": "json-text", "size": len(text)}}


def _event(type_: str, actor: str, cls: str, body: dict, value: Any = None, *, sealed: dict | None = None) -> dict:
    d = sealed or _content(value)
    return draft(type_, actor, cls, body, digest=d["digest"], note=d["note"])


def _tool_body(env: dict, **extra: Any) -> dict:
    body = {"tool": env["tool_name"], "tool_use_id": env["tool_use_id"]}
    if isinstance(env.get("duration_ms"), int) and not isinstance(env.get("duration_ms"), bool):
        body["duration_ms"] = env["duration_ms"]
    for k in ("agent_id", "agent_type"):
        if isinstance(env.get(k), str):
            body[k] = env[k]
    return {**body, **extra}


def _file_events(env: dict) -> list[dict]:
    tool, args, cwd = env["tool_name"], env["tool_input"], env["cwd"]
    key = "file_path" if tool in READS else WRITES.get(tool)
    target = args.get(key) if key else None
    if not isinstance(target, str) or not target:
        return []
    on_disk = _file_digest(_resolve(target, cwd))
    body = {"path": _shown_path(target, cwd), "tool_use_id": env["tool_use_id"]}
    if on_disk is None:
        return []
    if tool in READS:
        return [_event("file.read", f"tool:{tool}", "sealed", body, sealed=on_disk)]
    return [_event("file.write", f"tool:{tool}", "sealed", body, sealed=on_disk)]


class _Partial(Exception):
    """Some of an envelope's events could not be built; the rest still are recorded."""

    def __init__(self, drafts: list, failures: list[str]) -> None:
        super().__init__("; ".join(failures))
        self.drafts, self.failures = drafts, failures


def events_for(env: dict) -> list:
    """The §4 event drafts an envelope shows, in order, each built on its own so that
    one that cannot be built does not take the others with it. ``env`` is `envelopes.readable`."""
    name, cwd = env["hook_event_name"], env["cwd"]
    builders: list = []
    if name == "SessionStart":
        body = {"surface": "claude-code"}
        if isinstance(env.get("source"), str):
            body["source"] = env["source"]
        builders.append(lambda: _event("session.start", SURFACE, "witnessed", body, {"cwd": cwd}))
    elif name == "InstructionsLoaded":
        body = {"path": _shown_path(env["file_path"], cwd)}
        for k in ("memory_type", "load_reason"):
            if isinstance(env.get(k), str):
                body[k] = env[k]
        sealed = _file_digest(_resolve(env["file_path"], cwd))
        if sealed is None:  # gone before it could be read: say only what the envelope said
            builders.append(lambda: _event("context.injected", SURFACE, "witnessed", body, {"file_path": env["file_path"]}))
        else:
            builders.append(lambda: _event("context.injected", SURFACE, "sealed", body, sealed=sealed))
    elif name == "UserPromptSubmit":
        body = {"prompt_id": env["prompt_id"]} if isinstance(env.get("prompt_id"), str) else {}
        builders.append(lambda: _event("prompt", "human", "witnessed", body, env["prompt"]))
    elif name == "PreToolUse":
        def call():
            actor, version = tool_call_source(env["transcript_path"], env["tool_use_id"], agent_id=env.get("agent_id"))
            body = _tool_body(env, **({"version": version} if version else {}))
            return _event("tool.call", actor, "witnessed", body, env["tool_input"])

        builders.append(call)
    elif name == "PostToolUse":
        builders.append(lambda: _event("tool.result", f"tool:{env['tool_name']}", "witnessed", _tool_body(env), env["tool_response"]))
        builders.append(lambda: _file_events(env))
    elif name == "PostToolUseFailure":
        extra = {"failed": True}
        if isinstance(env.get("is_interrupt"), bool):
            extra["interrupted"] = env["is_interrupt"]
        builders.append(lambda: _event("tool.result", f"tool:{env['tool_name']}", "witnessed", _tool_body(env, **extra), {"error": env["error"]}))
    elif name == "Stop":
        def respond():
            actor, version = response_source(env["transcript_path"])
            return _event("response", actor, "witnessed", {"version": version} if version else {}, env["last_assistant_message"])

        builders.append(respond)
    elif name == "SessionEnd":
        body = {"reason": env["reason"]} if isinstance(env.get("reason"), str) else {}
        # Nothing is captured at the end but the reason: content null, not a digest of a stand-in.
        builders.append(lambda: draft("session.end", SURFACE, "witnessed", body, content=None, keep_content=True))
    drafts, failures = [], []
    for build in builders:
        try:
            made = build()
            drafts += made if isinstance(made, list) else [made]
        except Exception as exc:  # noqa: BLE001 -- one event that cannot be built costs only itself
            failures.append(f"{type(exc).__name__}: {exc}")
    if failures:
        raise _Partial(drafts, failures)
    return drafts


def record(env: object, *, home: Path | None = None) -> list:
    """Append what ``env`` shows to the local chain; return the records appended."""
    home = home or paths.client_home()
    drift = envelopes.problems(env)
    appended, failed = [], None
    if isinstance(env, dict) and envelopes.readable(env):
        try:
            drafts = events_for(env)
        except _Partial as part:
            drafts, failed = part.drafts, part
        if drafts:
            with ChainStore(paths.chain_path(home)) as store:
                appended = store.append_all(env["session_id"], drafts)
    # Logged after recording, each on its own: a log that cannot be written never costs an event.
    if drift:
        _try_log(paths.drift_log(home), {"event": env.get("hook_event_name") if isinstance(env, dict) else None,
                                         "pinned": envelopes.PINNED_VERSION, "problems": drift})
    if failed is not None:
        _try_log(paths.error_log(home), {"event": env.get("hook_event_name"), "error": str(failed)})
    return appended


def _try_log(path: Path, entry: dict) -> None:
    try:
        _log(path, entry)
    except OSError:
        pass


def _log(path: Path, entry: dict) -> None:
    """One JSON line, appended in a single write (local only; never part of the chain)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = (json.dumps({"at": time.time_ns() // 1000, **entry}, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    """``crucible-hook``: read one envelope from stdin and record it. Always exits 0."""
    home = None
    try:
        home = paths.client_home()
        raw = sys.stdin.read()
        try:
            env = json.loads(raw)
        except (ValueError, RecursionError) as exc:
            _try_log(paths.drift_log(home), {"event": None, "problems": [f"stdin is not JSON: {str(exc)[:200]}"]})
            return 0
        record(env, home=home)
    except Exception as exc:  # noqa: BLE001 -- a hook never stops the session
        try:
            _log(paths.error_log(home), {"error": f"{type(exc).__name__}: {exc}", "trace": traceback.format_exc(limit=6)})
        except Exception:  # noqa: BLE001
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
