"""What a hook reads from the Claude Code transcript: which model is speaking.

No hook envelope names the model (2.1.281 capture), but every assistant record
in the session's transcript (``transcript_path``, JSON lines) carries
``message.model``. The actor of a ``tool.call`` is ``model:<id>`` of the
assistant record that holds that ``tool_use`` block; of a ``response``, of the
last assistant record. The transcript is read backwards from its end, a bounded
amount, because a long session's transcript is large and a hook must be quick.

**PreToolUse fires before its record is written.** On 2.1.281 the assistant
record holding a tool call reaches the transcript about 0.1 s after the hook
starts (the first call of a session finds no assistant record at all), so
`tool_call_actor` waits for it, up to `TOOL_USE_WAIT` seconds. If it never
comes the actor is ``model:unknown``: the model of some other record would be a
guess, and a guess is not witnessed.

**A subagent keeps its own transcript.** Its tool envelopes carry ``agent_id``
and still name the main transcript; its records are in
``<main transcript without .jsonl>/subagents/agent-<agent_id>.jsonl``
(2.1.281 capture, tests/fixtures/hooks/subagent.json).
Ported, reduced to this one question, from v1's ``crucible_harness/transcript.py``.
"""

from __future__ import annotations

import json
import os
import re
import stat
import time
from pathlib import Path

CHUNK = 64 * 1024
MAX_READ = 8 * 1024 * 1024
TOOL_USE_WAIT = 2.0
POLL = 0.05
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}")
UNKNOWN = "model:unknown"


_AGENT_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


def subagent_transcript(transcript_path: str | os.PathLike, agent_id: str) -> Path | None:
    if not (isinstance(agent_id, str) and _AGENT_RE.fullmatch(agent_id)):
        return None
    return Path(transcript_path).with_suffix("") / "subagents" / f"agent-{agent_id}.jsonl"


def _lines_backwards(path: Path):
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):  # a FIFO would block the hook; a directory has no lines
            return
    except OSError:
        return
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        pos, tail, read = fh.tell(), b"", 0
        while pos > 0 and read < MAX_READ:
            step = min(CHUNK, pos)
            pos -= step
            fh.seek(pos)
            block = fh.read(step) + tail
            read += step
            lines = block.split(b"\n")
            tail = lines.pop(0)  # possibly a partial line; completed by the next block
            yield from reversed(lines)
        if pos == 0 and tail:
            yield tail


_VERSION_RE = re.compile(r"[0-9][0-9A-Za-z.+-]{0,63}")


def _record_of(raw: bytes, needle: bytes | None = None) -> dict | None:
    """``{"model", "version"}`` from an assistant record (holding ``needle``'s tool_use), or None."""
    if b'"assistant"' not in raw or (needle is not None and needle not in raw):
        return None
    try:
        record = json.loads(raw)
    except ValueError:
        return None
    message = record.get("message") if isinstance(record, dict) else None
    if not (isinstance(record, dict) and record.get("type") == "assistant" and isinstance(message, dict)):
        return None
    if needle is not None:
        content = message.get("content")
        ids = [b.get("id") for b in content if isinstance(b, dict) and b.get("type") == "tool_use"] if isinstance(content, list) else []
        if needle.decode() not in ids:
            return None
    model = message.get("model")
    if not (isinstance(model, str) and _MODEL_RE.fullmatch(model)):
        return None
    version = record.get("version")  # the surface's own version, on every record it writes
    return {"model": model, "version": version if isinstance(version, str) and _VERSION_RE.fullmatch(version) else None}


def _find(transcript_path, needle: bytes | None) -> dict | None:
    try:
        for raw in _lines_backwards(Path(transcript_path)):
            if (found := _record_of(raw, needle)) is not None:
                return found
    except OSError:
        return None
    return None


def latest_record(transcript_path: str | os.PathLike | None) -> dict | None:
    """``{"model", "version"}`` of the last assistant record, or None."""
    return _find(transcript_path, None) if transcript_path else None


def latest_model(transcript_path: str | os.PathLike | None) -> str | None:
    """The model id of the last assistant record, or None if there is none to read."""
    found = latest_record(transcript_path)
    return found["model"] if found else None


def tool_use_record(transcript_path: str | os.PathLike | None, tool_use_id: str, *, wait: float | None = None) -> dict | None:
    """``{"model", "version"}`` of the record holding ``tool_use_id``, waiting up to ``wait`` seconds for it."""
    if not transcript_path or not isinstance(tool_use_id, str) or not tool_use_id:
        return None
    deadline = time.monotonic() + (TOOL_USE_WAIT if wait is None else wait)
    needle = tool_use_id.encode()
    while True:
        if (found := _find(transcript_path, needle)) is not None:
            return found
        if time.monotonic() >= deadline:
            return None
        time.sleep(POLL)


def tool_use_model(transcript_path: str | os.PathLike | None, tool_use_id: str, *, wait: float | None = None) -> str | None:
    found = tool_use_record(transcript_path, tool_use_id, wait=wait)
    return found["model"] if found else None


def tool_call_source(transcript_path: str | os.PathLike | None, tool_use_id: str, *, agent_id: str | None = None,
                     wait: float | None = None) -> tuple[str, str | None]:
    """(actor, surface version) of a tool call: from the record that asked for it, in the
    subagent's own transcript when a subagent asked; ``model:unknown`` if none says."""
    if agent_id is not None:
        transcript_path = subagent_transcript(transcript_path, agent_id) if transcript_path else None
    found = tool_use_record(transcript_path, tool_use_id, wait=wait)
    return (f"model:{found['model']}", found["version"]) if found else (UNKNOWN, None)


def tool_call_actor(transcript_path: str | os.PathLike | None, tool_use_id: str, *, agent_id: str | None = None,
                    wait: float | None = None) -> str:
    return tool_call_source(transcript_path, tool_use_id, agent_id=agent_id, wait=wait)[0]


def response_source(transcript_path: str | os.PathLike | None) -> tuple[str, str | None]:
    """(actor, surface version) of a turn's response: the last assistant record."""
    found = latest_record(transcript_path)
    return (f"model:{found['model']}", found["version"]) if found else (UNKNOWN, None)


def model_actor(transcript_path: str | os.PathLike | None) -> str:
    """``model:<id>``; ``model:unknown`` when the transcript names none yet."""
    return response_source(transcript_path)[0]


__all__ = ["UNKNOWN", "latest_model", "latest_record", "model_actor", "response_source", "subagent_transcript",
           "tool_call_actor", "tool_call_source", "tool_use_model", "tool_use_record"]
