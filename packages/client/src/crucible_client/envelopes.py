"""The Claude Code hook envelope, pinned to what the client actually sends.

Ported from v1's ``crucible_harness/envelopes.py`` and re-transcribed from the
2.1.281 capture (``tests/fixtures/hooks``, written by
``scripts/capture_hooks.py``), not from the documentation: the capture wins
wherever the two disagree.

**Required** is what a hook reads into the event it records; without it the
event would say something it does not know, so that event is not recorded.
**Optional** is the rest of what was observed, type-checked when present.
Anything else is drift: a new field is how a client change announces itself.

**Drift never blocks** (docs/v1-audit.md §5 step 6). `problems` only reports;
the hook writes the report to the client's local drift log and goes on.
Phase 1 records drift in the chain as a ``gap``.

Nothing here raises: an envelope comes from a process this client does not
control, so every value is untrusted.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

PINNED_VERSION = "2.1.281"

Validator = Callable[[Any], str | None]


def _text(v: Any) -> str | None:
    return None if isinstance(v, str) and v else "must be a non-empty string"


def _any_text(v: Any) -> str | None:
    return None if isinstance(v, str) else "must be a string"  # "" is a real prompt or reply


def _object(v: Any) -> str | None:
    return None if isinstance(v, dict) else "must be an object"


def _array(v: Any) -> str | None:
    return None if isinstance(v, list) else "must be an array"


def _flag(v: Any) -> str | None:
    return None if isinstance(v, bool) else "must be a boolean"


def _int(v: Any) -> str | None:
    return None if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else "must be a non-negative integer"


def _anything(_v: Any) -> str | None:
    return None  # `tool_response` is tool-specific; its presence is what is pinned


@dataclass(frozen=True)
class EnvelopeSpec:
    event: str
    required: dict[str, Validator]
    optional: dict[str, Validator] = field(default_factory=dict)

    def problems(self, envelope: dict) -> list[str]:
        found = []
        if missing := sorted(self.required.keys() - envelope.keys()):
            found.append(f"missing {', '.join(missing)}")
        known = self.required.keys() | self.optional.keys()
        if unknown := sorted(repr(k)[:48] for k in envelope if not isinstance(k, str) or k not in known):
            found.append(f"unknown {', '.join(unknown[:8])}")
        for name, check in (*self.required.items(), *self.optional.items()):
            if name in envelope and (reason := check(envelope[name])) is not None:
                found.append(f"{name} {reason}")
        return found


_COMMON = {"hook_event_name": _text, "session_id": _text, "transcript_path": _text, "cwd": _text}
_UI = {"permission_mode": _text, "effort": _object, "prompt_id": _text}
_TOOL = {"tool_name": _text, "tool_input": _object, "tool_use_id": _text}
_AGENT = {"agent_id": _text, "agent_type": _text}  # on a subagent's tool events

SCHEMAS: dict[str, EnvelopeSpec] = {
    "SessionStart": EnvelopeSpec("SessionStart", {**_COMMON}, {"source": _text}),
    "InstructionsLoaded": EnvelopeSpec(
        "InstructionsLoaded", {**_COMMON, "file_path": _text}, {"memory_type": _text, "load_reason": _text},
    ),
    "UserPromptSubmit": EnvelopeSpec("UserPromptSubmit", {**_COMMON, "prompt": _any_text}, {**_UI}),
    "PreToolUse": EnvelopeSpec("PreToolUse", {**_COMMON, **_TOOL}, {**_UI, **_AGENT}),
    "PostToolUse": EnvelopeSpec(
        "PostToolUse", {**_COMMON, **_TOOL, "tool_response": _anything}, {**_UI, **_AGENT, "duration_ms": _int},
    ),
    "PostToolUseFailure": EnvelopeSpec(
        "PostToolUseFailure", {**_COMMON, **_TOOL, "error": _any_text},
        {**_UI, **_AGENT, "duration_ms": _int, "is_interrupt": _flag},
    ),
    "Stop": EnvelopeSpec(
        "Stop", {**_COMMON, "last_assistant_message": _any_text},
        {**_UI, "stop_hook_active": _flag, "background_tasks": _array, "session_crons": _array},
    ),
    "SessionEnd": EnvelopeSpec("SessionEnd", {**_COMMON}, {"reason": _text, "prompt_id": _text}),
}

#: The hooks the client installs: every event the 2.1.281 capture showed firing
#: that carries something §4 records (PostToolBatch repeats the tool events).
HOOK_EVENTS = tuple(SCHEMAS)

#: The tool hooks take a matcher, and ``*`` is the one observed to route every
#: tool, MCP tools included (tests/fixtures/hooks/matcher-routing.json).
MATCHED_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")
TOOL_MATCHER = "*"


def problems(envelope: object) -> list[str]:
    """What is wrong with ``envelope`` against the pinned schema; empty if nothing."""
    if not isinstance(envelope, dict):
        return [f"the envelope is not an object but {type(envelope).__name__}"]
    spec = SCHEMAS.get(envelope.get("hook_event_name")) if isinstance(envelope.get("hook_event_name"), str) else None
    if spec is None:
        return [f"hook_event_name {repr(envelope.get('hook_event_name'))[:48]} is not one this client records"]
    return spec.problems(envelope)


def readable(envelope: dict) -> bool:
    """Whether every required field is present and well formed, so the event can be recorded."""
    spec = SCHEMAS.get(envelope.get("hook_event_name"))
    return spec is not None and all(n in envelope and c(envelope[n]) is None for n, c in spec.required.items())


__all__ = ["HOOK_EVENTS", "MATCHED_EVENTS", "PINNED_VERSION", "SCHEMAS", "TOOL_MATCHER", "EnvelopeSpec", "problems", "readable"]
