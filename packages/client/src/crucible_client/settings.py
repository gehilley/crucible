"""The Claude Code hooks block, installed at user level (docs/v1-audit.md §5 step 8).

Ported from v1's ``crucible_harness/settings.py`` and retargeted from a
project's ``.claude/settings.json`` to the user's ``~/.claude/settings.json``
(v1 ``settings.py:198-204``), so every session on the machine is recorded,
whatever directory it starts in.

The user's settings hold permissions, environment, a status line and their own
hooks. Only Crucible's own hook commands -- the ones whose program is
``crucible-hook`` -- are replaced; every other hook is kept where it is, in its
group, in order, and a group is dropped only when nothing of the user's is left
in it. A hooks block of a shape Claude Code would not read is refused, not
rewritten. Settings that disable all hooks are refused: nothing would be
recorded. If ``settings.json`` is a symlink, the file it points to is written.
The previous file is copied beside it before the first change.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
from pathlib import Path

from crucible_core import atomic

from .envelopes import HOOK_EVENTS, MATCHED_EVENTS, TOOL_MATCHER

HOOK_NAME = "crucible-hook"
TIMEOUT = 30


class SettingsError(Exception):
    """The user's Claude Code settings cannot be read as a settings object."""


def settings_path(home: Path | None = None) -> Path:
    return (home or Path.home()) / ".claude" / "settings.json"


def hooks_block(command: str) -> dict:
    entry = {"hooks": [{"type": "command", "command": command, "timeout": TIMEOUT}]}
    return {e: [{"matcher": TOOL_MATCHER, **entry} if e in MATCHED_EVENTS else entry] for e in HOOK_EVENTS}


def is_crucible_hook(hook: object) -> bool:
    """Whether one hook object runs Crucible's hook: its program, after an ``env -u NAME ...``
    and any ``NAME=value`` assignments, is ``crucible-hook``."""
    command = hook.get("command") if isinstance(hook, dict) else None
    if not isinstance(command, str):
        return False
    words = [w for w in _words(command)]
    if words and Path(words[0]).name == "env":
        words.pop(0)
        while len(words) >= 2 and words[0] == "-u":
            del words[:2]
    while words and "=" in words[0] and not words[0].startswith(("/", ".")):
        words.pop(0)
    return bool(words) and Path(words[0]).name == HOOK_NAME


def is_crucible_entry(entry: object) -> bool:
    """Whether a matcher group holds only Crucible's hooks."""
    hooks = entry.get("hooks") if isinstance(entry, dict) else None
    return isinstance(hooks, list) and bool(hooks) and all(is_crucible_hook(h) for h in hooks)


def _without_crucible(entry: object) -> object | None:
    """The group with Crucible's hooks taken out; None if nothing else was in it."""
    if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
        return entry
    kept = [h for h in entry["hooks"] if not is_crucible_hook(h)]
    if len(kept) == len(entry["hooks"]):
        return entry
    return {**entry, "hooks": kept} if kept else None


def _words(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def merge_hooks(existing: dict, block: dict) -> dict:
    if not isinstance(existing, dict):
        raise SettingsError("Claude Code settings must be a JSON object")
    merged = dict(existing)
    hooks = merged.get("hooks")
    if hooks is not None and not isinstance(hooks, dict):
        raise SettingsError("the 'hooks' key in Claude Code settings must be an object")
    hooks = dict(hooks or {})
    for event, entries in block.items():
        current = hooks.get(event, [])
        if not isinstance(current, list):
            raise SettingsError(f"the {event!r} hooks in Claude Code settings are not a list; refusing to rewrite them")
        kept = [g for g in (_without_crucible(e) for e in current) if g is not None]
        hooks[event] = [*kept, *entries]
    merged["hooks"] = hooks
    return merged


def read(home: Path | None = None, *, command: str | None = None) -> dict:
    """The user's settings as they are, refusing what install could not write into: with
    ``command``, only if installing its hooks would change the file (a rerun writes nothing)."""
    path = settings_path(home)
    try:
        text = path.read_text(encoding="utf-8")
        existing = json.loads(text) if text.strip() else {}
    except FileNotFoundError:  # no settings yet (or a link to none): install will create them
        writable(home)
        return {}
    except (OSError, ValueError) as exc:
        raise SettingsError(f"cannot read {path}: {exc}") from exc
    if not isinstance(existing, dict):
        raise SettingsError("Claude Code settings must be a JSON object")
    if existing.get("disableAllHooks") is True:
        raise SettingsError(f"{path} sets disableAllHooks: no hook would fire, so nothing would be recorded")
    merged = merge_hooks(existing, hooks_block(command or HOOK_NAME))  # refuses a hooks block of the wrong shape
    if command is None or merged != existing:
        writable(home)
    return existing


def writable(home: Path | None = None) -> None:
    """Refuse, before anything is written anywhere, settings that install could not write:
    the file (or the target a symlink names) and its backup are made in their directory."""
    import tempfile

    path = settings_path(home)
    target = path.resolve() if path.is_symlink() else path
    directory = target.parent
    probe_from = directory
    while not probe_from.exists():  # it will be created; the first existing parent must allow that
        if probe_from.is_symlink():  # a link to nothing (a dotfiles link not made yet): it cannot be created
            raise SettingsError(f"cannot write {target}: {probe_from} is a link that leads nowhere "
                                f"({os.readlink(probe_from)} does not resolve)")
        probe_from = probe_from.parent
    try:
        fd, name = tempfile.mkstemp(dir=probe_from, prefix=".crucible-write-check-")
        os.close(fd)
        os.unlink(name)
    except OSError as exc:
        raise SettingsError(f"cannot write {target}: {exc}") from exc


def install(command: str, home: Path | None = None) -> tuple[Path, bool]:
    """Write the hooks into the user's settings. Returns (path, whether it changed)."""
    path = settings_path(home)
    if path.is_symlink():
        path = path.resolve()  # the user's managed copy; replacing the link would cut it off
    try:
        text = path.read_text(encoding="utf-8")
        existing = json.loads(text) if text.strip() else {}
    except FileNotFoundError:
        text, existing = None, {}
    except (OSError, ValueError) as exc:
        raise SettingsError(f"cannot read {path}: {exc}") from exc
    if isinstance(existing, dict) and existing.get("disableAllHooks") is True:
        raise SettingsError(f"{path} sets disableAllHooks: no hook would fire, so nothing would be recorded")
    merged = merge_hooks(existing, hooks_block(command))
    if merged == existing:
        return path, False
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = path.with_name(path.name + ".before-crucible")
    if text is not None and not backup.exists():
        shutil.copy2(path, backup)
    atomic.write_json(path, merged, indent=2)
    return path, True


__all__ = ["HOOK_NAME", "SettingsError", "hooks_block", "install", "is_crucible_entry", "is_crucible_hook", "merge_hooks",
           "read", "settings_path"]
