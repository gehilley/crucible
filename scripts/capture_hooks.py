#!/usr/bin/env python3
"""Capture real Claude Code hook envelopes as replay fixtures (docs/v1-audit.md §5 step 6).

Ported from v1's ``scripts/capture_hooks.py``. What it does:

1. build a throwaway workspace whose ``.claude/settings.json`` installs one
   hook per event, each dumping its stdin verbatim to a nanosecond-named file;
2. run ``claude -p`` headless in it with the scenario's prompt;
3. order the dumps by when they were written, which is the order the client
   fired them in;
4. scrub the machine-specific paths -- the workspace becomes ``/WORKSPACE``,
   each transcript ``/TRANSCRIPTS/<n>.jsonl``, the home directory ``/HOME`` --
   and edit nothing else, checking both directions (every placeholder used,
   no real path left);
5. write one JSON document per scenario, labelled with the client version.

A scenario states the events and tools it must have observed, so a run in
which the model skipped a tool is refused rather than written as a shorter
fixture that still parses. Writing over an existing fixture needs
``--overwrite``.

    uv run python scripts/capture_hooks.py --out packages/client/tests/fixtures/hooks
    uv run python scripts/capture_hooks.py --scenario tool-failure --out /tmp/x --show-reply
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

WORKSPACE = "/WORKSPACE"
HOME = "/HOME"

#: Every hook event wired for the capture: the plan's list (docs/v1-audit.md
#: §5 step 6) and the 2.1.281 events that bear on what §4 records. The fixture
#: shows which of them a session actually fires.
EVENTS = (
    "SessionStart",
    "InstructionsLoaded",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PostToolBatch",
    "PermissionDenied",
    "SubagentStart",
    "SubagentStop",
    "PreCompact",
    "PostCompact",
    "Stop",
    "StopFailure",
    "SessionEnd",
)
MATCHED = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionDenied")

DUMP_HOOK = '''\
import os, sys, time
capture_dir = sys.argv[1]
raw = sys.stdin.read()
stamp = time.time_ns()
while True:
    try:
        fd = os.open(os.path.join(capture_dir, "%020d.json" % stamp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        break
    except FileExistsError:
        stamp += 1
with os.fdopen(fd, "w", encoding="utf-8") as out:
    out.write(raw)
'''


class CaptureError(RuntimeError):
    """A capture that cannot be trusted as a record of what the client sent."""


@dataclass(frozen=True)
class Scenario:
    name: str
    prompt: str
    files: dict[str, str]
    allowed_tools: tuple[str, ...]
    expect_events: tuple[str, ...]
    expect_tools: tuple[str, ...] = field(default_factory=tuple)
    #: What the capture showed that the envelopes alone do not say.
    note: str = ""


SCENARIOS = {
    # Read, Bash, Write and Edit, with a CLAUDE.md to load: the full capture path.
    "toy-analysis": Scenario(
        name="toy-analysis",
        prompt=(
            "Do exactly these steps and nothing else, then reply DONE. "
            "(1) Read the file sample.txt. (2) Use Bash to run: wc -l sample.txt "
            "(3) Write the line count, a single number, to count.txt. "
            "(4) Edit count.txt to append the word ' lines' after the number."
        ),
        files={
            "sample.txt": "alpha\nbeta\ngamma\n",
            "CLAUDE.md": "# toy analysis\n\nCount the lines in sample.txt. Be brief.\n",
        },
        allowed_tools=("Read", "Write", "Edit", "Bash(wc:*)"),
        expect_events=("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SessionEnd"),
        expect_tools=("Read", "Bash", "Write", "Edit"),
    ),
    # A subagent: its tool calls are recorded from its own transcript.
    "subagent": Scenario(
        name="subagent",
        prompt=(
            "Use the Agent tool exactly once, with subagent_type general-purpose, to have a subagent Read the "
            "file sample.txt and report its first line. Do not read the file yourself. Then reply DONE."
        ),
        files={"sample.txt": "alpha\nbeta\n"},
        allowed_tools=("Agent", "Task", "Read"),
        expect_events=("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SessionEnd"),
        expect_tools=("Read",),
    ),
    # A failed Edit of a file that exists, and a NotebookEdit.
    "edit-failure-notebook": Scenario(
        name="edit-failure-notebook",
        prompt=(
            "Do exactly these steps and nothing else, then reply DONE. (1) Read notes.txt. (2) Edit notes.txt, "
            "replacing the text 'omega' with 'beta' (it is not there, so the edit will fail; do not retry). "
            "(3) Read analysis.ipynb. (4) Use NotebookEdit to replace the source of its first cell with print(2)."
        ),
        files={
            "notes.txt": "alpha\n",
            "analysis.ipynb": json.dumps({"cells": [{"cell_type": "code", "execution_count": None, "id": "c1", "metadata": {},
                                                      "outputs": [], "source": ["print(1)"]}],
                                           "metadata": {}, "nbformat": 4, "nbformat_minor": 5}, indent=1) + "\n",
        },
        allowed_tools=("Read", "Edit", "NotebookEdit"),
        expect_events=("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SessionEnd"),
        expect_tools=("Read", "NotebookEdit"),
        note=(
            "On 2.1.281 an Edit whose old_string is not in the file is refused by the client's input validation "
            "before PreToolUse: no hook fires for it at all, so the record shows no Edit. Phase 1 records such "
            "calls as gaps."
        ),
    ),
    # Tools that fail: a missing file and a non-zero exit.
    "tool-failure": Scenario(
        name="tool-failure",
        prompt=(
            "Do exactly these steps and nothing else, then reply DONE. "
            "(1) Read the file missing.txt, which does not exist. "
            "(2) Use Bash to run exactly: exit 7 "
            "If a step fails, say so in one line and go on to the next."
        ),
        files={"sample.txt": "alpha\n"},
        allowed_tools=("Read", "Bash(exit:*)"),
        expect_events=("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUseFailure", "Stop", "SessionEnd"),
        expect_tools=("Read", "Bash"),
    ),
}


def client_version() -> str:
    out = subprocess.run(["claude", "--version"], capture_output=True, text=True, check=False).stdout.split()
    if not out:
        raise CaptureError("`claude --version` printed nothing; an unlabelled fixture is evidence about no version")
    return out[0]


def build(root: Path, scenario: Scenario, capture_dir: Path) -> None:
    for relative, contents in scenario.files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
    dump = root.parent / "dump_hook.py"  # outside the workspace, so the model never sees it
    dump.write_text(DUMP_HOOK, encoding="utf-8")
    command = f"{shlex.quote(sys.executable)} {shlex.quote(str(dump))} {shlex.quote(str(capture_dir))}"
    entry = {"hooks": [{"type": "command", "command": command, "timeout": 30}]}
    hooks = {e: [{"matcher": "*", **entry} if e in MATCHED else entry] for e in EVENTS}
    (root / ".claude").mkdir()
    (root / ".claude" / "settings.json").write_text(json.dumps({"hooks": hooks}, indent=2), encoding="utf-8")


def run(root: Path, scenario: Scenario, timeout: int) -> subprocess.CompletedProcess[str]:
    # The parent shell may itself be a Claude Code session; its markers must not leak in.
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDECODE", "CLAUDE_CODE_", "CRUCIBLE_"))}
    return subprocess.run(
        ["claude", "-p", scenario.prompt, "--permission-mode", "acceptEdits",
         "--allowedTools", ",".join(scenario.allowed_tools), "--strict-mcp-config"],
        cwd=root, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, check=False,
    )


def collect(capture_dir: Path) -> list[dict]:
    dumps = list(capture_dir.glob("*.json"))
    if strange := [p.name for p in dumps if not p.stem.isdigit()]:
        raise CaptureError(f"{strange} are not nanosecond-named dumps")
    out = []
    for path in sorted(dumps, key=lambda p: int(p.stem)):
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CaptureError(f"{path.name} is not JSON ({exc}); the hook transport moved") from exc
        if not isinstance(envelope, dict) or "hook_event_name" not in envelope:
            raise CaptureError(f"{path.name} carries no hook_event_name; the envelope shape moved")
        out.append(envelope)
    return out


def _transcripts(value, found: set[str]) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, str) and k.endswith("transcript_path"):
                found.add(v)
            else:
                _transcripts(v, found)
    elif isinstance(value, list):
        for v in value:
            _transcripts(v, found)


def scrub(envelopes: list[dict], root: Path, files: dict[str, str] | None = None) -> tuple[list[dict], dict[str, list], dict[str, str]]:
    """The envelopes, the transcripts they name, and the workspace's files, with every real path replaced."""
    found: set[str] = set()
    _transcripts(envelopes, found)
    mains = sorted({e["transcript_path"] for e in envelopes if isinstance(e.get("transcript_path"), str)})
    for e in envelopes:  # a subagent's transcript, where the hooks look for it
        if isinstance(e.get("agent_id"), str) and isinstance(e.get("transcript_path"), str):
            found.add(str(Path(e["transcript_path"]).with_suffix("") / "subagents" / f"agent-{e['agent_id']}.jsonl"))
    names = {t: f"/TRANSCRIPTS/{i}.jsonl" for i, t in enumerate(mains)}
    for t in sorted(found - set(mains)):
        parent = next((m for m in mains if t.startswith(str(Path(m).with_suffix("")) + "/")), None)
        names[t] = (names[parent][: -len(".jsonl")] + t[len(str(Path(parent).with_suffix(""))):]) if parent else f"/TRANSCRIPTS/other-{len(names)}.jsonl"
    replacements = sorted(names.items(), key=lambda kv: len(kv[0]), reverse=True)
    replacements += [(s, WORKSPACE) for s in sorted({str(root), str(root.resolve())}, key=len, reverse=True)]
    if any(c.isalnum() for c in str(Path.home())):  # a home of "/" (no home) would turn every "/" into /HOME
        replacements += [(str(Path.home()), HOME)]

    def clean(value):
        # A whole path only: /home/al is not /home/alice's start (nor /home/alé's), but a path may end
        # a sentence ("... directory is <root>."). A path run straight into a letter of a script
        # written without spaces (目录) is left, and the check then refuses it: fails closed.
        text = json.dumps(value, ensure_ascii=False)
        for real, placeholder in replacements:
            text = re.sub(re.escape(json.dumps(real, ensure_ascii=False)[1:-1]) + r"(?![\w-]|\.[\w-])",
                          lambda _m: placeholder, text)
        return json.loads(text)

    # A transcript carries far more than a hook reads -- the injected system
    # context included, which names the account -- so only what the hooks read
    # is kept: each assistant record's model and surface version, and the ids of its tool calls.
    transcripts = {}
    for real, placeholder in names.items():
        path = Path(real)
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        records = [json.loads(line) for line in lines if line.strip()]
        transcripts[placeholder] = [
            {"type": "assistant", **({"version": r["version"]} if isinstance(r.get("version"), str) else {}),
             "message": {"model": r["message"]["model"], "content": [
                {"type": "tool_use", "id": b["id"]} for b in r["message"].get("content") or []
                if isinstance(b, dict) and b.get("type") == "tool_use" and isinstance(b.get("id"), str)
            ]}}
            for r in records
            if r.get("type") == "assistant" and isinstance(r.get("message"), dict) and "model" in r["message"]
        ]
    return clean(envelopes), transcripts, clean(files or {})


def check_scrubbed(envelopes: list[dict], root: Path, transcripts: dict, files: dict[str, str] | None = None) -> None:
    files = files or {}
    text = json.dumps(envelopes, ensure_ascii=False) + json.dumps(transcripts, ensure_ascii=False)
    if WORKSPACE not in text:
        raise CaptureError("no envelope names the workspace; the scrub would have nothing to replay against")
    text += json.dumps(files, ensure_ascii=False)
    import re
    import socket

    home = str(Path.home())
    homes = {home, _account_home()} - {""}  # $HOME, and the password database's home when they differ
    suspects = {str(root), str(root.resolve()), _slug(str(root)), _slug(str(root.resolve()))}
    suspects |= {f for h in homes for f in (h, h.replace("/", "-"), _slug(h))}
    for real in suspects:  # as it reads, and as JSON writes it (a backslash, a quote)
        if not re.search(r"[A-Za-z0-9]", real):  # a home of "/" (no home) gives "/" and "-": they name no machine
            continue
        if real in text or json.dumps(real, ensure_ascii=False)[1:-1] in text:
            where = list(_occurrences({"events": envelopes, "transcripts": transcripts, "files_after": files}, real))[:5]
            raise CaptureError(f"a machine-specific string survived the scrub: {real!r} at {where}")
    # The user's name as a word, whatever it holds (`ec2-user`, `first.last`, `jörg`, `id-svc`),
    # in any case and Unicode form, and in the form Claude Code gives it in a project's
    # directory name (every character but letters and digits made '-'): in a path, tool
    # output (`ls -l`, `id`), an identifier (`<user>_env`), a file the run wrote, or prose.
    # Not inside a word. "The user's name" is every name this account goes by: USER,
    # LOGNAME, the password database's, and the home directory's last part. A match in a
    # value is let go only when it lies wholly inside one word (letters, digits, `_`) that
    # is one of the pinned schemas' own identifiers -- a user called "tool" is not named by
    # `tool_input` -- and is not itself one of those names. Keys are scanned whole: one is
    # skipped only at a schema position (an envelope's fields, PostToolBatch's calls, a kept
    # transcript record's) and only when it is exactly such an identifier; the transcript
    # reduction's own constants (`assistant`, `tool_use`) are skipped where it writes them.
    # A name that is a common word, or a word in some tool's own keys (`max` in
    # `max_results`) or in Claude Code's own paths (`subagents`, `agent`, `jsonl`), still
    # refuses: the check fails closed.
    import unicodedata

    def nfc(t: str) -> str:
        return unicodedata.normalize("NFC", t)

    # The machine's own name, and its first label, as words in any case (a host called `pi`).
    host = socket.gethostname()
    hosts = {h for h in (host, host.split(".")[0]) if re.search(r"[A-Za-z0-9]", h)}
    names = _user_names()
    forms = {f for n in names for f in (nfc(n), _slug(nfc(n)), _slug(n))}
    named = re.compile("|".join(rf"(?<![A-Za-z0-9]){re.escape(f)}(?![A-Za-z0-9])" for f in sorted(forms, key=len, reverse=True)),
                       re.IGNORECASE)
    # A host of six characters or more is found even run into more letters or digits (a container's
    # name is the start of its 64-hex id); a shorter one only as a word.
    hosted = re.compile("|".join(rf"(?<![A-Za-z0-9]){re.escape(h)}" + ("" if len(h) >= 6 else "(?![A-Za-z0-9])")
                                 for h in sorted(hosts, key=len, reverse=True)), re.IGNORECASE) if hosts else None
    identifiers = _schema_identifiers()
    for path, raw, exempt in _scanned(envelopes, transcripts, files, identifiers, names):
        raw = nfc(raw)
        tokens = [m.span() for m in PLACEHOLDER.finditer(raw)]
        # The scrub's own tokens are no one's name (`workspace`, `home`): a match wholly inside one is
        # let go. The text is searched as it is (`/HOMER` is not the token) and with the tokens taken
        # out (a name run into one, `x/HOMEzqxuser`).
        for value, inside in ((raw, lambda m: any(a <= m.start() and m.end() <= b for a, b in tokens)),
                              (PLACEHOLDER.sub(" ", raw), lambda m: False)):
            for h in hosted.finditer(value) if hosted is not None else ():
                if not inside(h):
                    raise CaptureError(f"a machine-specific string survived the scrub: the host name {h.group()!r} at {path}")
            for m in named.finditer(value):
                if not inside(m) and not _inside_exempt_word(value, m, exempt):
                    raise CaptureError(f"the user name {m.group()!r} (this account is {', '.join(sorted(names))}) "
                                       f"survived the scrub at {path}")


#: The tokens scrub() itself writes, and only those: the rest of a transcript's placeholder (a
#: subagent's file name, copied as it was) is scanned like anything else.
PLACEHOLDER = re.compile(r"/(?:WORKSPACE|HOME)|/TRANSCRIPTS/(?:other-)?\d+(?:\.jsonl)?")


def _account_home() -> str:
    """The password database's home for this account ("" if none, or one with no letter or digit)."""
    import pwd

    try:
        home = pwd.getpwuid(os.getuid()).pw_dir
    except (KeyError, AttributeError):
        return ""
    return home if re.search(r"[A-Za-z0-9]", home or "") else ""


def _user_names() -> frozenset[str]:
    """Every name this account goes by; refused if there is none to look for."""
    import pwd

    try:
        login = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        login = ""
    names = frozenset(n for n in (os.environ.get("USER", ""), os.environ.get("LOGNAME", ""), login, Path.home().name,
                                  Path(_account_home()).name) if n)
    if not names:
        raise CaptureError("cannot tell this account's name (no USER, LOGNAME, password entry or home): nothing to check")
    return names


def _slug(text: str) -> str:
    """Claude Code's name for a project directory: every character but letters and digits is '-'."""
    import re

    return re.sub(r"[^A-Za-z0-9]", "-", text)


def _inside_exempt_word(text: str, match, exempt: frozenset[str]) -> bool:
    """Whether ``match`` lies wholly inside one [A-Za-z0-9_]+ word of ``text`` that is in ``exempt``."""
    import re

    if not re.fullmatch(r"[A-Za-z0-9_]+", match.group()):
        return False  # it spans a separator or a letter outside ASCII: never a schema word
    start, end = match.start(), match.end()
    while start > 0 and re.match(r"[A-Za-z0-9_]", text[start - 1]):
        start -= 1
    while end < len(text) and re.match(r"[A-Za-z0-9_]", text[end]):
        end += 1
    return text[start:end] in exempt


def _schema_identifiers() -> frozenset[str]:
    """The pinned envelopes' field names, and the transcript reduction's own keys and values."""
    from crucible_client.envelopes import SCHEMAS

    fields = {k for spec in SCHEMAS.values() for k in (*spec.required, *spec.optional)}
    # tool_calls: PostToolBatch's field (captured, not installed); the rest: the kept transcript records.
    return frozenset(fields | {"tool_calls", "type", "version", "message", "model", "content", "id", "assistant", "tool_use"})


REDUCTION_CONSTANTS = frozenset({"assistant", "tool_use"})  # the `type` values scrub() writes itself


def _scanned(envelopes: list[dict], transcripts: dict, files: dict[str, str], identifiers: frozenset[str],
             names: frozenset[str]):
    """(path, text, exempt words) for every key and string a fixture would carry."""
    folded = {n.casefold() for n in names}  # in a value, this account's own names (in any case) are never schema words
    values = frozenset(i for i in identifiers if i.casefold() not in folded)
    for i, envelope in enumerate(envelopes):
        for k, v in envelope.items():  # an envelope's own fields
            if str(k) not in identifiers:
                yield f"/events[{i}]/<key>", str(k), frozenset()
            if k == "tool_calls" and isinstance(v, list):  # PostToolBatch: each call carries a tool event's fields
                for j, call in enumerate(v):
                    for ck, cv in (call.items() if isinstance(call, dict) else ()):
                        if str(ck) not in identifiers:
                            yield f"/events[{i}]/tool_calls[{j}]/<key>", str(ck), frozenset()
                        yield from _strings(cv, f"/events[{i}]/tool_calls[{j}]/{ck}", values)
                    if not isinstance(call, dict):
                        yield from _strings(call, f"/events[{i}]/tool_calls[{j}]", values)
                continue
            yield from _strings(v, f"/events[{i}]/{k}", values)
    for name, records in transcripts.items():
        yield "/transcripts/<key>", str(name), frozenset()
        # The reduction keeps only its own keys and constants (scrub()), the model, the version and tool ids.
        yield from _strings(records, f"/transcripts/{name}", values, keys=identifiers, constants=REDUCTION_CONSTANTS)
    for name, content in files.items():
        yield "/files_after/<key>", str(name), frozenset()
        yield f"/files_after/{name}", str(content), values


def _strings(value, path: str, exempt: frozenset[str], *, keys: frozenset[str] = frozenset(),
             constants: frozenset[str] = frozenset()):
    """Strings with ``exempt`` words let go. A key is scanned whole, and skipped only when it is
    exactly one of ``keys`` (none, in free-form data); a ``type`` value in ``constants`` is skipped."""
    if isinstance(value, dict):
        for k, v in value.items():
            if str(k) not in keys:
                yield f"{path}/<key>", str(k), frozenset()
            if k == "type" and v in constants:
                continue
            yield from _strings(v, f"{path}/{k}", exempt, keys=keys, constants=constants)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _strings(v, f"{path}[{i}]", exempt, keys=keys, constants=constants)
    elif isinstance(value, str):
        yield path, value, exempt


def _occurrences(value, needle: str, path: str = ""):
    if isinstance(value, dict):
        for k, v in value.items():
            if needle in str(k):
                yield f"{path}/<key {k!r}>"
            yield from _occurrences(v, needle, f"{path}/{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _occurrences(v, needle, f"{path}[{i}]")
    elif isinstance(value, str) and needle in value:
        i = value.index(needle)
        yield f"{path}: ...{value[max(0, i - 40): i + 40]!r}..."


def check_observed(envelopes: list[dict], scenario: Scenario) -> None:
    fired = {e["hook_event_name"] for e in envelopes}
    if missing := [e for e in scenario.expect_events if e not in fired]:
        raise CaptureError(f"{scenario.name}: these hooks never fired: {missing}")
    tools = {e.get("tool_name") for e in envelopes if e["hook_event_name"] == "PreToolUse"}
    if missing := [t for t in scenario.expect_tools if t not in tools]:
        raise CaptureError(f"{scenario.name}: the model never called {missing}")


def capture(scenario: Scenario, timeout: int) -> tuple[dict, str]:
    with tempfile.TemporaryDirectory(prefix="crucible-capture-") as tmp:
        base = Path(tmp)
        root, capture_dir = base / "workspace", base / "dumps"
        root.mkdir()
        capture_dir.mkdir()
        build(root, scenario, capture_dir)
        result = run(root, scenario, timeout)
        envelopes = collect(capture_dir)
        try:
            check_observed(envelopes, scenario)
        except CaptureError as exc:
            raise CaptureError(f"{exc}\n--- claude exit {result.returncode} ---\n{result.stdout}\n{result.stderr}") from exc
        written = {
            str(p.relative_to(root)): p.read_text(encoding="utf-8")
            for p in sorted(root.rglob("*")) if p.is_file() and ".claude" not in p.relative_to(root).parts
        }
        scrubbed, transcripts, files = scrub(envelopes, root, written)
        check_scrubbed(scrubbed, root, transcripts, files)
        doc = {
            "comment": (
                "Real Claude Code hook envelopes, captured by scripts/capture_hooks.py running `claude -p` "
                "headless. Paths are scrubbed to /WORKSPACE, /TRANSCRIPTS/<n>.jsonl and /HOME; nothing else in "
                "an envelope is edited. Each transcript keeps only what the hooks read from it: the model of "
                "each assistant record and the ids of its tool calls."
            ),
            "scenario": scenario.name,
            "prompt": scenario.prompt,
            "claude_code_version": client_version(),
            "captured": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files_before": scenario.files,
            "files_after": files,
            "events": scrubbed,
            "transcripts": transcripts,
            "note": scenario.note,
        }
        return doc, result.stdout


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="capture_hooks")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--scenario", choices=sorted(SCENARIOS), action="append")
    ap.add_argument("--overwrite", action="store_true", help="replace an existing fixture")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--show-reply", action="store_true")
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    for name in args.scenario or sorted(SCENARIOS):
        target = args.out / f"{name}.json"
        if target.exists() and not args.overwrite:
            print(f"capture_hooks: {target} exists; pass --overwrite to replace it", file=sys.stderr)
            return 2
        doc, reply = capture(SCENARIOS[name], args.timeout)
        target.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        fired = [e["hook_event_name"] for e in doc["events"]]
        print(f"{name}: {len(fired)} envelopes -> {target}\n  {' '.join(fired)}")
        if args.show_reply:
            print(f"  reply: {reply.strip()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
