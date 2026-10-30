#!/usr/bin/env python3
"""Capture which tools a hook ``matcher`` routes, on the real client (docs/v1-audit.md §5 step 6).

Ported from v1's ``scripts/capture_matcher_routing.py``. The matcher decides
whether a tool hook runs at all, so a matcher that misses a tool records
nothing about it while every test below that layer passes. Method: run
``claude -p`` headless in a workspace whose settings install one PreToolUse
entry per candidate matcher, each logging the tool name it fired for, over runs
that call file tools, Bash and an MCP tool; write down what fired.

    uv run python scripts/capture_matcher_routing.py --out packages/client/tests/fixtures/hooks/matcher-routing.json

The fixture is read by ``packages/client/tests/test_matcher_routing.py``,
which checks that the matcher the client installs routed every tool observed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

MATCHERS = {"star": "*", "empty": "", "dot-star": ".*", "alternation": "Bash|Edit|Write|Read"}

PROBE = """import json, sys
label = sys.argv[1]
name = json.load(sys.stdin).get("tool_name", "")
with open(sys.argv[2] + "." + label, "a", encoding="utf-8") as fh:
    fh.write(name + "\\n")
"""

TINY_MCP = """
import json, sys
TOOL = {"name": "probe_ping", "description": "Return pong.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}}
for line in sys.stdin:
    if not line.strip():
        continue
    msg = json.loads(line)
    method, mid = msg.get("method"), msg.get("id")
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "probe", "version": "0"}}
    elif method == "tools/list":
        result = {"tools": [TOOL]}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "pong"}]}
    else:
        result = {}
    if mid is not None:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}) + "\\n")
        sys.stdout.flush()
"""

RUNS = [
    ("file and utility tools",
     "Do exactly these tool calls in order and nothing else, then reply DONE: (1) Read the file sample.txt, "
     "(2) use the Grep tool with pattern alpha and path . , (3) use the Glob tool with pattern '*.txt', "
     "(4) run the Bash command 'echo hi'.",
     ["Read", "Grep", "Glob", "Bash(echo:*)"]),
    ("an MCP tool",
     "Call the probe_ping MCP tool once (it takes no arguments), then reply DONE. Do not call any other tool.",
     ["mcp__probe__probe_ping"]),
]


def capture(base: Path) -> dict:
    root = base / "workspace"
    root.mkdir()
    probe, server, log = base / "probe.py", base / "tiny_mcp.py", base / "probe.log"
    probe.write_text(PROBE, encoding="utf-8")
    server.write_text(TINY_MCP, encoding="utf-8")
    (root / "sample.txt").write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
    (root / ".claude").mkdir()
    entries = [
        {"matcher": m, "hooks": [{"type": "command", "command": f"{sys.executable} {probe} {label} {log}", "timeout": 20}]}
        for label, m in MATCHERS.items()
    ]
    (root / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": entries}}, indent=2), encoding="utf-8")
    mcp = base / "mcp.json"
    mcp.write_text(json.dumps({"mcpServers": {"probe": {"command": sys.executable, "args": [str(server)]}}}), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDECODE", "CLAUDE_CODE_", "CRUCIBLE_"))}
    for _label, prompt, allowed in RUNS:
        argv = ["claude", "-p", prompt, "--permission-mode", "acceptEdits", "--allowedTools", ",".join(allowed),
                "--strict-mcp-config"]
        if any(a.startswith("mcp__") for a in allowed):
            argv += ["--mcp-config", str(mcp)]
        subprocess.run(argv, cwd=root, env=env, capture_output=True, text=True, timeout=600, check=False)
    fired: dict[str, set[str]] = {}
    for label in MATCHERS:
        path = Path(f"{log}.{label}")
        for name in (path.read_text(encoding="utf-8").split() if path.is_file() else []):
            fired.setdefault(name, set()).add(label)
    version = subprocess.run(["claude", "--version"], capture_output=True, text=True, check=False).stdout.split()[0]
    return {
        "comment": "Which PreToolUse matcher fired for which tool, observed by scripts/capture_matcher_routing.py "
                   "running `claude -p` headless.",
        "claude_code_version": version,
        "captured": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "matchers": MATCHERS,
        "tools_called": sorted({a.split("(")[0] for _l, _p, allowed in RUNS for a in allowed}),
        "observations": [{"tool": t, "fired": sorted(labels)} for t, labels in sorted(fired.items())],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="capture_matcher_routing")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--overwrite", action="store_true")
    args = ap.parse_args(argv)
    if args.out.exists() and not args.overwrite:
        print(f"capture_matcher_routing: {args.out} exists; pass --overwrite to replace it", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="crucible-matcher-") as tmp:
        doc = capture(Path(tmp))
    observed = {o["tool"] for o in doc["observations"]}
    if missing := [t for t in doc["tools_called"] if t not in observed]:
        print(f"capture_matcher_routing: no matcher fired for {missing}; the model skipped a call, or no hook ran",
              file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(doc["observations"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
