# Crucible

Crucible keeps an independent record of how a researcher works with an AI agent.
A client on the researcher's machine records each Claude Code session as a hash
chain. The chain covers every prompt, the model's reply at the end of each turn,
every tool call and its result, and each file read with Read or written with Write,
Edit, MultiEdit or NotebookEdit. A file that a shell command reads or writes shows
only as that command and its output. A background sender ships the chain to
a service, which keeps it in a write-once log and returns a signed, timestamped
receipt for each batch. Later, anyone can check a session's record: it is
**intact**, or **broken at event N**.

This repository holds Crucible's client, its verifier, and the service that holds
the record (ingest, the log, receipts and its API), under the MIT license, with
the recipe that builds each release. [SPEC.md](SPEC.md) governs the project's
scope.

**Status (phase 0).** The service runs at **https://log.cruciblehub.org**, from
release **0.1.0**. Its key and log id are published apart from it, at
**https://status.cruciblehub.org**. The service is run by the project's operator,
so it is not yet independent of them.

What the record holds, in this phase:

- A digest (sha256) of each piece of content (prompts, replies, tool inputs and
  outputs, file bytes), not the content itself. Anyone who guesses short or
  well-known content, such as a one-word prompt or a common file, can confirm the
  guess against its digest.
- In plain text: the path of each file the agent reads or writes and of each
  instruction file Claude Code loads (as `~/…` under your home directory, in full
  elsewhere), each tool's name, the model's id and Claude Code's version, and sizes,
  durations and times.
- Anyone who has a session's id, including anyone you give it to for checking, can
  download that session's record without signing in. The log is write-once: the
  record cannot be deleted.
- If a hook fails to record an event, it writes why to a local error log (Step 5)
  and the session goes on without that event. In this phase nothing in the record
  marks the gap, and the session still checks as intact.

The commands below are for release 0.1.0. The service's own page,
https://log.cruciblehub.org/, always gives the commands for the release it serves
now. If its commands differ from these, use its commands.

---

## Install the client, step by step

### Step 0: Check what you need

You need all four of these:

| Need | Check with | If it is missing |
|---|---|---|
| Linux or macOS | `uname -s` (prints `Linux` or `Darwin`) | Windows is not supported. |
| Python 3.11 or newer | `python3 --version` | Install it from your system's package manager or [python.org](https://www.python.org/downloads/). |
| [uv](https://docs.astral.sh/uv/) 0.8.5 or newer | `uv --version` | Install: `curl -LsSf https://astral.sh/uv/install.sh \| sh`. Update an older one: `uv self update`. |
| [Claude Code](https://claude.com/claude-code) | `claude --version` | Install it, and run it once, so that `~/.claude/` exists. |

Crucible is set up per user, so nothing here needs `sudo`.

### Step 1: Remove any earlier copy of the client

```sh
env -u UV_CONFIG_FILE uv tool uninstall --no-config crucible-client 2>/dev/null || true
```

If no earlier copy is installed, this prints nothing and does nothing.

### Step 2: Install the client, release 0.1.0

This is one command; copy all of it:

```sh
env -u UV_CONFIG_FILE -u UV_FIND_LINKS -u UV_OVERRIDE -u UV_EXCLUDE -u UV_INDEX -u UV_INDEX_URL -u UV_EXTRA_INDEX_URL -u UV_DEFAULT_INDEX -u UV_INSECURE_HOST uv tool install --no-config --reinstall --index https://log.cruciblehub.org/client/simple/ --index-strategy first-index --constraints https://log.cruciblehub.org/client/constraints.txt --with-executables-from crucible-verify crucible-client==0.1.0
```

What it does:

- Crucible's own packages come only from the service (`--index … --index-strategy
  first-index`), never from a public package index.
- No package source from your uv configuration or environment is used: `--no-config`,
  and the `env -u` list, which unsets every variable that could add or replace one.
- The packages Crucible depends on come from PyPI, at the versions this release was
  built and tested with (`--constraints`).
- It installs five commands: `crucible`, `crucible-hook`, `crucible-send` and
  `crucible-liveness` from the client, and `crucible-verify` from the verifier. It
  ends with `Installed 4 executables: crucible, crucible-hook, crucible-liveness,
  crucible-send`.

If you reach PyPI only through a mirror, put `UV_DEFAULT_INDEX=<your mirror>` just
before `uv` in this command, after the `env -u` list. If your network needs its own
TLS certificates, add `UV_NATIVE_TLS=1` there too.

### Step 3: Check that the commands are on your PATH

```sh
command -v crucible
command -v crucible-verify
```

Each should print a path, usually in `~/.local/bin`. If they print nothing (Step 2
may also have warned that the directory `is not on your PATH`), add uv's tool
directory to your PATH:

```sh
uv tool update-shell
```

Then open a new terminal and run the two `command -v` lines again.

### Step 4: Connect this machine to the service

This registers your key in the service's write-once log. Read what the record holds
(above) before you run it.

```sh
env -u PYTHONPATH -u PYTHONHOME crucible install https://log.cruciblehub.org
```

It asks for nothing else. It does four things:

1. It makes your researcher key, in `~/.local/state/crucible/`, readable only by
   you. If you already have one, it keeps it. (If you set an absolute
   `XDG_STATE_HOME`, the directory is `$XDG_STATE_HOME/crucible/` instead. The hooks'
   command in `~/.claude/settings.json` names the exact directory after
   `CRUCIBLE_HOME=`. Wherever this README says `~/.local/state/crucible`, read
   that directory.)
2. It fetches the service's public key and pins it: every receipt from then on must
   be signed by that key. It registers your key with the service.
3. It starts the sender in the background. On Linux the sender is a systemd user
   service and on macOS a launchd agent, and both start again at login. On macOS 13
   and later, the system may tell you that a background item was added: that is the
   sender. Leave it allowed under System Settings > General > Login Items.
4. It adds Crucible's hooks to `~/.claude/settings.json`. Your own settings and hooks
   are kept. If the file already existed, the first install saves a copy of it, as
   it was, beside it as `settings.json.before-crucible`.

When it succeeds, it prints four lines like these:

```text
crucible: generated researcher key sha256:…
crucible: sending to https://log.cruciblehub.org, service key sha256:7481d57aac6be48a8df7196788e3b87a405a6b9fc9f5320539c2e02e7752f887
crucible: hooks written to /home/you/.claude/settings.json
crucible: sender: systemd user service crucible-sender.service
```

On macOS the last line names `launchd agent org.cruciblehub.sender` instead. When
you run the command again, the first line says `kept` for `generated`, and the third
says `already in` for `written to` if the hooks were already there.

The service key in the second line must be
`sha256:7481d57aac6be48a8df7196788e3b87a405a6b9fc9f5320539c2e02e7752f887`, the key
published at https://status.cruciblehub.org/service.json. If it is not, stop and
uninstall (see below).

Running the same command again is safe. It keeps your key and your registration,
replaces Crucible's hooks in place, and leaves one sender running.

On a Linux machine with no systemd user manager (some containers and remote shells),
the sender runs as a plain background process instead, and `crucible install` says
so. That process does not start again at login or after a reboot. To restart it,
run the Step 4 command again.

### Step 5: Use Claude Code as you always do

Start a new Claude Code session. Sessions from before Step 4 are not recorded, and
a session that was already open may not be either, so quit any that were open
(including one you ran Step 4 from). There is nothing else to run. Each session is
recorded as it happens, and the sender ships it to the service in the background.

To see that the sender is running:

- Linux: `systemctl --user status crucible-sender`
- macOS: `launchctl print gui/$(id -u)/org.cruciblehub.sender | head`
- A plain background process: `ps -o args= -p "$(cat ~/.local/state/crucible/sender.pid)" | grep crucible-send`
  (it prints the sender's command line if it is running, and nothing otherwise;
  after a reboot it is not running until you run Step 4 again)

Where to look when something goes wrong:

- `~/.local/state/crucible/sender.jsonl`: what the sender could not send, and why
  (retries, and batches the service refused), one JSON line per problem.
- `~/.local/state/crucible/hook-errors.jsonl`: events a hook could not record.
- If the sender cannot start at all: `journalctl --user -u crucible-sender` on Linux,
  and `~/.local/state/crucible/sender.err` otherwise.

---

## Check a session

A session is named by its Claude Code session id, which is the name of the session's
transcript file: `~/.claude/projects/<project>/<session-id>.jsonl`. The id of your
most recent session is:

```sh
basename "$(ls -t ~/.claude/projects/*/*.jsonl | head -1)" .jsonl
```

First get the service's key from the status host, which is served apart from the
service:

```sh
curl -fsS https://status.cruciblehub.org/service.pub.json > service.pub.json
```

Then check the session:

```sh
env -u PYTHONPATH -u PYTHONHOME crucible-verify https://log.cruciblehub.org/v2/sessions/<session-id>/export --service-key service.pub.json
```

The check uses the key from the status host, not the key the service presents. The
machine that runs the service cannot change what the status host holds. A key you
get only from the service you are checking does not, on its own, prove anything.
The `crucible-verify` you run was itself installed from the service (Step 2), so in
this phase the check also rests on the release the service serves: the key from the
status host guards against a different key, not against a different verifier.

The first line of the report is the verdict:

- `intact`: every event is in the chain, and every one is anchored by a receipt
  signed with the service's key.
- `broken at event N`: the record differs from what the service sealed, at event N
  or after it. Receipts anchor batches of events, so N is the first event of the
  batch that holds the difference.
- `could_not_check(<reason>)`: something the check needs is missing; the reason
  names it. This is never counted as a pass. See Troubleshooting for the reasons.

The second line gives how many events the service holds for the session. The export
holds only what the sender has shipped and the service has sealed, so `intact`
covers those events and no more. Events the sender has not shipped yet are simply
not in it, so check a session a minute or more after it ends.

`crucible-verify` exits with 0 for intact, 1 for broken, 2 for could_not_check and
3 for not_applicable. The report is the evidence; the exit status is not. Exit 4 is
not a verdict: the record or the key could not be read (see Troubleshooting).

---

## Update the client

First quit your Claude Code sessions, and run the update in a plain terminal, not
through Claude Code. From Step 1 until Step 2 finishes, the program the hooks run is
not installed: anything a session does then is not recorded, and nothing in the
record shows it is missing.

Then run Steps 1, 2 and 4 again, with the commands the service's page
(https://log.cruciblehub.org/) gives for its current release. `crucible install`
restarts the sender on the new code. For a sender run as a plain background
process, stop it first with the `kill` line under Uninstall.

Do not use `uv tool upgrade`. It re-resolves with whatever package indexes your
environment names, and could take a Crucible package from one of them.

---

## Uninstall

1. Stop the sender, and remove what starts it:
   - Linux: `systemctl --user disable --now crucible-sender`, then
     `rm ~/.config/systemd/user/crucible-sender.service` and
     `systemctl --user daemon-reload`
   - macOS: `launchctl bootout gui/$(id -u)/org.cruciblehub.sender`, then
     `rm ~/Library/LaunchAgents/org.cruciblehub.sender.plist`
   - A plain background process (this kills the pid only if it is still the sender):
     `pid=$(cat ~/.local/state/crucible/sender.pid); ps -o args= -p "$pid" | grep -q crucible-send && kill "$pid"`
2. Delete the entries in `~/.claude/settings.json` whose command runs
   `crucible-hook`. If `settings.json.before-crucible` exists, it is the file as it
   was before your first install. Moving it back over `settings.json` also undoes
   any settings you changed since, so do that only if you changed none. Then delete
   `settings.json.before-crucible`.
3. Remove the client:
   `env -u UV_CONFIG_FILE uv tool uninstall --no-config crucible-client`
4. Delete `~/.local/state/crucible/`, which holds your key and your local copy of
   the record.

The record the service holds stays there: the log is write-once.

---

## Troubleshooting

| What you see | What to do |
|---|---|
| `crucible: command not found` | Step 3: `uv tool update-shell`, then open a new terminal. |
| `uv` says an option is unknown | Your uv is older than 0.8.5: `uv self update`. |
| Step 2 cannot reach PyPI | Use your mirror: `UV_DEFAULT_INDEX=<mirror>` just before `uv` in Step 2 (and `UV_NATIVE_TLS=1` if your network needs its own certificates). |
| `crucible: … disableAllHooks …` | Your Claude Code settings turn hooks off, so nothing would be recorded. Remove `disableAllHooks` from `~/.claude/settings.json`, then run Step 4 again. |
| `crucible: … asks to wait …; trying again in N s` | The service is rate-limiting key registrations. The command waits and tries again by itself; let it run. |
| `crucible: the service refused the key registration (429) …` | It is still rate-limited after three tries. Wait a few minutes, then run Step 4 again. |
| `crucible: … presents key …, not the pinned …` | The service shows a key other than the one this machine pinned at its first install. Stop: receipts under another key would not be the service's word. Check the key at https://status.cruciblehub.org/service.json. |
| `crucible-verify` says `could_not_check(no service public key was given …)` | Add `--service-key service.pub.json` to the command. |
| `crucible-verify` says `could_not_check(the checkpoint is signed by key sha256:…, and no key with that id was given)` | The receipts are signed by a key other than the one in your service.pub.json. Fetch it again and compare its id with https://status.cruciblehub.org/service.json. If the status host's key is not the one the receipts name, stop: those receipts are not the service's word. |
| `crucible-verify` says `could_not_check(… format version …)` | Your client is older than the service. See Update the client. |
| `crucible-verify: cannot read …: HTTP Error 404: Not Found` (exit 4) | The service holds nothing for that session: it started before Step 4, the id is wrong, or the sender has not sent it yet. Wait a minute; if it persists, look in `~/.local/state/crucible/sender.jsonl` (Step 5). |
| `crucible-verify: cannot read …: HTTP Error 503` (exit 4) | A receipt is still being signed. Try again in a minute. |
| The report's event count is lower than you expect | The sender has not shipped the rest. Wait a minute and check again; if it stays short, look in `~/.local/state/crucible/sender.jsonl`. |
| On macOS, sessions never reach the service | Check that the sender is allowed under System Settings > General > Login Items, then run Step 4 again. |
| Anything else `crucible install` refuses | It prints the reason after `crucible:` and exits with status 2. Fix what it names and run Step 4 again; a rerun keeps whatever is already right. |

---

## This repository

- [SPEC.md](SPEC.md): what Crucible is, and the rules the build follows.
- `packages/`: the client (`client`), the verifier (`verify`), the service
  (`service`), and the chain and key code they share (`chain`, `core`).
- `scripts/release.py`, `deploy/Dockerfile`, `deploy/build-constraints.txt` and
  `deploy/README.md`: the release recipe. A release is built from an annotated tag
  of this repository; the same tag builds the same wheels, byte for byte, and
  `RELEASE.json` records each one's sha256 and the tagged commit. The service serves
  its release's `RELEASE.json` at `/client/RELEASE.json`, so for a release built
  from a tag here you can rebuild the wheels it serves and compare. Release 0.1.0
  was built before the service's code joined this repository; its client-side
  package sources are this repository's tag `v0.1.0`.
- `corpus/`: records with known faults, which the verifier is tested against.
- `scripts/capture_hooks.py` and `scripts/capture_matcher_routing.py`: the tools
  that captured the real Claude Code hook envelopes the client's tests replay.

To run the tests, with [uv](https://docs.astral.sh/uv/):

```sh
uv run pytest
```

The deployment of https://log.cruciblehub.org (its cloud resources and the
operator's procedures), and the project's design records, are kept privately.
References in the code to `docs/…` name those records.

## License

MIT. See [LICENSE](LICENSE).
