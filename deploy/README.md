# Crucible

Crucible keeps an independent record of how a researcher works with an AI
agent. This service, **{service}**, holds that record.

On your machine, Crucible records each Claude Code session as a hash chain:
every prompt and response, every tool call and its result, and every file the
agent reads or writes. A background sender ships it here. The service keeps
it in a write-once log, and returns a signed, timestamped receipt for each
batch. Later, anyone can check a session's record: it is **intact**, or
**broken at event N**.

In this first phase, the record holds a digest of each piece of content (its
sha256), not the content itself. The service is run by the project's
operator, so it is not yet independent of them.

## What you need

- Linux or macOS
- [Claude Code](https://claude.com/claude-code)

The installer gets the rest: [uv](https://docs.astral.sh/uv/) 0.8.5 or newer if you
don't have it, and, through uv, Python 3.11 or newer if you don't have that.

## Install

One command:

```sh
curl -fsSL {service_url}/install.sh | sh
```

Or, with wget: `wget -qO- {service_url}/install.sh | sh`.

It checks that this service's key is the one published apart from it, at
[{published}/service.json]({published}/service.json), and installs nothing if it is
not. Then it runs the three commands below. To see what it would do without changing
anything: `curl -fsSL {service_url}/install.sh | CRUCIBLE_INSTALL_DRY_RUN=1 sh`. To
read it before running it: `curl -fsSL {service_url}/install.sh -o install.sh`, then
`sh install.sh`.

To run the three commands yourself instead (they need uv 0.8.5 or newer):

```sh
env -u UV_CONFIG_FILE uv tool uninstall --no-config crucible-client 2>/dev/null || true
env -u UV_CONFIG_FILE -u UV_FIND_LINKS -u UV_OVERRIDE -u UV_EXCLUDE -u UV_INDEX -u UV_INDEX_URL -u UV_EXTRA_INDEX_URL -u UV_DEFAULT_INDEX -u UV_INSECURE_HOST uv tool install --no-config --reinstall --index {service_url}/client/simple/ --index-strategy first-index --constraints {service_url}/client/constraints.txt --with-executables-from crucible-verify crucible-client=={version}
env -u PYTHONPATH -u PYTHONHOME crucible install {service_url}
```

The first two commands install release {version} of the client. Crucible's
own packages come only from this service, never from a public package index:
any copy you had installed before is removed first, and no package source
from your uv configuration or environment is used (`--no-config`, and the
`env -u` list). The packages they depend on come from PyPI, at the versions
this release was built and tested with. If you reach PyPI only through a
mirror, put `UV_DEFAULT_INDEX=<your mirror>` just before `uv` in the second
command, after the `env -u` list (and `UV_NATIVE_TLS=1` if your network needs
its own certificates).

To change the client later, run all three commands again, as the README this
service then serves gives them; `crucible install` restarts the sender on the
new code (a sender run as a plain background process: stop it first with the
`kill` line under Uninstall). Do not use `uv tool upgrade`: it re-resolves
with whatever indexes your environment names, and could take a Crucible
package from one of them.

`crucible install` asks for nothing else. It does four things:

1. It makes your key, in `~/.local/state/crucible/`, readable only by you.
2. It registers the key with this service.
3. It adds Crucible's hooks to `~/.claude/settings.json`. Your own settings
   and hooks are kept, and the file as it was is saved beside it as
   `settings.json.before-crucible`.
4. It starts the sender in the background: a systemd user service on Linux,
   a launchd agent on macOS. Both start again at login.

After that, use Claude Code as you always do. There is nothing else to run.

On a Linux machine with no systemd user manager (some containers and remote
shells have none), the sender runs as a plain background process instead, and
`crucible install` says so. That process does not start again at login or
after a reboot; to restart it then, run the Install block's last command,
`env -u PYTHONPATH -u PYTHONHOME crucible install {service_url}`, again.

The client's files are listed, with their sha256, at
[{service_url}/client/]({service_url}/client/).

## Check a session

Each session is named by its Claude Code session id. It is the name of the
session's transcript file, `~/.claude/projects/<project>/<session-id>.jsonl`.

```sh
curl -fsS {published}/service.pub.json > service.pub.json
env -u PYTHONPATH -u PYTHONHOME crucible-verify {service_url}/v2/sessions/<session-id>/export --service-key service.pub.json
```

The service's key is `{key_id}`, and its log is `{log_id}`. Both are also
published at [{published}/service.json]({published}/service.json). That host
is served apart from this service, and the machine that runs the service
cannot change what it holds. The command above checks the record against the
key from there. A key you get only from the service you are checking does not,
on its own, prove anything.

The first line of the report is the verdict:

- `intact`: every event is in the chain, and every one is anchored by a
  receipt signed with the service's key.
- `broken at event N`: the record differs from what the service sealed, at
  event N or after it. Receipts anchor batches of events, so N is the first
  event of the batch that holds the difference.
- `could_not_check(<reason>)`: something the check needs is missing, such as
  events that are not anchored yet. The reason names it. This is never
  counted as a pass.

`crucible-verify` exits with 0 for intact, 1 for broken, 2 for
could_not_check and 3 for not_applicable. The report is the evidence; the
exit status is not.

## Uninstall

1. Stop the sender, and remove what starts it:
   - Linux: `systemctl --user disable --now crucible-sender`, then
     `rm ~/.config/systemd/user/crucible-sender.service` and
     `systemctl --user daemon-reload`
   - macOS: `launchctl bootout gui/$(id -u)/org.cruciblehub.sender`, then
     `rm ~/Library/LaunchAgents/org.cruciblehub.sender.plist`
   - A sender started as a plain background process:
     `kill $(cat ~/.local/state/crucible/sender.pid)`
2. Restore `~/.claude/settings.json` from `settings.json.before-crucible`,
   or delete the entries whose command runs `crucible-hook`.
3. Remove the client with `env -u UV_CONFIG_FILE uv tool uninstall --no-config crucible-client`.
4. Delete `~/.local/state/crucible/`, which holds your key and your local
   copy of the record.

The record this service holds stays here: the log is write-once.
