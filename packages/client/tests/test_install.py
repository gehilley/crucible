"""``crucible install <service-address>`` on a fresh HOME (docs/v1-audit.md §5 step 8):
one command gives hooks, a registered key and a running sender; a rerun is
idempotent; no address is a refusal. The sender is spawned as a process
(``CRUCIBLE_SERVICE_MANAGER=spawn``): a test never touches the user's own
service manager."""

from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from crucible_chain.store import ChainStore
from crucible_client import config, daemon, settings
from crucible_client.envelopes import HOOK_EVENTS, MATCHED_EVENTS, TOOL_MATCHER

BIN = Path(sys.executable).parent
SESSION = "5a1c3e2b-0000-4000-8000-0000000000bb"


@pytest.fixture
def fresh(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if k not in ("CRUCIBLE_HOME", "XDG_STATE_HOME")}
    env.update(HOME=str(home), CRUCIBLE_SERVICE_MANAGER="spawn")
    yield home, env
    daemon.stop_spawned(home / ".local" / "state" / "crucible")


def crucible(env, *args):
    return subprocess.run([str(BIN / "crucible"), *args], capture_output=True, text=True, env=env, timeout=120)


def client_home(home: Path) -> Path:
    return home / ".local" / "state" / "crucible"


def fire(command: str, envelope: dict) -> None:
    r = subprocess.run(command, shell=True, input=json.dumps(envelope), capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr


def wait_for(predicate, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return False


def test_one_command_gives_hooks_a_registered_key_and_a_running_sender(fresh, ephemeral_service):
    home, env = fresh
    r = crucible(env, "install", ephemeral_service.url)
    assert r.returncode == 0, r.stderr

    # hooks, at user level, for every event, matching every tool
    hooks = json.loads((home / ".claude" / "settings.json").read_text())["hooks"]
    assert set(hooks) == set(HOOK_EVENTS)
    for event, [entry] in hooks.items():
        assert entry.get("matcher") == (TOOL_MATCHER if event in MATCHED_EVENTS else None)
    command = hooks["UserPromptSubmit"][0]["hooks"][0]["command"]

    # a key, private to the user, registered with the service
    ch = client_home(home)
    key_file = config.key_path(ch)
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    cfg = config.load(ch)
    assert cfg.key.key_id in ephemeral_service.service.keys
    assert cfg.service == ephemeral_service.url and cfg.service_key.key_id == ephemeral_service.key.key_id

    # a running sender: what a hook records reaches the service with no further command
    base = {"session_id": SESSION, "cwd": str(home), "transcript_path": str(home / "t.jsonl")}
    fire(command, {**base, "hook_event_name": "SessionStart", "source": "startup"})
    fire(command, {**base, "hook_event_name": "UserPromptSubmit", "prompt": "hello", "prompt_id": "p1"})

    def anchored():
        with ChainStore(ch / "chain.sqlite") as store:
            return store.last_receipted_seq(SESSION) == 1

    assert wait_for(anchored), (ch / "sender.err").read_text() if (ch / "sender.err").exists() else "no sender log"
    assert ephemeral_service.service.sessions[SESSION].next_seq == 2


def test_a_rerun_changes_nothing(fresh, ephemeral_service):
    home, env = fresh
    assert crucible(env, "install", ephemeral_service.url).returncode == 0
    ch = client_home(home)
    before = {
        "key": config.key_path(ch).read_bytes(),
        "settings": (home / ".claude" / "settings.json").read_bytes(),
        "pid": daemon.pid_path(ch).read_text(),
        "log": ephemeral_service.service.log.size,
    }
    r = crucible(env, "install", ephemeral_service.url)
    assert r.returncode == 0, r.stderr
    assert "kept researcher key" in r.stdout and "hooks already in" in r.stdout and "already running" in r.stdout
    after = {
        "key": config.key_path(ch).read_bytes(),
        "settings": (home / ".claude" / "settings.json").read_bytes(),
        "pid": daemon.pid_path(ch).read_text(),
        "log": ephemeral_service.service.log.size,
    }
    assert after == before  # the registration resent got its original receipt: nothing appended


def test_no_address_is_a_refusal_and_installs_nothing(fresh):
    home, env = fresh
    r = crucible(env, "install")
    assert r.returncode == 2 and "no default service" in r.stderr
    assert not (home / ".claude").exists() and not client_home(home).exists()


@pytest.mark.parametrize("address,why", [
    ("log.cruciblehub.org", "not a service address"), ("http://example.org", "plain http"), ("ftp://x", "not a service address"),
    ("https://x/?q=1", "query or fragment"), ("", "no default service"),
])
def test_an_address_that_is_not_a_service_address_is_refused(fresh, address, why):
    home, env = fresh
    r = crucible(env, "install", address)
    assert r.returncode == 2 and why in r.stderr, r.stderr
    assert not (home / ".claude").exists()


def test_an_unreachable_service_writes_no_hooks(fresh):
    home, env = fresh
    r = crucible(env, "install", "http://127.0.0.1:9")
    assert r.returncode == 2 and "cannot reach" in r.stderr
    assert not (home / ".claude" / "settings.json").exists()


def test_a_service_presenting_another_key_is_refused_not_re_pinned(fresh, ephemeral_service):
    from crucible_core.keys import PrivateKey

    home, env = fresh
    assert crucible(env, "install", ephemeral_service.url).returncode == 0
    ch = client_home(home)
    config.save(ch, ephemeral_service.url, PrivateKey.generate("service").public())  # as if the first install had seen another key
    r = crucible(env, "install", ephemeral_service.url)
    assert r.returncode == 2 and "not the pinned" in r.stderr


def test_an_expected_key_the_service_does_not_present_is_refused_before_anything_is_written(fresh, ephemeral_service,
                                                                                           service_key):
    home, env = fresh
    r = crucible(env, "install", ephemeral_service.url, "--expect-key", "sha256:" + "0" * 64)
    assert r.returncode == 2 and "not the expected" in r.stderr and "nothing was installed" in r.stderr
    assert not client_home(home).exists() and not (home / ".claude").exists()
    bad = crucible(env, "install", ephemeral_service.url, "--expect-key", "not-a-key")
    assert bad.returncode == 2 and "is not a key id" in bad.stderr
    ok = crucible(env, "install", ephemeral_service.url, "--expect-key", service_key.key_id)
    assert ok.returncode == 0, ok.stderr
    assert f"service key {service_key.key_id}" in ok.stdout


def test_the_users_own_settings_and_hooks_are_kept(fresh, ephemeral_service):
    home, env = fresh
    (home / ".claude").mkdir()
    own = {"model": "opus", "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-own-hook"}]}],
                                      "Notification": [{"hooks": [{"type": "command", "command": "notify-me"}]}]}}
    (home / ".claude" / "settings.json").write_text(json.dumps(own))
    assert crucible(env, "install", ephemeral_service.url).returncode == 0
    merged = json.loads((home / ".claude" / "settings.json").read_text())
    assert merged["model"] == "opus" and merged["hooks"]["Notification"] == own["hooks"]["Notification"]
    pre = merged["hooks"]["PreToolUse"]
    assert pre[0] == own["hooks"]["PreToolUse"][0] and settings.is_crucible_entry(pre[1]) and len(pre) == 2
    assert json.loads((home / ".claude" / "settings.json.before-crucible").read_text()) == own


def test_settings_that_are_not_an_object_are_refused_untouched(fresh, ephemeral_service):
    home, env = fresh
    (home / ".claude").mkdir()
    (home / ".claude" / "settings.json").write_text("[1, 2]")
    r = crucible(env, "install", ephemeral_service.url)
    assert r.returncode == 2 and "JSON object" in r.stderr
    assert (home / ".claude" / "settings.json").read_text() == "[1, 2]"


# --- the service managers, without touching the user's ---------------------------------------


def test_the_systemd_unit_runs_the_sender_and_restarts_it(tmp_path, monkeypatch):
    monkeypatch.setenv("CRUCIBLE_SERVICE_MANAGER", "systemd")
    ran = []

    def runner(argv):
        ran.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    what = daemon.start("/opt/crucible/bin/crucible-send", tmp_path / "state", run=runner, user_home=tmp_path)
    unit = (tmp_path / ".config" / "systemd" / "user" / daemon.UNIT).read_text()
    assert 'ExecStart="/opt/crucible/bin/crucible-send"' in unit and "Restart=always" in unit
    assert f'Environment="CRUCIBLE_HOME={tmp_path / "state"}"' in unit and "WantedBy=default.target" in unit
    assert ["systemctl", "--user", "enable", "--now", daemon.UNIT] in ran and what.startswith("systemd")


def test_the_launchd_agent_runs_the_sender_at_load_and_keeps_it_alive(tmp_path, monkeypatch):
    import plistlib

    monkeypatch.setenv("CRUCIBLE_SERVICE_MANAGER", "launchd")
    ran = []
    daemon.start("/opt/crucible/bin/crucible-send", tmp_path / "state", run=lambda a: ran.append(a) or subprocess.CompletedProcess(a, 0, "", ""),
                 user_home=tmp_path)
    plist = plistlib.loads((tmp_path / "Library" / "LaunchAgents" / f"{daemon.LABEL}.plist").read_bytes())
    assert plist["ProgramArguments"][-1] == "/opt/crucible/bin/crucible-send" and plist["KeepAlive"] and plist["RunAtLoad"]
    assert any(a[:2] == ["launchctl", "bootstrap"] for a in ran)


def test_a_failing_service_manager_is_a_refusal(tmp_path, monkeypatch):
    monkeypatch.setenv("CRUCIBLE_SERVICE_MANAGER", "systemd")
    with pytest.raises(daemon.DaemonError, match="failed"):
        daemon.start("/x/crucible-send", tmp_path, run=lambda a: subprocess.CompletedProcess(a, 1, "", "no user bus"), user_home=tmp_path)


# --- from the fresh review of steps 7-8 ----------------------------------------------------------


def test_a_users_hook_in_a_group_crucible_shares_survives_a_rerun(fresh, ephemeral_service):
    home, env = fresh
    assert crucible(env, "install", ephemeral_service.url).returncode == 0
    path = home / ".claude" / "settings.json"
    data = json.loads(path.read_text())
    data["hooks"]["PreToolUse"][0]["hooks"].append({"type": "command", "command": "/usr/local/bin/block-rm-rf"})
    data["hooks"]["Stop"].append({"hooks": [{"type": "command", "command": "notify-send done --icon ~/icons/crucible-hook"}]})
    path.write_text(json.dumps(data))
    assert crucible(env, "install", ephemeral_service.url).returncode == 0
    after = json.loads(path.read_text())["hooks"]
    pre = [h["command"] for g in after["PreToolUse"] for h in g["hooks"]]
    assert "/usr/local/bin/block-rm-rf" in pre and sum(settings.is_crucible_hook({"command": c}) for c in pre) == 1
    assert any("notify-send" in h["command"] for g in after["Stop"] for h in g["hooks"])


def _fake_systemctl(tmp_path, *, fails: str) -> Path:
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir(exist_ok=True)
    tool = bin_dir / "systemctl"
    tool.write_text(f"#!/bin/sh\ncase \"$*\" in *{fails}*) echo 'Failed to connect to bus: No medium found' >&2; exit 1;; esac\nexit 0\n")
    tool.chmod(0o755)
    return bin_dir


def test_a_service_manager_that_fails_leaves_no_hooks_behind(fresh, ephemeral_service, tmp_path):
    home, env = fresh
    env = {**env, "CRUCIBLE_SERVICE_MANAGER": "systemd", "PATH": f"{_fake_systemctl(tmp_path, fails='daemon-reload')}:{env['PATH']}"}
    r = crucible(env, "install", ephemeral_service.url)
    assert r.returncode == 2 and "Failed to connect" in r.stderr
    assert not (home / ".claude" / "settings.json").exists()


def test_systemctl_without_a_user_manager_falls_back_to_a_spawned_sender(fresh, ephemeral_service, tmp_path):
    home, env = fresh
    env = {k: v for k, v in env.items() if k != "CRUCIBLE_SERVICE_MANAGER"}
    env["PATH"] = f"{_fake_systemctl(tmp_path, fails='show-environment')}:{env['PATH']}"
    r = crucible(env, "install", ephemeral_service.url)
    assert r.returncode == 0, r.stderr
    assert "not started at login" in r.stdout


def test_a_stale_pid_file_does_not_stop_a_sender_being_started(fresh, ephemeral_service):
    from crucible_client.sender import sender_running

    home, env = fresh
    ch = client_home(home)
    ch.mkdir(parents=True)
    daemon.pid_path(ch).write_text(f"{os.getpid()}\n")  # a live process that is not a sender
    assert crucible(env, "install", ephemeral_service.url).returncode == 0
    assert wait_for(lambda: sender_running(ch), timeout=15)


def test_a_symlinked_settings_file_keeps_its_link_and_its_target_gets_the_hooks(fresh, ephemeral_service):
    home, env = fresh
    (home / "dotfiles").mkdir()
    target = home / "dotfiles" / "claude-settings.json"
    target.write_text('{"model": "opus"}')
    (home / ".claude").mkdir()
    (home / ".claude" / "settings.json").symlink_to(target)
    assert crucible(env, "install", ephemeral_service.url).returncode == 0
    assert (home / ".claude" / "settings.json").is_symlink()
    assert "hooks" in json.loads(target.read_text()) and json.loads(target.read_text())["model"] == "opus"


@pytest.mark.parametrize("content,why", [
    ('{"hooks": {"Stop": {"hooks": [{"command": "say done"}]}}}', "not a list"),
    ('{"disableAllHooks": true}', "disableAllHooks"),
])
def test_settings_install_cannot_honestly_write_into_are_refused_untouched(fresh, ephemeral_service, content, why):
    home, env = fresh
    (home / ".claude").mkdir()
    (home / ".claude" / "settings.json").write_text(content)
    r = crucible(env, "install", ephemeral_service.url)
    assert r.returncode == 2 and why in r.stderr
    assert (home / ".claude" / "settings.json").read_text() == content
    assert not (client_home(home) / "config.json").exists()  # refused before anything was registered


def test_a_relative_crucible_home_is_made_absolute_in_the_hook_command(fresh, ephemeral_service, tmp_path):
    home, env = fresh
    env = {**env, "CRUCIBLE_HOME": "state/crucible"}
    r = subprocess.run([str(BIN / "crucible"), "install", ephemeral_service.url], capture_output=True, text=True,
                       env=env, timeout=120, cwd=home)
    assert r.returncode == 0, r.stderr
    try:
        command = json.loads((home / ".claude" / "settings.json").read_text())["hooks"]["Stop"][0]["hooks"][0]["command"]
        assert f"CRUCIBLE_HOME={home / 'state' / 'crucible'} " in command
    finally:
        daemon.stop_spawned(home / "state" / "crucible")


def test_a_service_that_hangs_up_on_registration_is_a_refusal_not_a_traceback(tmp_path, monkeypatch, ephemeral_service, capsys):
    from crucible_client import cli

    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    monkeypatch.setenv("CRUCIBLE_SERVICE_MANAGER", "spawn")
    monkeypatch.delenv("CRUCIBLE_HOME", raising=False)
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    def hangs_up(url, body):
        raise ConnectionResetError("Remote end closed connection without response")

    monkeypatch.setattr(cli, "http_post", hangs_up)
    assert cli.main(["install", ephemeral_service.url]) == 2
    assert "cannot reach the service" in capsys.readouterr().err


@pytest.mark.parametrize("state", ["existing", "missing", "dangling-link", "dangling-claude-dir"])
def test_settings_install_cannot_write_are_refused_before_anything_starts(fresh, ephemeral_service, state):
    from crucible_client.sender import sender_running

    home, env = fresh
    if state == "dangling-claude-dir":  # ~/.claude a link whose target is not made yet
        (home / ".claude").symlink_to(home / "dotfiles" / "claude")
        r = crucible(env, "install", ephemeral_service.url)
        assert r.returncode == 2 and "cannot write" in r.stderr and "leads nowhere" in r.stderr
        assert not (client_home(home) / "config.json").exists() and ephemeral_service.service.log.size == 1
        return
    (home / ".claude").mkdir()
    if state == "existing":
        (home / ".claude" / "settings.json").write_text('{"theme": "dark"}')
    elif state == "dangling-link":  # a managed copy not made yet
        (home / ".claude" / "settings.json").symlink_to(home / ".claude" / "managed" / "settings.json")
    (home / ".claude").chmod(0o555)  # e.g. left root-owned after `sudo claude`
    try:
        r = crucible(env, "install", ephemeral_service.url)
        assert r.returncode == 2 and "cannot write" in r.stderr
        assert not (client_home(home) / "config.json").exists() and not sender_running(client_home(home)) if client_home(home).exists() else True
        assert ephemeral_service.service.log.size == 1  # nothing registered
    finally:
        (home / ".claude").chmod(0o755)


def test_a_rerun_with_the_hooks_in_place_needs_no_write_access(fresh, ephemeral_service):
    home, env = fresh
    assert crucible(env, "install", ephemeral_service.url).returncode == 0
    before = (home / ".claude" / "settings.json").read_bytes()
    (home / ".claude").chmod(0o555)
    try:
        r = crucible(env, "install", ephemeral_service.url)
        assert r.returncode == 0, r.stderr
        assert "hooks already in" in r.stdout and (home / ".claude" / "settings.json").read_bytes() == before
    finally:
        (home / ".claude").chmod(0o755)


def test_a_rate_limited_registration_is_waited_out(tmp_path, ephemeral_service, monkeypatch):
    from crucible_client import cli
    from crucible_core.keys import PrivateKey

    answers = [(429, {"retry-after": "7"}, {"error": "rate_limited", "detail": "too many"}), None]
    real = cli.http_post

    def limited_once(url, body):
        answer = answers.pop(0)
        return answer if answer is not None else real(url, body)

    monkeypatch.setattr(cli, "http_post", limited_once)
    slept = []
    home = tmp_path / "client"
    home.mkdir()
    key = PrivateKey.generate("researcher")
    key.write(config.key_path(home))
    cli.register(ephemeral_service.url, home, key, sleep=slept.append)
    assert slept == [7.0] and config.load(home).service == ephemeral_service.url


def test_a_long_retry_after_is_waited_out_only_up_to_the_cap(tmp_path, ephemeral_service, monkeypatch, capsys):
    from crucible_client import cli
    from crucible_core.keys import PrivateKey

    answers = [(429, {"retry-after": "3600"}, {"error": "rate_limited", "detail": "too many requests from the address x"}), None]
    real = cli.http_post
    monkeypatch.setattr(cli, "http_post", lambda url, body: answers.pop(0) or real(url, body))
    slept = []
    home = tmp_path / "client"
    home.mkdir()
    key = PrivateKey.generate("researcher")
    key.write(config.key_path(home))
    cli.register(ephemeral_service.url, home, key, sleep=slept.append)
    assert slept == [cli.REGISTER_WAIT] and "too many requests from the address x" in capsys.readouterr().err


def test_ctrl_c_during_install_says_how_to_finish(monkeypatch, capsys):
    from crucible_client import cli

    def interrupted(address, **_kw):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "install", interrupted)
    assert cli.main(["install", "https://log.example"]) == 130
    assert "run the same command again" in capsys.readouterr().err


def _fake_sender(tmp_path, body: str) -> str:
    script = tmp_path / "fake-send"
    script.write_text(f"#!{sys.executable}\nimport os, sys, time\nfrom pathlib import Path\n{body}\n")
    script.chmod(0o755)
    return str(script)


def test_a_spawned_sender_is_running_by_the_time_install_says_so(tmp_path):
    home = tmp_path / "client"
    home.mkdir()
    send = _fake_sender(tmp_path, """
time.sleep(0.5)  # a slow start: the run lock comes late
from crucible_client.sender import _locked
with _locked(Path(os.environ["CRUCIBLE_HOME"]) / "sender.run.lock", wait=False):
    time.sleep(30)
""")
    try:
        daemon._spawn(send, home)
        from crucible_client.sender import sender_running

        assert sender_running(home)  # so a rerun sees it, and the pid file names it
        assert "already running" in daemon._spawn(send, home)
    finally:
        daemon.stop_spawned(home)


def test_a_sender_that_exits_at_once_is_reported(tmp_path):
    home = tmp_path / "client"
    home.mkdir()
    with pytest.raises(daemon.DaemonError, match="exited at once"):
        daemon._spawn(_fake_sender(tmp_path, "sys.exit(3)"), home)


@pytest.mark.parametrize("command", [
    "env -u PYTHONPATH -u PYTHONHOME CRUCIBLE_HOME=/h/state /h/bin/crucible-hook",
    "CRUCIBLE_HOME=/h/state /h/bin/crucible-hook",  # as installed before
    "/usr/bin/env -u PYTHONPATH /h/bin/crucible-hook",
])
def test_a_crucible_hook_is_recognised_with_or_without_its_environment_prefix(command):
    assert settings.is_crucible_hook({"type": "command", "command": command})
    assert not settings.is_crucible_hook({"type": "command", "command": command.replace("crucible-hook", "other-hook")})


def test_the_sender_never_gets_a_python_module_path_from_outside(tmp_path, monkeypatch):
    home = tmp_path / "client"
    home.mkdir()
    monkeypatch.setenv("PYTHONPATH", "/somewhere/else")
    monkeypatch.setenv("PYTHONHOME", "/elsewhere")
    seen = tmp_path / "env.json"
    send = _fake_sender(tmp_path, f"""
import json
Path({str(seen)!r}).write_text(json.dumps({{k: os.environ.get(k) for k in ("PYTHONPATH", "PYTHONHOME")}}))
from crucible_client.sender import _locked
with _locked(Path(os.environ["CRUCIBLE_HOME"]) / "sender.run.lock", wait=False):
    time.sleep(30)
""")
    try:
        daemon._spawn(send, home)
        assert json.loads(seen.read_text()) == {"PYTHONPATH": None, "PYTHONHOME": None}
    finally:
        daemon.stop_spawned(home)
    unit = daemon.systemd_unit("/h/bin/crucible-send", tmp_path)
    assert "UnsetEnvironment=PYTHONPATH PYTHONHOME" in unit
    import plistlib

    args = plistlib.loads(daemon.launchd_plist("/h/bin/crucible-send", tmp_path))["ProgramArguments"]
    assert args == ["/usr/bin/env", "-u", "PYTHONPATH", "-u", "PYTHONHOME", "/h/bin/crucible-send"]



def test_a_client_installed_under_a_path_with_an_equals_sign_is_refused(monkeypatch):
    from crucible_client import cli

    monkeypatch.setattr(cli, "_find_executable", lambda name: f"/opt/a=b/bin/{name}")  # env would read it as an assignment
    with pytest.raises(cli.Refused, match="with '=' in it"):
        cli._executable("crucible-hook")
