"""Start the sender in the background, so it outlives the install command.

On Linux it is a systemd user service, on macOS a launchd agent: both restart
it when it exits and start it at login. ``spawn`` starts it as a detached
process with a pid file, which is what tests use (a test must not touch the
user's own service manager) and the fallback where neither exists. The
manager is chosen by ``$CRUCIBLE_SERVICE_MANAGER`` (systemd, launchd, spawn),
else by the platform. Starting is idempotent: an installed, running sender is
left as it is.
"""

from __future__ import annotations

import os
import plistlib
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

UNIT = "crucible-sender.service"
LABEL = "org.cruciblehub.sender"

Runner = Callable[[list[str]], subprocess.CompletedProcess]


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)


class DaemonError(Exception):
    """The sender could not be started."""


def manager(run: Runner = _run) -> str:
    chosen = os.environ.get("CRUCIBLE_SERVICE_MANAGER")
    if chosen:
        if chosen not in ("systemd", "launchd", "spawn"):
            raise DaemonError(f"CRUCIBLE_SERVICE_MANAGER={chosen!r} is not systemd, launchd or spawn")
        return chosen
    if sys.platform == "darwin" and shutil.which("launchctl"):
        return "launchd"
    if sys.platform.startswith("linux") and shutil.which("systemctl"):
        # systemctl alone is not a user manager (su, sudo -u, WSL without systemd, containers).
        if run(["systemctl", "--user", "show-environment"]).returncode == 0:
            return "systemd"
    return "spawn"


_SYSTEMD_UNSAFE = set("'\"\\\n")


def _systemd_path(value: str) -> str:
    """A path for a unit file: %-specifiers escaped; characters systemd cannot run refused."""
    if _SYSTEMD_UNSAFE & set(value):
        raise DaemonError(f"{value!r} holds a character a systemd unit cannot carry; install the client under another path")
    return value.replace("%", "%%")


def systemd_unit(send: str, home: Path) -> str:
    return (
        "[Unit]\n"
        "Description=Crucible sender: ships the local chain to the service\n\n"
        "[Service]\n"
        f'Environment="CRUCIBLE_HOME={_systemd_path(str(home))}"\n'
        "UnsetEnvironment=PYTHONPATH PYTHONHOME\n"  # the installed client, never a module path from outside
        f'ExecStart="{_systemd_path(send)}"\n'
        "Restart=always\n"
        "RestartSec=5\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def launchd_plist(send: str, home: Path) -> bytes:
    return plistlib.dumps({
        "Label": LABEL,
        "ProgramArguments": ["/usr/bin/env", "-u", "PYTHONPATH", "-u", "PYTHONHOME", send],
        "EnvironmentVariables": {"CRUCIBLE_HOME": str(home)},
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardErrorPath": str(home / "sender.err"),
    })


def start(send: str, home: Path, *, run: Runner = _run, user_home: Path | None = None) -> str:
    """Install and start the sender; return a one-line description of what runs it."""
    user_home = user_home or Path.home()
    kind = manager(run)
    if kind == "systemd":
        unit = user_home / ".config" / "systemd" / "user" / UNIT
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text(systemd_unit(send, home), encoding="utf-8")
        for argv in (["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", UNIT],
                     ["systemctl", "--user", "restart", UNIT]):
            r = run(argv)
            if r.returncode != 0:
                raise DaemonError(f"`{' '.join(argv)}` failed: {(r.stderr or r.stdout).strip()}")
        return f"systemd user service {UNIT}"
    if kind == "launchd":
        plist = user_home / "Library" / "LaunchAgents" / f"{LABEL}.plist"
        plist.parent.mkdir(parents=True, exist_ok=True)
        plist.write_bytes(launchd_plist(send, home))
        domain = f"gui/{os.getuid()}"
        run(["launchctl", "bootout", f"{domain}/{LABEL}"])  # absent the first time; that is fine
        r = run(["launchctl", "bootstrap", domain, str(plist)])
        if r.returncode != 0:
            raise DaemonError(f"launchctl bootstrap failed: {(r.stderr or r.stdout).strip()}")
        return f"launchd agent {LABEL}"
    return _spawn(send, home)


SPAWN_WAIT = 10.0  # how long a spawned sender has to take its run lock


def pid_path(home: Path) -> Path:
    return home / "sender.pid"


def _spawn(send: str, home: Path) -> str:
    from .sender import sender_running

    pidfile = pid_path(home)
    if sender_running(home):  # its run lock, not a pid that may now be someone else's
        return "sender process (already running; not started at login)"
    log = open(home / "sender.err", "ab")
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    proc = subprocess.Popen([send], env={**env, "CRUCIBLE_HOME": str(home)}, stdin=subprocess.DEVNULL,
                            stdout=log, stderr=log, start_new_session=True)
    # Until it holds its run lock a sender is invisible to sender_running(), and a rerun of install
    # would start a second one (which exits at once, its pid in place of the first's).
    deadline = time.monotonic() + SPAWN_WAIT
    while not sender_running(home):
        if proc.poll() is not None:
            raise DaemonError(f"the sender exited at once (status {proc.returncode}); see {home / 'sender.err'}")
        if time.monotonic() > deadline:
            break
        time.sleep(0.05)
    pidfile.write_text(f"{proc.pid}\n")
    return f"sender process {proc.pid} (not started at login: no service manager)"


def stop_spawned(home: Path) -> None:
    """Stop a sender started by `_spawn` (tests, and uninstall by hand)."""
    try:
        pid = int(pid_path(home).read_text().strip())
        os.kill(pid, signal.SIGTERM)
    except (OSError, ValueError):
        pass


__all__ = ["DaemonError", "LABEL", "UNIT", "launchd_plist", "manager", "pid_path", "start", "stop_spawned", "systemd_unit"]
