"""``crucible install <service-address>``: the one command (SPEC.md §3 Installation).

It asks for the service address and nothing else; there is no default, so a
client that was not told where to send sends nowhere. It then:

1. generates the researcher's keypair (kept if one exists);
2. pins the service's public key, which every receipt must be signed by
   (fetched from the address on first install; a later install that is shown
   a different key refuses rather than re-pinning);
3. registers the researcher key with the service;
4. writes the Claude Code hooks into the user's ``~/.claude/settings.json``;
5. starts the background sender (`daemon`).

``--expect-key <key_id>`` refuses, before anything is written, unless the service
presents that key: for example the key its status host publishes, which the
one-command installer passes.

Running it again changes nothing that is already right: the same key, the same
registration (the service returns the original receipt), the hooks replaced in
place, one sender.

The address must be ``https://``, or ``http://`` to this machine. Exit status:
0 installed, 2 refused (the reason is printed).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from crucible_chain import wire
from crucible_core.keys import KeyError_, PrivateKey, PublicKey
from crucible_verify.receipts import signed_checkpoint

from . import config, daemon, paths, settings
from .sender import _retry_after, http_post

LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class Refused(Exception):
    pass


def _address(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw.strip())
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise Refused(f"{raw!r} is not a service address; give one such as https://log.cruciblehub.org")
    if parsed.scheme == "http" and parsed.hostname not in LOOPBACK:
        raise Refused(f"{raw!r} is plain http to another machine; a service address is https://")
    if parsed.query or parsed.fragment:
        raise Refused(f"{raw!r} carries a query or fragment; give the service's base address")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _get(url: str) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            body = json.loads(resp.read())
    except (OSError, ValueError) as exc:
        raise Refused(f"cannot reach the service at {url}: {exc}") from exc
    if not isinstance(body, dict):
        raise Refused(f"{url} did not answer with a JSON object")
    return body


def _executable(name: str) -> str:
    """The console script of the environment this client is installed in (a path `env` cannot
    mistake for an assignment: no '=')."""
    found = _find_executable(name)
    if "=" in found:
        raise Refused(f"the client is installed under {found!r}, a path with '=' in it, which a hook command "
                      "cannot run; install it under another path")
    return found


def _find_executable(name: str) -> str:
    import shutil
    import sysconfig

    for scheme in (None, f"{os.name}_user"):
        try:
            where = Path(sysconfig.get_path("scripts", scheme) if scheme else sysconfig.get_path("scripts")) / name
        except KeyError:
            continue
        if where.exists():
            return str(where)
    beside = Path(sys.executable).parent / name
    if beside.exists():
        return str(beside)
    if found := shutil.which(name):
        return str(Path(found).absolute())
    raise Refused(f"cannot find the {name} command; reinstall the client")


REGISTER_TRIES = 3
REGISTER_WAIT = 300.0  # the longest a rate limit's Retry-After is waited out


def register(service: str, home: Path, key: PrivateKey, *, expect: PublicKey | None = None,
             expect_key_id: str | None = None, sleep=time.sleep) -> PublicKey:
    """Pin the service key ``service`` presents (it must be ``expect``, or have the id
    ``expect_key_id``, when given, and be the key already pinned, if any), register ``key``
    with it, and save the configuration. A rate limit (429) is waited out, up to
    ``REGISTER_WAIT`` at a time, ``REGISTER_TRIES`` times."""
    try:
        presented = PublicKey.from_dict(_get(f"{service}/v2/pubkey"))
    except KeyError_ as exc:
        raise Refused(f"the service at {service} did not present a usable public key: {exc}") from exc
    if presented.role != "service":
        raise Refused(f"the key {service} presents is a {presented.role} key, not a service key")
    if expect is not None and (presented.key_id, presented.public_bytes) != (expect.key_id, expect.public_bytes):
        raise Refused(f"{service} presents key {presented.key_id}, not the expected {expect.key_id}")
    if expect_key_id is not None and presented.key_id != expect_key_id:
        raise Refused(f"{service} presents key {presented.key_id}, not the expected {expect_key_id}")
    try:
        pinned = config.load(home)
    except config.ConfigError:
        pinned = None
    if pinned is not None:
        if pinned.service != service:
            raise Refused(f"this client already sends to {pinned.service}; it will not be moved to {service} silently")
        if pinned.service_key.key_id != presented.key_id:
            raise Refused(f"{service} now presents key {presented.key_id}, not the pinned {pinned.service_key.key_id}; "
                          "receipts under another key would not be the service's word")
    for attempt in range(REGISTER_TRIES):
        try:
            status, headers, body = http_post(f"{service}/v2/keys", {"registration": wire.registration(key)})
        except OSError as exc:
            raise Refused(f"cannot reach the service at {service} to register the key: {exc}") from exc
        if status != 429 or attempt == REGISTER_TRIES - 1:
            break
        wait = min(_retry_after(headers) or 30.0, REGISTER_WAIT)
        print(f"crucible: {service} asks to wait ({(body or {}).get('detail', 'rate limited')}); "
              f"trying again in {wait:.0f} s", file=sys.stderr)
        sleep(wait)
    receipt = (body or {}).get("receipt")
    if status != 200 or not isinstance(receipt, dict):
        raise Refused(f"the service refused the key registration ({status}): {(body or {}).get('detail', body)}")
    try:
        signed_checkpoint(receipt.get("checkpoint"), presented)
    except ValueError as exc:
        raise Refused(f"the registration receipt is not signed by the key {service} presents: {exc}") from exc
    if (receipt.get("entry") or {}).get("payload", {}).get("key_id") != key.key_id:
        raise Refused("the registration receipt does not name this client's key")
    config.save(home, service, presented)
    return presented


KEY_ID = re.compile(r"sha256:[0-9a-f]{64}")


def install(address: str, *, expect_key: str | None = None, out=print) -> int:
    service = _address(address)
    home = paths.client_home()
    # Everything that can refuse is asked before anything is written.
    if expect_key is not None:
        if not KEY_ID.fullmatch(expect_key):
            raise Refused(f"{expect_key!r} is not a key id (sha256:<64 hex>)")
        try:
            presented_id = PublicKey.from_dict(_get(f"{service}/v2/pubkey")).key_id
        except KeyError_ as exc:
            raise Refused(f"the service at {service} did not present a usable public key: {exc}") from exc
        if presented_id != expect_key:
            raise Refused(f"{service} presents key {presented_id}, not the expected {expect_key}; nothing was installed")
    hook, send = _executable(settings.HOOK_NAME), _executable("crucible-send")
    # The hooks' command names the client's home, so a hook finds the same chain
    # whatever environment Claude Code runs it in.
    # and imports only the installed client: a PYTHONPATH in Claude Code's environment is not let in
    command = f"/usr/bin/env -u PYTHONPATH -u PYTHONHOME CRUCIBLE_HOME={shlex.quote(str(home))} {shlex.quote(hook)}"
    settings.read(command=command)
    home.mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)

    # 1. the researcher's key
    key_file = config.key_path(home)
    if key_file.exists():
        try:
            key = PrivateKey.read(key_file)
        except (KeyError_, OSError, ValueError) as exc:
            raise Refused(f"the researcher key at {key_file} cannot be read: {exc}") from exc
        made = False
    else:
        key = PrivateKey.generate("researcher")
        key.write(key_file)
        made = True

    # 2-3. the service's key, pinned, and the registration
    presented = register(service, home, key, expect_key_id=expect_key)

    # 4. the sender, before the hooks: hooks that record into a queue nothing
    # drains would be a half-installed client
    running = daemon.start(send, home)

    # 5. the hooks
    settings_file, changed = settings.install(command)

    out(f"crucible: {'generated' if made else 'kept'} researcher key {key.key_id}")
    out(f"crucible: sending to {service}, service key {presented.key_id}")
    out(f"crucible: hooks {'written to' if changed else 'already in'} {settings_file}")
    out(f"crucible: sender: {running}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="crucible", description="Crucible client.")
    sub = ap.add_subparsers(dest="command")
    inst = sub.add_parser("install", help="install the client: crucible install <service-address>")
    inst.add_argument("address", nargs="?", help="the service address, e.g. https://log.cruciblehub.org")
    inst.add_argument("--expect-key", metavar="KEY_ID",
                      help="refuse unless the service presents this key (sha256:...), e.g. the one its status host publishes")
    args = ap.parse_args(argv)
    if args.command != "install":
        ap.print_help(sys.stderr)
        return 2
    if not args.address:
        print("crucible: give the service address: crucible install <service-address>. "
              "There is no default service.", file=sys.stderr)
        return 2
    try:
        return install(args.address, expect_key=args.expect_key)
    except (Refused, config.ConfigError, settings.SettingsError, daemon.DaemonError, KeyError_, OSError) as exc:
        print(f"crucible: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("crucible: stopped; run the same command again to finish", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
