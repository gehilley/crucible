"""A stranger's path, end to end (docs/v1-audit.md §5 step 11): on a clean HOME,
install the client from the wheels a real service serves, run the one command,
replay a captured Claude Code session through the installed hook, and the
service reports intact; alter event N in an exported copy, and the CLI reports
broken at event N (for an event sent in a batch of its own, as a live session's
pace gives; otherwise at the first event of its batch).

Builds a release from a tag in a throwaway copy of this repository, and installs
it by running the install line of the README the service serves. The default
package index is a squatter's: it offers crucible-* packages of its own (at a
higher version, and at the release's), and sends every other name on to PyPI,
where third-party dependencies come from (or uv's cache). The squatter's client
is already installed at the release's version (its first install also took
find-links from UV_CONFIG_FILE), every package source the environment can name
points at the squatter, and the uv configuration (UV_CONFIG_FILE and the user's
uv.toml) is unparseable when the README's commands run. Every crucible file
installed must be the release's, and every third-party version the release's
constraints. The README's own `crucible install` and `crucible-verify` lines
run through a shell with a PYTHONPATH that shadows the client and a PATH that
holds only the installed tools and the system's; every hook runs with that
PYTHONPATH and a PATH of a trap `env` and the system's only."""

from __future__ import annotations

import base64
import hashlib
import http.server
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
import zipfile
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = Path(__file__).parent / "fixtures" / "hooks" / "toy-analysis.json"
UV = shutil.which("uv") or str(Path.home() / ".local" / "bin" / "uv")


@pytest.fixture(scope="module")
def release_dir(tmp_path_factory, copy_tracked_tree):
    repo = tmp_path_factory.mktemp("repo")
    copy_tracked_tree(repo)
    git = ["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
    for argv in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "e2e"], ["tag", "-a", "-m", "e2e", "v0.0.1.dev1"]):
        subprocess.run(git + argv, cwd=repo, check=True)
    spec = importlib.util.spec_from_file_location("release", ROOT / "scripts" / "release.py")
    release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release)
    out = tmp_path_factory.mktemp("releases")
    release.release(repo, "v0.0.1.dev1", out, image=False, repository=None, base="python:3.11-slim")
    return out / "v0.0.1.dev1"


SQUATTED = ("crucible-core", "crucible-chain", "crucible-verify", "crucible-client")


def _squat_wheel(out: Path, name: str, version: str) -> Path:
    """A wheel anyone could upload under a name nobody registered: importing it stops the process."""
    mod = name.replace("-", "_")
    files = {f"{mod}/__init__.py": "raise SystemExit('this came from the package index, not from the release')\n",
             f"{mod}-{version}.dist-info/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
             f"{mod}-{version}.dist-info/WHEEL": "Wheel-Version: 1.0\nGenerator: squat\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
    if name == "crucible-client":
        files[f"{mod}-{version}.dist-info/entry_points.txt"] = "[console_scripts]\ncrucible = crucible_client:main\n"
    record = f"{mod}-{version}.dist-info/RECORD"
    lines = [f"{k},sha256={base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()},{len(v)}"
             for k, v in files.items()]
    files[record] = "\n".join([*lines, f"{record},,"]) + "\n"
    if name == "crucible-client":  # a .pth hook RECORD does not list: a reinstall alone may leave it behind
        files["zz_squatted.pth"] = "import sys\n"
    path = out / f"{mod}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as z:
        for k, v in files.items():
            z.writestr(k, v)
    return path


@pytest.fixture(scope="module")
def squatter(tmp_path_factory):
    """A default index that answers for the crucible-* names, and redirects the rest to PyPI."""
    files = tmp_path_factory.mktemp("squat")
    wheels = {name: [_squat_wheel(files, name, v) for v in ("99.0", "0.0.1.dev1")] for name in SQUATTED}
    # A third-party name too: PyPI's own files for it, and a newer version of the squatter's. Only the
    # release's constraints keep the version the release was built and tested with.
    newer = {"rfc8785": _squat_wheel(files, "rfc8785", "99.0")}

    class Index(http.server.BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.do_GET(head=True)

        def do_GET(self, head=False):
            parts = [p for p in self.path.split("?")[0].split("/") if p]
            if parts[:1] == ["files"] and len(parts) == 2 and (files / parts[1]).is_file():
                body, kind = (files / parts[1]).read_bytes(), "application/octet-stream"
            elif parts == ["flat"]:  # a find-links page
                body = "".join(f'<a href="/files/{w.name}">{w.name}</a>\n' for ws in wheels.values() for w in ws).encode()
                kind = "text/html"
            elif parts[:1] == ["simple"] and len(parts) == 2 and parts[1] in newer:
                req = urllib.request.Request(f"https://pypi.org/simple/{parts[1]}/", headers={"Accept": "text/html"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    page = resp.read().decode()
                own = f'<a href="/files/{newer[parts[1]].name}">{newer[parts[1]].name}</a>\n'
                body, kind = page.replace("</body>", own + "</body>").encode(), "text/html"
            elif parts[:1] == ["simple"] and len(parts) == 2 and parts[1] in wheels:
                body = "".join(f'<a href="/files/{w.name}">{w.name}</a>\n' for w in wheels[parts[1]]).encode()
                kind = "text/html"
            elif parts[:1] == ["simple"] and len(parts) == 2:
                self.send_response(302)
                self.send_header("Location", f"https://pypi.org/simple/{parts[1]}/")
                self.end_headers()
                return
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def log_message(self, *_a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Index)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/simple"
    server.shutdown()


def _readme_client_commands(readme: str, service_url: str, public_url: str, mirror: str) -> list[str]:
    """The README's commands that get the client, as a stranger copies them, against this test's
    service, with the README's own mirror instruction followed (UV_DEFAULT_INDEX just before `uv`)."""
    block = readme.split("## Install", 1)[1].split("```sh\n", 1)[1].split("```", 1)[0]
    lines = [x for x in block.splitlines() if x.strip() and "crucible install" not in x]
    assert len(lines) == 2 and " tool install " in lines[1], lines
    lines[1] = lines[1].replace(" uv tool install ", f" UV_DEFAULT_INDEX={shlex.quote(mirror)} uv tool install ", 1)
    return [x.replace(public_url, service_url) for x in lines]


def _assert_constrained(release_dir: Path, tools: Path) -> None:
    """Every third-party package installed is at the version the release's constraints name."""
    pins = {}
    for line in (release_dir / "constraints.txt").read_text().splitlines():
        if m := re.match(r"([A-Za-z0-9._-]+)==([^\s;]+)", line):
            pins[re.sub(r"[-_.]+", "-", m.group(1)).lower()] = m.group(2)
    [site] = list((tools / "envs" / "crucible-client").glob("lib/python3*/site-packages"))
    seen = {}
    for meta in site.glob("*.dist-info/METADATA"):
        fields = dict(line.split(": ", 1) for line in meta.read_text().splitlines()[:5] if ": " in line)
        seen[re.sub(r"[-_.]+", "-", fields["Name"]).lower()] = fields["Version"]
    checked = {n for n in seen if n in pins}
    assert {"cryptography", "cbor2", "pycose", "rfc8785"} <= checked, checked
    assert {n: seen[n] for n in checked} == {n: pins[n] for n in checked}


def _assert_installed_from(release_dir: Path, tools: Path) -> None:
    """Every crucible package installed is the release's: each file is byte for byte the wheel's."""
    manifest = json.loads((release_dir / "RELEASE.json").read_text())
    [site] = list((tools / "envs" / "crucible-client").glob("lib/python3*/site-packages"))
    found = {p.name.split("-")[0] for p in site.glob("crucible*.dist-info")}
    assert found == {"crucible_core", "crucible_chain", "crucible_verify", "crucible_client"}, found
    for package in SQUATTED:
        wheel = release_dir / "wheels" / manifest["wheels"][package]["file"]
        with zipfile.ZipFile(wheel) as z:
            for name in z.namelist():
                if name.endswith("/RECORD") or name.endswith("/"):
                    continue
                assert (site / name).read_bytes() == z.read(name), f"{name} is not the release's"


def _get(url):
    with urllib.request.urlopen(url, timeout=30) as resp:
        return resp.status, resp.read()


def _wait_anchored(chain_file: Path, session: str, timeout: float = 30.0) -> None:
    from crucible_chain.store import ChainStore

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with ChainStore(chain_file) as store:
            head = store.head(session)
            if head is not None and store.last_receipted_seq(session) == head.seq:
                return
        time.sleep(0.2)
    raise AssertionError(f"the sender did not anchor {session} within {timeout}s")


def _apply_tool(env: dict) -> None:
    args = env["tool_input"]
    if env["tool_name"] == "Write":
        Path(args["file_path"]).write_text(args["content"], encoding="utf-8")
    elif env["tool_name"] == "Edit":
        p = Path(args["file_path"])
        p.write_text(p.read_text(encoding="utf-8").replace(args["old_string"], args["new_string"], 1), encoding="utf-8")


def test_a_stranger_installs_from_the_address_and_a_captured_session_reads_intact(tmp_path, make_service, service_key, release_dir,
                                                                                  squatter):
    from crucible_service.api import Release

    svc = make_service(Release(release_dir, published="https://status.test"))
    status, readme = _get(svc.url + "/")
    assert status == 200 and f"crucible install https://{svc.name}".encode() in readme
    assert service_key.key_id.encode() in readme and b"https://status.test/service.pub.json" in readme

    home, tools = tmp_path / "home", tmp_path / "tools"
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CRUCIBLE_", "XDG_", "VIRTUAL_ENV", "UV_PROJECT"))}
    env = {k: v for k, v in env.items() if not k.startswith(("UV_INDEX", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX",
                                                             "UV_FIND_LINKS", "UV_CONSTRAINT", "UV_NO_INDEX"))}
    flat = squatter.removesuffix("/simple") + "/flat/"
    config = tmp_path / "xdg"
    config.mkdir(parents=True)
    (config / "named.toml").write_text(f'find-links = ["{flat}"]\n')  # UV_CONFIG_FILE: honoured even with --no-config
    version = json.loads((release_dir / "RELEASE.json").read_text())["version"]
    files = squatter.removesuffix("/simple") + "/files/"
    (config / "override.txt").write_text(f"crucible-core @ {files}crucible_core-{version}-py3-none-any.whl\n")
    (config / "exclude.txt").write_text("crucible-chain\n")
    env.update(HOME=str(home), CRUCIBLE_SERVICE_MANAGER="spawn", UV_TOOL_DIR=str(tools / "envs"),
               UV_TOOL_BIN_DIR=str(tools / "bin"), PATH=f"{tools / 'bin'}:{Path(UV).parent}:{env['PATH']}",
               UV_DEFAULT_INDEX=squatter, UV_INDEX=squatter, UV_INDEX_URL=squatter, UV_EXTRA_INDEX_URL=squatter,
               UV_FIND_LINKS=flat, XDG_CONFIG_HOME=str(config), UV_CONFIG_FILE=str(config / "named.toml"),
               UV_OVERRIDE=str(config / "override.txt"), UV_EXCLUDE=str(config / "exclude.txt"))
    if "UV_CACHE_DIR" not in env:
        env["UV_CACHE_DIR"] = str(Path.home() / ".cache" / "uv")  # the cache this machine already holds
    # A first try from the public index already left the squatter's client, at the release's version.
    first = subprocess.run([UV, "tool", "install", f"crucible-client=={version}"], env=env, capture_output=True, text=True,
                           timeout=300)
    assert first.returncode == 0 and "SystemExit" not in first.stderr, first.stderr
    # The README's own commands, through a shell as a stranger runs them, with every package source the
    # environment can name pointing at the squatter, and the squatter as the mirror for third-party names.
    uninstall, install = _readme_client_commands(readme.decode(), svc.url, f"https://{svc.name}", squatter)
    # And the uv configuration the environment names is broken: the README's commands must not read it.
    broken = tmp_path / "xdg-broken"
    (broken / "uv").mkdir(parents=True)
    (broken / "uv" / "uv.toml").write_text("this is [not toml\n")
    env = {**env, "XDG_CONFIG_HOME": str(broken), "UV_CONFIG_FILE": str(broken / "uv" / "uv.toml")}
    gone = subprocess.run(uninstall, shell=True, executable="/bin/sh", env=env, capture_output=True, text=True, timeout=300)
    assert gone.returncode == 0 and not (tools / "envs" / "crucible-client").exists(), gone.stderr  # the squatter's copy is gone
    got = subprocess.run(install, shell=True, executable="/bin/sh", env=env, capture_output=True, text=True, timeout=300)
    assert got.returncode == 0, got.stderr
    _assert_installed_from(release_dir, tools)
    _assert_constrained(release_dir, tools)
    [site] = list((tools / "envs" / "crucible-client").glob("lib/python3*/site-packages"))
    assert not (site / "zz_squatted.pth").exists()  # nothing the squatter's install left behind remains
    bin_dir = tools / "bin"
    # A PYTHONPATH in the stranger's shell, or in Claude Code's environment, that shadows the client.
    shadow = tmp_path / "shadow"
    for package in ("crucible_client", "crucible_verify"):
        (shadow / package).mkdir(parents=True)
        (shadow / package / "__init__.py").write_text(f"raise SystemExit('a {package} from PYTHONPATH ran')\n")
    # Only the tools the README installed, and the system's: never a developer's own copy on PATH.
    shadowed = {**env, "PYTHONPATH": str(shadow), "PATH": f"{bin_dir}:/usr/bin:/bin"}
    block = readme.decode().split("## Install", 1)[1].split("```sh\n", 1)[1].split("```", 1)[0]
    [install_line] = [x for x in block.splitlines() if "crucible install" in x]
    try:
        r = subprocess.run(install_line.replace(f"https://{svc.name}", svc.url), shell=True, executable="/bin/sh", env=shadowed,
                           capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, r.stderr

        # Replay a captured Claude Code session through the installed hook command.
        doc = json.loads(FIXTURE.read_text())
        ws, tdir = tmp_path / "ws", tmp_path / "transcripts"
        ws.mkdir()
        for rel, text in doc["files_before"].items():
            (ws / rel).write_text(text, encoding="utf-8")
        text = json.dumps(doc["events"])
        for placeholder, records in doc["transcripts"].items():
            path = tdir / placeholder.removeprefix("/TRANSCRIPTS/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("".join(json.dumps(x) + "\n" for x in records), encoding="utf-8")
            text = text.replace(placeholder, str(path))
        envelopes = json.loads(text.replace("/WORKSPACE", str(ws)))
        command = json.loads((home / ".claude" / "settings.json").read_text())["hooks"]["Stop"][0]["hooks"][0]["command"]
        # Claude Code runs hooks in its own environment: a PYTHONPATH there must not reach the client,
        # and the command must not look `env` up on PATH (a trap one comes first there).
        trap = tmp_path / "trap"
        trap.mkdir()
        (trap / "env").write_text("#!/bin/sh\necho 'a bare env from PATH ran' >&2\nexit 1\n")
        (trap / "env").chmod(0o755)
        hook_env = {**shadowed, "PATH": f"{trap}:/usr/bin:/bin"}  # the hook is named by its absolute path
        installed = {e for e, groups in json.loads((home / ".claude" / "settings.json").read_text())["hooks"].items()}
        session = envelopes[0]["session_id"]
        chain_file = home / ".local" / "state" / "crucible" / "chain.sqlite"
        for e in envelopes:
            if e["hook_event_name"] == "PostToolUse":
                _apply_tool(e)
            if e["hook_event_name"] in installed:
                done = subprocess.run(command, shell=True, input=json.dumps(e), env=hook_env, capture_output=True, text=True,
                                      timeout=60)
                assert done.returncode == 0, done.stderr
                # At a live session's pace: the sender anchors each envelope's events before the next
                # arrives, so receipts are as fine as the events (N is the first event of the batch
                # that holds a change).
                _wait_anchored(chain_file, session)

        deadline = time.monotonic() + 60
        verdict = None
        while time.monotonic() < deadline:
            try:
                status, body = _get(f"{svc.url}/v2/sessions/{session}/verify")
                verdict = json.loads(body)["verdict"]["says"]
                if verdict == "intact":
                    break
            except OSError:
                pass
            time.sleep(0.5)
        assert verdict == "intact"

        # Alter event 6 (the Bash tool call, a batch of its own) in an exported copy: the CLI the
        # stranger installed says where. (A change is placed at the first event of the batch that
        # holds it: event 5, the Read's file.read, came in one batch with its result at 4.)
        _status, exported = _get(f"{svc.url}/v2/sessions/{session}/export")
        lines = exported.decode().split("\n")
        event6 = json.loads(lines[7])
        assert (event6["seq"], event6["event"]["type"]) == (6, "tool.call")
        event6["event"]["body"] = {"altered": True}
        lines[7] = json.dumps(event6, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        copy = tmp_path / "altered.jsonl"
        copy.write_text("\n".join(lines))
        _status, pub = _get(f"{svc.url}/v2/pubkey")
        key = tmp_path / "service.pub.json"
        key.write_bytes(pub)
        [verify_line] = [x for x in readme.decode().splitlines() if re.search(r"(^|\s)crucible-verify\s", x) and "--service-key" in x]
        verify = verify_line.split("crucible-verify", 1)[0] + f"crucible-verify {shlex.quote(str(copy))} --service-key {shlex.quote(str(key))}"
        check = subprocess.run(verify, shell=True, executable="/bin/sh", env=shadowed, capture_output=True, text=True, timeout=60)
        said = check.stdout.splitlines()[:1]
        assert check.returncode == 1 and said and said[0].split() == ["record", "broken", "at", "event", "6"], check.stdout + check.stderr
    finally:
        from crucible_client import daemon

        daemon.stop_spawned(home / ".local" / "state" / "crucible")


def test_the_service_serves_only_the_releases_files_each_with_its_sha256(make_service, release_dir):
    from crucible_service.api import Release

    svc = make_service(Release(release_dir, published="https://status.test"))
    manifest = json.loads((release_dir / "RELEASE.json").read_text())
    _status, index = _get(svc.url + "/client/")
    _status, root = _get(svc.url + "/client/simple/")
    for package, w in manifest["wheels"].items():
        assert f'{w["file"]}#sha256={w["sha256"].removeprefix("sha256:")}' in index.decode()
        assert f'href="{package}/"' in root.decode()
        _status, page = _get(f"{svc.url}/client/simple/{package}/")
        assert f'href="../../{w["file"]}#sha256={w["sha256"].removeprefix("sha256:")}"' in page.decode()
        _status, data = _get(f'{svc.url}/client/{w["file"]}')
        assert "sha256:" + hashlib.sha256(data).hexdigest() == w["sha256"]
    _status, constraints = _get(svc.url + "/client/constraints.txt")
    assert "sha256:" + hashlib.sha256(constraints).hexdigest() == manifest["client_constraints_sha256"]
    try:  # a name this release does not hold: the installer must look in the next index
        _get(f"{svc.url}/client/simple/cryptography/")
        raise AssertionError("cryptography")
    except urllib.error.HTTPError as exc:
        assert exc.code == 404
    for name in ("RELEASE.jsonx", "..%2FREADME.md", "README.md"):
        try:
            _get(f"{svc.url}/client/{name}")
            raise AssertionError(name)
        except urllib.error.HTTPError as exc:
            assert exc.code == 404


def test_a_release_whose_wheel_does_not_match_its_manifest_is_not_served(tmp_path, release_dir):
    from crucible_service.api import Release

    copy = tmp_path / "rel"
    shutil.copytree(release_dir, copy)
    wheel = next((copy / "wheels").iterdir())
    wheel.write_bytes(wheel.read_bytes() + b"x")
    with pytest.raises(ValueError, match="does not hash"):
        Release(copy, published="https://status.test")
    shutil.copytree(release_dir, tmp_path / "rel2")
    (tmp_path / "rel2" / "constraints.txt").write_text("cryptography==1.0\n")
    with pytest.raises(ValueError, match="does not hash"):
        Release(tmp_path / "rel2", published="https://status.test")
