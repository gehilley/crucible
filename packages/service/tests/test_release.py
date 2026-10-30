"""A release is built from a tag, and the same tag builds the same bytes
(docs/v1-audit.md §5 step 9: "Build client and service wheels from a tag, with
their sha256 recorded"). Runs in a throwaway copy of this repository."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _release_module():
    spec = importlib.util.spec_from_file_location("release", ROOT / "scripts" / "release.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def tagged(tmp_path_factory, copy_tracked_tree):
    """A copy of the tracked tree (with this working tree's changes), committed and tagged."""
    repo = tmp_path_factory.mktemp("repo")
    copy_tracked_tree(repo)
    git = ["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
    subprocess.run(git + ["init", "-q"], cwd=repo, check=True)
    subprocess.run(git + ["add", "-A"], cwd=repo, check=True)
    subprocess.run(git + ["commit", "-q", "-m", "release test"], cwd=repo, check=True)
    subprocess.run(git + ["tag", "-a", "-m", "v0.0.1.dev1", "v0.0.1.dev1"], cwd=repo, check=True)
    return repo


def test_the_same_tag_builds_the_same_wheels_with_their_sha256_recorded(tagged, tmp_path):
    release = _release_module()
    a = release.release(tagged, "v0.0.1.dev1", tmp_path / "a", image=False, repository=None, base="python:3.11-slim")
    b = release.release(tagged, "v0.0.1.dev1", tmp_path / "b", image=False, repository=None, base="python:3.11-slim")
    assert set(a["wheels"]) == {"crucible-core", "crucible-chain", "crucible-verify", "crucible-service", "crucible-client"}
    assert a["wheels"] == b["wheels"] and a["requirements_sha256"] == b["requirements_sha256"]
    for w in a["wheels"].values():
        assert release.sha256(tmp_path / "a" / "v0.0.1.dev1" / "wheels" / w["file"]) == w["sha256"]
    assert json.loads((tmp_path / "a" / "v0.0.1.dev1" / "RELEASE.json").read_text())["commit"] == a["commit"]


def test_a_release_is_built_once(tagged, tmp_path):
    release = _release_module()
    release.release(tagged, "v0.0.1.dev1", tmp_path, image=False, repository=None, base="python:3.11-slim")
    with pytest.raises(release.ReleaseError, match="built once"):
        release.release(tagged, "v0.0.1.dev1", tmp_path, image=False, repository=None, base="python:3.11-slim")


def test_a_tag_that_does_not_exist_is_refused(tagged, tmp_path):
    release = _release_module()
    with pytest.raises(release.ReleaseError):
        release.release(tagged, "no-such-tag", tmp_path, image=False, repository=None, base="python:3.11-slim")


def test_a_tag_that_names_no_version_is_refused(tagged, tmp_path):
    release = _release_module()
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "tag", "-a", "-m", "x", "not-a-version"], cwd=tagged, check=True)
    with pytest.raises(release.ReleaseError, match="does not name a version"):
        release.release(tagged, "not-a-version", tmp_path, image=False, repository=None, base="python:3.11-slim")


def test_the_wheels_carry_the_tags_version(tagged, tmp_path):
    release = _release_module()
    m = release.release(tagged, "v0.0.1.dev1", tmp_path, image=False, repository=None, base="python:3.11-slim")
    assert m["version"] == "0.0.1.dev1" and all("-0.0.1.dev1-" in w["file"] for w in m["wheels"].values())


def test_only_an_annotated_tag_is_released_never_a_branch_or_a_lightweight_tag(tagged, tmp_path):
    release = _release_module()
    subprocess.run(["git", "branch", "v9.9.9"], cwd=tagged, check=True)
    with pytest.raises(release.ReleaseError, match="no tag"):
        release.release(tagged, "v9.9.9", tmp_path, image=False, repository=None, base="python:3.11-slim")
    subprocess.run(["git", "tag", "v9.9.8"], cwd=tagged, check=True)
    with pytest.raises(release.ReleaseError, match="lightweight"):
        release.release(tagged, "v9.9.8", tmp_path, image=False, repository=None, base="python:3.11-slim")
    m = release.release(tagged, "v0.0.1.dev1", tmp_path, image=False, repository=None, base="python:3.11-slim")
    tag_object = subprocess.run(["git", "rev-parse", "refs/tags/v0.0.1.dev1"], cwd=tagged, capture_output=True,
                                text=True, check=True).stdout.strip()
    assert m["tag_object"] == tag_object != m["commit"]


def test_each_wheel_pins_its_crucible_dependencies_to_the_release(tagged, tmp_path):
    import re
    import zipfile

    release = _release_module()
    m = release.release(tagged, "v0.0.1.dev1", tmp_path, image=False, repository=None, base="python:3.11-slim")
    requires = {}
    for pkg, w in m["wheels"].items():
        with zipfile.ZipFile(tmp_path / "v0.0.1.dev1" / "wheels" / w["file"]) as z:
            [meta] = [n for n in z.namelist() if n.endswith(".dist-info/METADATA")]
            requires[pkg] = [line.split(":", 1)[1].strip() for line in z.read(meta).decode().splitlines()
                             if re.match(r"Requires-Dist: *crucible", line)]
    assert set(requires["crucible-client"]) == {"crucible-core==0.0.1.dev1", "crucible-chain==0.0.1.dev1",
                                                "crucible-verify==0.0.1.dev1"}
    assert requires["crucible-core"] == [] and all(r.endswith("==0.0.1.dev1") for rs in requires.values() for r in rs)
    constraints = (tmp_path / "v0.0.1.dev1" / "constraints.txt").read_text()
    assert "cryptography==" in constraints and not any(line.startswith("crucible") for line in constraints.splitlines())
    assert m["client_constraints_sha256"] == "sha256:" + __import__("hashlib").sha256(constraints.encode()).hexdigest()


def test_a_wheel_whose_crucible_dependency_is_not_pinned_is_refused(tmp_path):
    import zipfile

    release = _release_module()
    wheel = tmp_path / "crucible_client-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as z:
        z.writestr("crucible_client-1.0.dist-info/METADATA",
                   "Metadata-Version: 2.4\nName: crucible-client\nVersion: 1.0\nRequires-Dist: crucible-core>=1.0\n")
    with pytest.raises(release.ReleaseError, match="not the release's 1.0"):
        release.check_pins(wheel, "1.0")


def test_the_build_backend_is_pinned_by_hash_and_recorded(tagged, tmp_path):
    release = _release_module()
    m = release.release(tagged, "v0.0.1.dev1", tmp_path, image=False, repository=None, base="python:3.11-slim")
    pinned = (tagged / "deploy" / "build-constraints.txt").read_bytes()
    assert m["build_backend"].startswith("hatchling==") and m["build_backend"].encode() in pinned
    assert m["build_constraints_sha256"] == "sha256:" + __import__("hashlib").sha256(pinned).hexdigest()
    import zipfile

    version = m["build_backend"].split("==")[1]
    for w in m["wheels"].values():  # each wheel names the backend that built it
        with zipfile.ZipFile(tmp_path / "v0.0.1.dev1" / "wheels" / w["file"]) as z:
            [wheel] = [n for n in z.namelist() if n.endswith(".dist-info/WHEEL")]
            assert f"Generator: hatchling {version}" in z.read(wheel).decode()
    tree = tmp_path / "tree"
    (tree / "deploy").mkdir(parents=True)
    with pytest.raises(release.ReleaseError, match="build backend"):
        release.build_backend(tree)


def test_a_pushed_release_needs_a_base_pinned_by_digest(tagged, tmp_path, monkeypatch):
    release = _release_module()

    def never(*_a, **_k):  # were the check to regress, nothing is built or pushed anywhere
        raise AssertionError("the release went on to build or push")

    monkeypatch.setattr(release, "build_image", never)
    monkeypatch.setattr(release, "push", never)
    with pytest.raises(release.ReleaseError, match="not pinned by digest"):
        release.release(tagged, "v0.0.1.dev1", tmp_path, image=True, repository="invalid.invalid/crucible/notary",
                        base="python:3.11-slim")


@pytest.mark.parametrize("change", ["wrong-hash", "no-hash"])
def test_a_tag_whose_build_backend_is_not_pinned_by_a_matching_hash_is_not_released(tagged, tmp_path, change):
    import re

    release = _release_module()
    pinned = tagged / "deploy" / "build-constraints.txt"
    original = pinned.read_text()
    if change == "wrong-hash":
        tampered = re.sub(r"--hash=sha256:[0-9a-f]{64}", "--hash=sha256:" + "0" * 64, original)  # every artifact's
    else:  # one build dependency left without a hash: --require-hashes refuses it
        tampered = re.sub(r"(pluggy==\S+) \\\n(    --hash=sha256:[0-9a-f]{64}( \\)?\n)+", r"\1\n", original)
    assert tampered != original
    git = ["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
    pinned.write_text(tampered)
    try:
        subprocess.run(git + ["commit", "-qam", "tampered backend"], cwd=tagged, check=True)
        tag = f"v0.0.2.dev{1 if change == 'wrong-hash' else 2}"
        subprocess.run(git + ["tag", "-a", "-m", "t", tag], cwd=tagged, check=True)
        with pytest.raises(release.ReleaseError) as refused:
            release.release(tagged, tag, tmp_path, image=False, repository=None, base="python:3.11-slim")
        assert "uv build" in str(refused.value)
        assert ("sha256:" + "0" * 64 if change == "wrong-hash" else "pluggy") in str(refused.value)
    finally:
        pinned.write_text(original)
        subprocess.run(git + ["commit", "-qam", "restored"], cwd=tagged, check=True)


def test_a_tag_whose_lock_is_not_current_for_its_tree_is_not_released(tagged, tmp_path):
    """A dependency added without `uv lock` would release third-party pins the tree no longer
    asks for."""
    release = _release_module()
    git = ["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
    pyproject = tagged / "packages" / "client" / "pyproject.toml"
    before = pyproject.read_text()
    pyproject.write_text(before.replace('dependencies = ["crucible-core"', 'dependencies = ["six", "crucible-core"', 1))
    assert pyproject.read_text() != before
    subprocess.run(git + ["commit", "-qam", "a dependency, not locked"], cwd=tagged, check=True)
    subprocess.run(git + ["tag", "-a", "-m", "t", "v0.0.3.dev1"], cwd=tagged, check=True)
    try:
        with pytest.raises(release.ReleaseError, match="uv.lock is not current"):
            release.release(tagged, "v0.0.3.dev1", tmp_path, image=False, repository=None, base="python:3.11-slim")
    finally:
        pyproject.write_text(before)
        subprocess.run(git + ["commit", "-qam", "restored"], cwd=tagged, check=True)
