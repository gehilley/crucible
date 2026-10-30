#!/usr/bin/env python3
"""Build a release from a git tag (SPEC.md §5 Deployment; docs/v1-audit.md §5 step 9).

    uv run python scripts/release.py <tag> [--out dist/releases] [--image] [--push <ecr-repository-uri>]

1. Extract the tag with ``git archive`` into a temporary directory: a release is
   built from the tagged tree, never from a working tree. The tag must be an
   annotated tag (``refs/tags/<tag>``, never a branch of the same name); its
   object id is recorded. The tag's uv.lock must be current for the tagged tree.
2. Stamp the tag's version into every package, and pin each crucible-*
   dependency to exactly that version, so an install of one release's client
   can only ever resolve that release's wheels.
3. Build the crucible wheels there (core, chain, verify, service, client), with
   ``SOURCE_DATE_EPOCH`` set to the tag's commit time and the build backend
   pinned by hash (``deploy/build-constraints.txt``), so the same tag builds the
   same bytes; record each wheel's sha256.
4. Export the third-party requirements, pinned by hash, from the tag's uv.lock,
   for the image; and the client's, pinned by version, as the
   ``constraints.txt`` the service serves to strangers.
5. With ``--image``, build the service image from deploy/Dockerfile; with
   ``--push`` (which needs a base pinned by ``@sha256:``), push it and record the
   image digest the service will run as.
6. Write ``<out>/<tag>/RELEASE.json`` and copy the wheels beside it. The client's
   wheels, their sha256 and the constraints are what the service serves to
   strangers (step 11), with deploy/README.md and deploy/install.sh, which the
   service renders with its own address at ``/`` and ``/install.sh``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

PACKAGES = ("crucible-core", "crucible-chain", "crucible-verify", "crucible-service", "crucible-client")
# The image runs the service and, as the liveness probe, the released client too.
SERVICE_PACKAGES = PACKAGES
UV = shutil.which("uv") or str(Path.home() / ".local" / "bin" / "uv")


class ReleaseError(RuntimeError):
    pass


def _run(argv: list[str], *, cwd: Path | None = None, env: dict | None = None) -> str:
    r = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise ReleaseError(f"`{' '.join(argv)}` failed:\n{r.stderr.strip() or r.stdout.strip()}")
    return r.stdout


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def resolve_tag(repo: Path, tag: str) -> tuple[str, str]:
    """The annotated tag's object id and its commit; a branch or a lightweight tag is refused."""
    ref = f"refs/tags/{tag}"
    try:
        obj = _run(["git", "rev-parse", "--verify", "--quiet", ref], cwd=repo).strip()
    except ReleaseError:
        raise ReleaseError(f"no tag {tag!r} (a release is built from refs/tags/<tag>, never a branch)") from None
    if _run(["git", "cat-file", "-t", obj], cwd=repo).strip() != "tag":
        raise ReleaseError(f"{tag!r} is a lightweight tag; a release is built from an annotated tag (git tag -a)")
    return obj, _run(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=repo).strip()


def extract(repo: Path, tag: str, into: Path) -> tuple[str, str, int]:
    tag_object, commit = resolve_tag(repo, tag)
    when = int(_run(["git", "log", "-1", "--format=%ct", commit], cwd=repo).strip())
    archive = into.parent / "tree.tar"
    _run(["git", "archive", "--format=tar", "-o", str(archive), commit], cwd=repo)
    with tarfile.open(archive) as tar:
        tar.extractall(into, filter="data")
    archive.unlink()
    return tag_object, commit, when


def check_lock(tree: Path) -> None:
    """The tag's uv.lock is current for the tagged pyprojects: the third-party pins the image
    installs and strangers are given come from it."""
    try:
        _run([UV, "lock", "--check", "--offline"], cwd=tree)
    except ReleaseError as exc:
        raise ReleaseError(f"the tag's uv.lock is not current for its tree (run `uv lock` and commit it): {exc}") from None


def version_of(tag: str) -> str:
    """The packages' version for a tag: ``v1.2.3`` -> ``1.2.3`` (PEP 440, or refused)."""
    v = tag[1:] if tag.startswith("v") else tag
    if not re.fullmatch(r"\d+(\.\d+)*((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?(\+[a-z0-9.]+)?", v):
        raise ReleaseError(f"tag {tag!r} does not name a version (v1.2.3)")
    return v


def stamp_version(tree: Path, version: str) -> None:
    """Give every package in the extracted tree the tag's version (the repository says 0.0.0),
    and pin its crucible-* dependencies to exactly that version."""
    for pyproject in sorted((tree / "packages").glob("*/pyproject.toml")):
        text = pyproject.read_text(encoding="utf-8")
        if text.count('version = "0.0.0"') != 1:
            raise ReleaseError(f"{pyproject.relative_to(tree)} does not hold exactly one version line to stamp")
        text = text.replace('version = "0.0.0"', f'version = "{version}"')
        deps = list(re.finditer(r"^dependencies = \[(.*?)\]", text, re.M | re.S))
        if len(deps) != 1:
            raise ReleaseError(f"{pyproject.relative_to(tree)} does not hold exactly one dependencies list to pin")
        start, end = deps[0].span(1)
        pinned = re.sub(r'"(crucible-[a-z]+)"', rf'"\1=={version}"', text[start:end])
        pyproject.write_text(text[:start] + pinned + text[end:], encoding="utf-8")


def check_pins(wheel: Path, version: str) -> None:
    """Every crucible-* requirement of a built wheel names exactly the release's version."""
    import zipfile

    with zipfile.ZipFile(wheel) as z:
        [meta] = [n for n in z.namelist() if n.endswith(".dist-info/METADATA")]
        lines = z.read(meta).decode("utf-8").splitlines()
    for line in lines:
        if line.startswith("Requires-Dist:") and re.match(r"Requires-Dist: *crucible", line):
            if not re.fullmatch(rf"Requires-Dist: *crucible-[a-z]+ *== *{re.escape(version)}", line):
                raise ReleaseError(f"{wheel.name} requires {line.split(':', 1)[1].strip()!r}, not the release's {version}")


BUILD_CONSTRAINTS = Path("deploy") / "build-constraints.txt"


def build_backend(tree: Path) -> Path:
    """The tag's build constraints: the build backend and its dependencies, pinned by hash."""
    path = tree / BUILD_CONSTRAINTS
    if not path.is_file() or not re.search(r"^hatchling==\S+ ", path.read_text(encoding="utf-8"), re.M):
        raise ReleaseError(f"the tag holds no {BUILD_CONSTRAINTS} pinning the build backend by hash")
    return path


def build_wheels(tree: Path, out: Path, epoch: int, version: str) -> dict[str, dict]:
    env = {**os.environ, "SOURCE_DATE_EPOCH": str(epoch)}
    for name in ("UV_BUILD_CONSTRAINT", "UV_NO_VERIFY_HASHES", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL"):
        env.pop(name, None)
    constraints = build_backend(tree)
    wheels = {}
    for pkg in PACKAGES:
        before = set(out.glob("*.whl"))
        _run([UV, "build", "--package", pkg, "--wheel", "--out-dir", str(out), "--no-sources",
              "--build-constraints", str(constraints), "--require-hashes"], cwd=tree, env=env)
        [made] = set(out.glob("*.whl")) - before
        check_pins(made, version)
        wheels[pkg] = {"file": made.name, "sha256": sha256(made)}
    return wheels


def requirements(tree: Path, package: str = "crucible-service", *, hashes: bool = True) -> str:
    return _run([UV, "export", "--frozen", "--no-dev", "--package", package, "--no-emit-workspace",
                 *([] if hashes else ["--no-hashes", "--no-annotate"]), "--no-header", "--format", "requirements-txt"],
                cwd=tree)


def build_image(tree: Path, context: Path, tag: str, base: str) -> str:
    _run(["docker", "build", "-f", str(tree / "deploy" / "Dockerfile"), "--build-arg", f"BASE={base}",
          "-t", f"crucible/notary:{tag}", str(context)])
    return _run(["docker", "image", "inspect", "--format", "{{.Id}}", f"crucible/notary:{tag}"]).strip()


def push(tag: str, repository: str) -> str:
    _run(["docker", "tag", f"crucible/notary:{tag}", f"{repository}:{tag}"])
    _run(["docker", "push", f"{repository}:{tag}"])
    digests = json.loads(_run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", f"{repository}:{tag}"]))
    match = [d for d in digests if d.startswith(repository + "@")]
    if not match:
        raise ReleaseError(f"no digest recorded for {repository}:{tag} after the push")
    return match[0].split("@", 1)[1]


def release(repo: Path, tag: str, out: Path, *, image: bool, repository: str | None, base: str) -> dict:
    target = out / tag
    if target.exists():
        raise ReleaseError(f"{target} exists; a release is built once")
    if repository and not re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", base):
        raise ReleaseError(f"--base {base!r} is not pinned by digest (name@sha256:...); a pushed release names its base exactly")
    with tempfile.TemporaryDirectory(prefix="crucible-release-") as tmp:
        tree, context = Path(tmp) / "tree", Path(tmp) / "context"
        tree.mkdir()
        (context / "wheels").mkdir(parents=True)
        tag_object, commit, epoch = extract(repo, tag, tree)
        check_lock(tree)
        version = version_of(tag)
        stamp_version(tree, version)
        backend = build_backend(tree).read_bytes()
        wheels = build_wheels(tree, context / "wheels", epoch, version)
        readme = tree / "deploy" / "README.md"
        if not readme.is_file():
            raise ReleaseError("the tag holds no deploy/README.md for the service to serve")
        shutil.copy2(readme, context / "README.md")
        installer = tree / "deploy" / "install.sh"
        if not installer.is_file():
            raise ReleaseError("the tag holds no deploy/install.sh for the service to serve")
        shutil.copy2(installer, context / "install.sh")
        reqs = requirements(tree)
        (context / "requirements.txt").write_text(reqs, encoding="utf-8")
        client = requirements(tree, "crucible-client", hashes=False)
        (context / "constraints.txt").write_text(client, encoding="utf-8")
        for pkg in PACKAGES:  # the service image holds the service and what it imports, not the client
            if pkg not in SERVICE_PACKAGES:
                (context / "wheels" / wheels[pkg]["file"]).rename(Path(tmp) / wheels[pkg]["file"])
        manifest = {
            "tag": tag,
            "tag_object": tag_object,
            "version": version,
            "commit": commit,
            "source_date_epoch": epoch,
            "wheels": wheels,
            "requirements_sha256": "sha256:" + hashlib.sha256(reqs.encode()).hexdigest(),
            "client_constraints_sha256": "sha256:" + hashlib.sha256(client.encode()).hexdigest(),
            "build_constraints_sha256": "sha256:" + hashlib.sha256(backend).hexdigest(),
            "build_backend": re.search(rb"^(hatchling==\S+)", backend, re.M).group(1).decode(),
            "base_image": base,
        }
        (context / "RELEASE.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if image:
            manifest["image_id"] = build_image(tree, context, tag, base)
            if repository:
                manifest["image_digest"] = push(tag, repository)
        # The same layout as the image's /release: RELEASE.json, README.md, wheels/.
        (target / "wheels").mkdir(parents=True)
        for pkg, w in wheels.items():
            src = context / "wheels" / w["file"]
            shutil.copy2(src if src.exists() else Path(tmp) / w["file"], target / "wheels" / w["file"])
        shutil.copy2(context / "README.md", target / "README.md")
        shutil.copy2(context / "install.sh", target / "install.sh")
        shutil.copy2(context / "constraints.txt", target / "constraints.txt")
        (target / "RELEASE.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="release")
    ap.add_argument("tag")
    ap.add_argument("--out", type=Path, default=Path("dist/releases"))
    ap.add_argument("--image", action="store_true", help="build the service image")
    ap.add_argument("--push", metavar="REPOSITORY", help="push the image to this ECR repository URI (implies --image)")
    ap.add_argument("--base", default="python:3.11-slim", help="the base image; --push needs it pinned (name@sha256:...)")
    args = ap.parse_args(argv)
    repo = Path(_run(["git", "rev-parse", "--show-toplevel"]).strip())
    try:
        manifest = release(repo, args.tag, args.out, image=args.image or bool(args.push), repository=args.push, base=args.base)
    except ReleaseError as exc:
        print(f"release: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
