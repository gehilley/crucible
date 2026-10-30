"""Fixtures shared by every package's tests.

Deterministic key material, so goldens are byte-stable across runs. These seeds
are never used outside tests.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from crucible_core.keys import PrivateKey, compute_key_id

_RESEARCHER_SEED = bytes(range(32))
_SERVICE_SEED = bytes(range(32, 64))


def _key_id_for(seed: bytes) -> str:
    pub = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return compute_key_id(pub)


@pytest.fixture
def researcher_key() -> PrivateKey:
    """A fixed researcher identity (the client's signing key)."""
    return PrivateKey(
        role="researcher",
        key_id=_key_id_for(_RESEARCHER_SEED),
        private_bytes=_RESEARCHER_SEED,
        label="test-researcher",
    )


@pytest.fixture
def service_key() -> PrivateKey:
    """A fixed service identity (signs checkpoints and receipts)."""
    return PrivateKey(
        role="service",
        key_id=_key_id_for(_SERVICE_SEED),
        private_bytes=_SERVICE_SEED,
        label="test-service",
    )


# --- this repository, copied ------------------------------------------------------------


def _tracked(root: Path) -> list[str]:
    """The files git would commit from ``root``'s working tree: tracked, or untracked and not ignored."""
    listing = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root,
                             capture_output=True, text=True, check=True).stdout
    return [f for f in filter(None, listing.split("\0")) if (root / f).is_file()]


@pytest.fixture(scope="session")
def copy_tracked_tree():
    """copy_tracked_tree(dest): this working tree's files, copied into ``dest``: what a release
    built from a tag of this tree would hold."""
    if not shutil.which("git"):
        pytest.skip("git is not available")
    root = Path(__file__).resolve().parent

    def copy(dest: Path) -> None:
        for f in _tracked(root):
            (dest / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / f, dest / f)

    return copy


# --- a real service on a real socket, per test ---------------------------------------


class EphemeralService:
    """A `crucible_service` on a temp journal and an OS-chosen port, under real uvicorn.

    Ported from v1's ``ephemeral_notary`` (``../crucible/conftest.py:864-921``): a
    real server rather than an ASGI shim, because what a client test exercises is
    HTTP -- status codes, connections, the client's own transport. `stop` and
    `start` restart it on the same port, and every start rebuilds the service
    from the journal alone, as a fresh process would.
    """

    def __init__(self, journal: Path, key: PrivateKey, name: str = "test.service", *, release=None) -> None:
        from crucible_service.journal import DirStore
        from crucible_service.log import TransparencyLog
        from crucible_service.signer import LocalSigner

        self.journal, self.key, self.name, self.release = journal, key, name, release
        TransparencyLog.create(DirStore(journal), LocalSigner(key), service=name, log_id="log-ephemeral")
        self.port: int = 0
        self.service = None
        self._server = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        import uvicorn

        from crucible_service.api import create_app
        from crucible_service.journal import DirStore
        from crucible_service.log import TransparencyLog
        from crucible_service.service import Service
        from crucible_service.signer import LocalSigner

        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self.port))
        self.port = sock.getsockname()[1]
        self.service = Service(TransparencyLog.open(DirStore(self.journal), LocalSigner(self.key)))
        self._server = uvicorn.Server(uvicorn.Config(create_app(self.service, release=self.release), log_level="warning"))
        self._thread = threading.Thread(target=lambda: self._server.run(sockets=[sock]), daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 20.0
        while not self._server.started:
            if time.monotonic() > deadline or not self._thread.is_alive():
                raise RuntimeError("the ephemeral service did not start")
            time.sleep(0.01)

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
            self._thread.join(timeout=20.0)
            self._server = None


@pytest.fixture
def ephemeral_service(tmp_path, service_key) -> Iterator[EphemeralService]:
    svc = EphemeralService(tmp_path / "ephemeral-service" / "journal", service_key)
    svc.start()
    try:
        yield svc
    finally:
        svc.stop()


@pytest.fixture
def make_service(tmp_path, service_key):
    """make_service(release=None): another EphemeralService, started; stopped at teardown."""
    made = []

    def make(release=None):
        svc = EphemeralService(tmp_path / f"service-{len(made)}" / "journal", service_key, release=release)
        svc.start()
        made.append(svc)
        return svc

    yield make
    for svc in made:
        svc.stop()
