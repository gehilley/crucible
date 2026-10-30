from __future__ import annotations

import pytest

from crucible_chain.events import draft
from crucible_chain.store import ChainStore
from crucible_core.keys import PrivateKey
from crucible_service.journal import DirStore
from crucible_service.log import TransparencyLog
from crucible_service.service import Service
from crucible_service.signer import LocalSigner


@pytest.fixture
def journal(tmp_path):
    return DirStore(tmp_path / "journal")


@pytest.fixture
def signer(service_key):
    return LocalSigner(service_key)


@pytest.fixture
def svc(journal, signer):
    log = TransparencyLog.create(journal, signer, service="test.service", log_id="log-test")
    return Service(log)


@pytest.fixture
def chain(tmp_path):
    """chain(session, n): a client store with n events in ``session``; returns its records."""
    store = ChainStore(tmp_path / "client.sqlite")

    def make(session="s-1", n=10, start=0):
        for i in range(start, start + n):
            store.append(session, draft("tool.result", "tool:Bash", "witnessed", {"i": i}, content={"out": i}))
        return [r.as_record() for r in store.records(session)]

    yield make
    store.close()


@pytest.fixture
def other_researcher():
    return PrivateKey.generate("researcher", label="someone else")
