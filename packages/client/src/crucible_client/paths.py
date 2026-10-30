"""Where the client keeps its state.

``$CRUCIBLE_HOME`` if set; otherwise ``crucible`` under ``$XDG_STATE_HOME``,
which defaults to ``~/.local/state``. Everything the client writes lives here:
the chain (``chain.sqlite``), and the local logs of envelope drift and hook
errors, which never enter the chain.
"""

from __future__ import annotations

import os
from pathlib import Path


def client_home() -> Path:
    """Always absolute: a relative home would follow each hook's working directory."""
    if explicit := os.environ.get("CRUCIBLE_HOME"):
        return Path(explicit).absolute()
    state = os.environ.get("XDG_STATE_HOME", "")
    if not os.path.isabs(state):  # the XDG spec: a relative value is to be ignored
        state = str(Path.home() / ".local" / "state")
    return Path(state) / "crucible"


def chain_path(home: Path | None = None) -> Path:
    return (home or client_home()) / "chain.sqlite"


def drift_log(home: Path | None = None) -> Path:
    return (home or client_home()) / "drift.jsonl"


def error_log(home: Path | None = None) -> Path:
    return (home or client_home()) / "hook-errors.jsonl"


__all__ = ["chain_path", "client_home", "drift_log", "error_log"]
