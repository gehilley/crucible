"""What the client sends the service (SPEC.md §3 Installation and Sending).

Two messages, each a COSE_Sign1 signed by the researcher's key and sent as
base64:

* a **registration**, whose payload carries the public key it is signed by:
  ``{"v": 2, "kind": "register", "public_key": {...}}``;
* a **batch** of consecutive events from one session's chain:
  ``{"v": 2, "kind": "batch", "session", "from_seq", "to_seq", "prev_head",
  "head", "events", "heads"}``, where ``heads`` is every event's chain head
  and ``head`` the last of them. Carrying each head lets the service hold the
  same record the client does, and name the exact event at which a batch, or a
  record, breaks.

This module only builds them. The service parses and checks what it receives
with its own code (``crucible_service.service``).
"""

from __future__ import annotations

import base64
from collections.abc import Sequence

from crucible_core.cose import sign
from crucible_core.keys import PrivateKey

from .chain import GENESIS
from .events import PROTOCOL_VERSION


def registration(key: PrivateKey) -> str:
    payload = {"v": PROTOCOL_VERSION, "kind": "register", "public_key": key.public().to_dict()}
    return base64.b64encode(sign(payload, key)).decode("ascii")


def batch_payload(records: Sequence[dict], prev_head: str | None = None) -> dict:
    """A batch of consecutive ``{"seq", "head", "event"}`` records."""
    if not records:
        raise ValueError("a batch carries at least one event")
    first, last = records[0], records[-1]
    return {
        "v": PROTOCOL_VERSION,
        "kind": "batch",
        "session": first["event"]["session"],
        "from_seq": first["seq"],
        "to_seq": last["seq"],
        "prev_head": prev_head if prev_head is not None else GENESIS,
        "head": last["head"],
        "events": [r["event"] for r in records],
        "heads": [r["head"] for r in records],
    }


def batch(key: PrivateKey, records: Sequence[dict], prev_head: str | None = None) -> str:
    return base64.b64encode(sign(batch_payload(records, prev_head), key)).decode("ascii")


__all__ = ["batch", "batch_payload", "registration"]
