"""Rate limits (docs/phase0-deployment.md, "Abuse"): per client address and per key.

Every registration of a new key and every batch becomes a leaf of a write-once
journal, which nothing can remove, so the limits sit in front of the writes.
Each is a token bucket: ``burst`` requests at once, refilled at ``rate`` per
second. A refused request is answered 429 with ``Retry-After``; the client's
sender waits that long and sends the same batch again, so a limit slows a
client and loses nothing.

The client address is the peer's, except behind a trusted proxy (Caddy, on
the Docker bridge): then it is the last ``X-Forwarded-For`` entry, the one that
proxy appended. A header from anyone else is ignored.
"""

from __future__ import annotations

import ipaddress
import math
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    burst: float
    rate: float  # tokens per second


# New keys (each a permanent leaf): twenty at once from one address -- a workshop behind one
# NAT -- then one every two minutes; re-registering a held key is not charged. A live session
# sends about one batch a second, and a catch-up after a day offline a few hundred in a row.
REGISTER = Rule(burst=20, rate=1 / 120)
BATCH_PER_ADDRESS = Rule(burst=300, rate=5)
BATCH_PER_KEY = Rule(burst=300, rate=2)
READ = Rule(burst=120, rate=5)


class Buckets:
    """Token buckets by name, the least recently used dropped beyond ``size``."""

    def __init__(self, rule: Rule, *, clock: Callable[[], float] = time.monotonic, size: int = 100_000) -> None:
        self.rule, self.clock, self.size = rule, clock, size
        self._state: OrderedDict[str, tuple[float, float]] = OrderedDict()  # name -> (tokens, at)
        self._lock = threading.Lock()

    def take(self, name: str) -> float | None:
        """Spend a token for ``name``: None if there was one, else the seconds until there is."""
        now = self.clock()
        with self._lock:
            tokens, at = self._state.pop(name, (self.rule.burst, now))
            tokens = min(self.rule.burst, tokens + (now - at) * self.rule.rate)
            wait = None if tokens >= 1 else (1 - tokens) / self.rule.rate
            self._state[name] = (tokens - 1 if wait is None else tokens, now)
            while len(self._state) > self.size:
                self._state.popitem(last=False)
        return wait


class Limits:
    def __init__(self, *, trusted_proxies: tuple[str, ...] = (), clock: Callable[[], float] = time.monotonic,
                 register: Rule = REGISTER, batch_address: Rule = BATCH_PER_ADDRESS, batch_key: Rule = BATCH_PER_KEY,
                 read: Rule = READ) -> None:
        self.trusted = tuple(ipaddress.ip_network(n) for n in trusted_proxies)
        self.register = Buckets(register, clock=clock)
        self.batch_address = Buckets(batch_address, clock=clock)
        self.batch_key = Buckets(batch_key, clock=clock)
        self.read = Buckets(read, clock=clock)

    def address(self, peer: str | None, forwarded: str | None) -> str:
        """The client's address: the peer's, or behind a trusted proxy the entry it appended."""
        peer = peer or "unknown"
        try:
            behind = any(ipaddress.ip_address(peer) in n for n in self.trusted)
        except ValueError:
            behind = False
        if behind and forwarded:
            last = forwarded.split(",")[-1].strip()
            try:
                return str(ipaddress.ip_address(last))
            except ValueError:
                return peer
        return peer


def retry_after(wait: float) -> str:
    return str(max(1, math.ceil(wait)))


__all__ = ["BATCH_PER_ADDRESS", "BATCH_PER_KEY", "READ", "REGISTER", "Buckets", "Limits", "Rule", "retry_after"]
