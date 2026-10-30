"""The client's configuration, written once by ``crucible install`` (step 8).

``<home>/config.json``::

    {"v": 1, "service": "https://log.cruciblehub.org", "service_key": {<public key>}}

``<home>/researcher.key.json`` is the researcher's private key (mode 0600).
There is no default service (SPEC.md §3): a client with no configuration sends
nothing, rather than sending to a service nobody chose. The service key is the
one the receipts must be signed by; it is pinned when the client is installed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from crucible_core import atomic
from crucible_core.keys import KeyError_, PrivateKey, PublicKey

from . import paths

VERSION = 1


class ConfigError(Exception):
    """The client is not configured, or its configuration cannot be read."""


@dataclass(frozen=True)
class Config:
    service: str
    service_key: PublicKey
    key: PrivateKey
    home: Path


def config_path(home: Path | None = None) -> Path:
    return (home or paths.client_home()) / "config.json"


def key_path(home: Path | None = None) -> Path:
    return (home or paths.client_home()) / "researcher.key.json"


def load(home: Path | None = None) -> Config:
    home = home or paths.client_home()
    try:
        data = json.loads(config_path(home).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"no client configuration at {config_path(home)}; run `crucible install <service-address>`") from exc
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read {config_path(home)}: {exc}") from exc
    if not (isinstance(data, dict) and data.get("v") == VERSION and isinstance(data.get("service"), str) and data["service"]):
        raise ConfigError(f"{config_path(home)} is not a version {VERSION} client configuration")
    try:
        service_key = PublicKey.from_dict(data.get("service_key"))
        key = PrivateKey.read(key_path(home))
    except (KeyError_, OSError, ValueError) as exc:
        raise ConfigError(f"the client's keys cannot be read: {exc}") from exc
    if service_key.role != "service" or key.role != "researcher":
        raise ConfigError("the configured keys do not have the service and researcher roles")
    return Config(data["service"].rstrip("/"), service_key, key, home)


def save(home: Path, service: str, service_key: PublicKey) -> Path:
    doc = {"v": VERSION, "service": service.rstrip("/"), "service_key": service_key.to_dict()}
    return atomic.write_json(config_path(home), doc, sort_keys=True)


__all__ = ["Config", "ConfigError", "config_path", "key_path", "load", "save"]
