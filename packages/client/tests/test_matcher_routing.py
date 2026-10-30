"""The matcher the client installs routed every tool the real client called
(tests/fixtures/hooks/matcher-routing.json, scripts/capture_matcher_routing.py)."""

from __future__ import annotations

import json
from pathlib import Path

from crucible_client.envelopes import TOOL_MATCHER

ROUTING = json.loads((Path(__file__).parent / "fixtures" / "hooks" / "matcher-routing.json").read_text())


def test_the_installed_matcher_routed_every_tool_observed():
    label = next(k for k, m in ROUTING["matchers"].items() if m == TOOL_MATCHER)
    observed = {o["tool"]: o["fired"] for o in ROUTING["observations"]}
    assert set(ROUTING["tools_called"]) <= set(observed)
    assert all(label in fired for fired in observed.values()), observed


def test_the_capture_can_tell_a_narrow_matcher_from_a_wide_one():
    """A fixture in which every matcher fired for everything would show nothing."""
    narrow = {o["tool"] for o in ROUTING["observations"] if "alternation" in o["fired"]}
    assert narrow == {"Bash", "Read"} and "mcp__probe__probe_ping" not in narrow
