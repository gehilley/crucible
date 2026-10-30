"""The four-valued result model (SPEC.md §4 Honesty rule).

Every verdict the system produces about a record is one of four values:

===================  ==================================================
``pass``             the property was checked and holds
``fail``             the property was checked and does not hold
``not_applicable``   the property does not apply here, and why
``could_not_check``  the check could not be performed, and why
===================  ==================================================

``could_not_check`` is never rendered as pass, never counted toward a pass rate,
and never hidden behind a summary. Ported from v1's ``crucible_verify.results``,
keeping its four states and the rules below, and leaving out its six-valued
aggregate verdict, which rounded the four into more (``docs/v1-audit.md`` §0
finding 5).

**A reason is required on all four states.** A report that prints reasons only
for failures teaches its readers that a bare line means success, and then an
empty reason on a ``could_not_check`` reads as success too. The check is shape,
not substance: it refuses empty, blank and punctuation-only text.

**No boolean coercion.** ``State`` and ``Check`` raise from ``__bool__``: ``if
check:`` would be true for all four values, so the arm for "the property holds"
would run for a property nobody looked at.

**The four render differently in word and case** (``pass``, ``FAIL``, ``n/a``,
``UNCHECKED``), so a reader skimming a column cannot take an unchecked line for
a passing one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class ResultError(ValueError):
    """A result would be constructed outside its vocabulary."""


class BooleanCoercionError(TypeError):
    """A four-valued object was used where a boolean was expected."""


class State(StrEnum):
    """The four results. A `StrEnum`, so a state *is* its JSON token."""

    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    COULD_NOT_CHECK = "could_not_check"

    def __bool__(self) -> bool:
        raise BooleanCoercionError(
            f"a State is four-valued and must not be used as a boolean: this one is {self.value!r}. "
            f"Compare it against a State, or match on it"
        )

    @property
    def mark(self) -> str:
        """The label every rendering of this state uses."""
        return _MARKS[self]


_MARKS: Final[dict[State, str]] = {
    State.PASS: "pass",
    State.FAIL: "FAIL",
    State.NOT_APPLICABLE: "n/a",
    State.COULD_NOT_CHECK: "UNCHECKED",
}

_NAME_RE = re.compile(r"(?:[a-z0-9]+)(?:[._-][a-z0-9]+)*")


def require_reason(value: object, what: str = "reason") -> str:
    """A non-empty, non-blank string with at least one letter in it."""
    if not isinstance(value, str):
        raise ResultError(f"{what} must be a string, not {type(value).__name__}")
    text = value.strip()
    if not text:
        raise ResultError(f"{what} must not be empty: a result that cannot say why is silence")
    if not any(ch.isalpha() for ch in text):
        raise ResultError(f"{what} must contain words, not only punctuation: {value!r}")
    return text


@dataclass(frozen=True)
class Check:
    """One named property, its state, and why."""

    name: str
    state: State
    reason: str

    def __post_init__(self) -> None:
        if not (isinstance(self.name, str) and _NAME_RE.fullmatch(self.name)):
            raise ResultError(f"check name {self.name!r} is not lower-case words joined by . _ -")
        if type(self.state) is not State:
            raise ResultError(f"state must be a State, not {type(self.state).__name__} {self.state!r}")
        object.__setattr__(self, "reason", require_reason(self.reason))

    def __bool__(self) -> bool:
        raise BooleanCoercionError(f"a Check is four-valued and must not be used as a boolean: {self.name}")

    def to_json(self) -> dict:
        return {"name": self.name, "state": self.state.value, "reason": self.reason}

    @classmethod
    def from_json(cls, data: dict) -> Check:
        try:
            return cls(data["name"], State(data["state"]), data["reason"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ResultError(f"not a check: {data!r}") from exc

    def render(self) -> str:
        return f"{self.name:<10} {self.state.mark:<9} {self.reason}"


__all__ = ["BooleanCoercionError", "Check", "ResultError", "State", "require_reason"]
