"""The four-valued result (SPEC.md §4 Honesty rule)."""

from __future__ import annotations

import json

import pytest

from crucible_verify.results import BooleanCoercionError, Check, ResultError, State


def test_there_are_exactly_four_states_and_they_are_their_json_tokens():
    assert [s.value for s in State] == ["pass", "fail", "not_applicable", "could_not_check"]
    assert json.dumps(State.COULD_NOT_CHECK) == '"could_not_check"'


@pytest.mark.parametrize("state", list(State))
def test_a_state_refuses_to_be_a_boolean(state):
    with pytest.raises(BooleanCoercionError):
        bool(state)
    with pytest.raises(TypeError):  # still a TypeError, for callers that catch that
        if state:
            pass


def test_the_four_marks_differ_in_word_and_case():
    marks = [s.mark for s in State]
    assert marks == ["pass", "FAIL", "n/a", "UNCHECKED"]
    assert len(set(marks)) == 4


@pytest.mark.parametrize("state", list(State))
def test_every_state_needs_a_reason(state):
    Check("chain", state, "the chain replays to its head")
    for empty in ["", "   ", "-", "???"]:
        with pytest.raises(ResultError):
            Check("chain", state, empty)


def test_a_check_refuses_to_be_a_boolean():
    with pytest.raises(BooleanCoercionError):
        bool(Check("chain", State.PASS, "intact"))


def test_a_check_name_has_a_shape():
    for bad in ["", "Chain", "chain check", "chain/"]:
        with pytest.raises(ResultError):
            Check(bad, State.PASS, "intact")


def test_a_check_round_trips_through_json():
    c = Check("receipts", State.COULD_NOT_CHECK, "no service public key was given")
    assert Check.from_json(json.loads(json.dumps(c.to_json()))) == c


def test_a_state_given_as_a_bare_string_is_refused():
    with pytest.raises(ResultError):
        Check("chain", "pass", "intact")  # type: ignore[arg-type]
