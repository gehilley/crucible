"""SPEC.md §4 events: the closed vocabulary and the field rules.

Planted known answers: each test hands `validate` an event that breaks exactly
one rule and expects exactly that refusal, or a correct event and expects none.
"""

from __future__ import annotations

import pytest

from crucible_chain.events import (
    EVENT_TYPES,
    EVIDENCE_CLASSES,
    PROTOCOL_VERSION,
    EventError,
    digest_only,
    draft,
    validate,
)

SESSION = "0b6c3f6e-1f62-4c0e-9a51-6f0b0a8c2d11"


def full(**over):
    """A valid event, with any field overridden. A gap carries content null and no digest."""
    if over.get("type") == "gap":
        return {"v": PROTOCOL_VERSION, "session": SESSION, "seq": 0, "ts": 1_761_300_000_000_000, "actor": "tool:crucible",
                "class": "witnessed", "body": {}, "content": None, **over}
    event = {
        "v": PROTOCOL_VERSION,
        "session": SESSION,
        "seq": 0,
        "ts": 1_761_300_000_000_000,
        "type": "prompt",
        "actor": "human",
        "class": "witnessed",
        "body": {},
        **digest_only({"text": "hello"}),
    }
    event.update(over)
    return event


def test_the_vocabulary_is_exactly_spec_section_4():
    assert EVENT_TYPES == (
        "session.start",
        "session.end",
        "prompt",
        "response",
        "tool.call",
        "tool.result",
        "file.read",
        "file.write",
        "fetch",
        "context.injected",
        "gap",
    )
    assert EVIDENCE_CLASSES == ("witnessed", "sealed", "reconstructed")


def test_a_valid_event_passes():
    validate(full())


@pytest.mark.parametrize("t", EVENT_TYPES)
def test_every_type_in_the_vocabulary_is_accepted(t):
    body = {"could_not_see": "the chat surface"} if t == "gap" else {}
    validate(full(type=t, body=body))


@pytest.mark.parametrize("t", ["thought", "Prompt", "prompt ", "tool", "", None, 3])
def test_a_type_outside_the_vocabulary_is_refused(t):
    with pytest.raises(EventError, match="type"):
        validate(full(type=t))


@pytest.mark.parametrize(
    "actor", ["human", "model:claude-opus-5-5", "model:unknown", "tool:Read", "tool:mcp__srv__ping"]
)
def test_actors_in_the_grammar_are_accepted(actor):
    validate(full(actor=actor))


@pytest.mark.parametrize("actor", ["", "Human", "model:", "tool:", "model: x", "agent:x", "tool:a b", None])
def test_actors_outside_the_grammar_are_refused(actor):
    with pytest.raises(EventError, match="actor"):
        validate(full(actor=actor))


@pytest.mark.parametrize("cls", ["witnessed", "sealed"])
def test_witnessed_and_sealed_need_no_supplier(cls):
    validate(full(**{"class": cls}))


def test_reconstructed_names_its_supplier():
    validate(full(**{"class": "reconstructed", "supplier": "the operator, from memory"}))
    with pytest.raises(EventError, match="supplier"):
        validate(full(**{"class": "reconstructed"}))


def test_a_supplier_on_a_witnessed_event_is_refused():
    with pytest.raises(EventError, match="supplier"):
        validate(full(supplier="someone"))


@pytest.mark.parametrize("cls", ["observed", "", None])
def test_a_class_outside_the_three_is_refused(cls):
    with pytest.raises(EventError, match="class"):
        validate(full(**{"class": cls}))


def test_content_or_digest_plus_note_never_both_never_neither():
    whole = full()
    del whole["digest"], whole["note"]
    whole["content"] = {"text": "hello"}
    validate(whole)

    both = full(content={"text": "hello"})
    with pytest.raises(EventError, match="content"):
        validate(both)

    neither = full()
    del neither["digest"], neither["note"]
    with pytest.raises(EventError, match="content"):
        validate(neither)

    digest_without_note = full()
    del digest_without_note["note"]
    with pytest.raises(EventError, match="note"):
        validate(digest_without_note)


def test_digest_only_states_what_it_digested():
    out = digest_only({"text": "hello"})
    assert out["digest"].startswith("sha256:")
    assert out["note"] == {"reason": "digest_only", "of": "jcs", "size": len(b'{"text":"hello"}')}
    raw = digest_only(b"file bytes")
    assert raw["note"] == {"reason": "digest_only", "of": "bytes", "size": 10}


def test_a_gap_says_what_could_not_be_seen():
    validate(full(type="gap", body={"could_not_see": "the model's injected context"}))
    with pytest.raises(EventError, match="could_not_see"):
        validate(full(type="gap", body={}))


@pytest.mark.parametrize(
    "field,value",
    [("seq", -1), ("seq", True), ("seq", 1.0), ("ts", 0), ("ts", "now"), ("ts", 2**53), ("ts", 1_761_300_000_000_000_000), ("v", 1), ("session", ""), ("session", "has space")],
)
def test_malformed_scalars_are_refused(field, value):
    with pytest.raises(EventError, match=field):
        validate(full(**{field: value}))


def test_an_unknown_top_level_field_is_refused():
    with pytest.raises(EventError, match="unknown"):
        validate(full(extra=1))


def test_a_draft_has_no_chain_fields_and_validates_once_placed():
    d = draft("tool.call", "model:unknown", "witnessed", {"tool": "Read"}, content={"path": "a.txt"})
    assert set(d) >= {"type", "actor", "class", "body", "digest", "note"}
    assert not {"v", "session", "seq", "ts"} & set(d)
    validate({**d, "v": PROTOCOL_VERSION, "session": SESSION, "seq": 3, "ts": 5})


def test_a_draft_keeps_content_whole_only_when_asked():
    d = draft("prompt", "human", "witnessed", content={"text": "hi"}, keep_content=True)
    assert d["content"] == {"text": "hi"} and "digest" not in d


def _nested(depth):
    """A body that brings an event to ``depth`` levels (the event itself is 1)."""
    body: dict = {}
    node = body
    for _ in range(depth - 2):
        node["x"] = {}
        node = node["x"]
    return body


def test_an_event_may_nest_to_the_stated_depth_and_no_further():
    from crucible_chain.events import MAX_DEPTH

    validate(full(body=_nested(MAX_DEPTH)))
    with pytest.raises(EventError, match="nests deeper"):
        validate(full(body=_nested(MAX_DEPTH + 1)))
    with pytest.raises(EventError, match="nests deeper"):
        draft("prompt", "human", "witnessed", _nested(MAX_DEPTH + 1), content="x")
    with pytest.raises(EventError, match="nests deeper"):
        validate(full(body=_nested(983)))  # the depth that used to depend on the stack
