"""Unit tests for storage and search scoping.

These assert the *functional* contract of search: it finds the caller's matching
notes and is scoped to the caller. They pass whether the query is parameterised
or built by string concatenation, because a benign query term behaves the same
either way -- which is why the SQL-injection defect sails past them and is caught
only by static analysis and a malicious-input probe.
"""
from app import db


def _fresh():
    con = db.connect()
    alice = db.create_user(con, "alice", "pw")
    bob = db.create_user(con, "bob", "pw")
    db.add_note(con, alice, "groceries", "milk")
    db.add_note(con, alice, "grocery list two", "eggs")
    db.add_note(con, bob, "groceries for bob", "ham")
    return con, alice, bob


def test_search_finds_matching_titles():
    con, alice, _ = _fresh()
    rows = db.search_notes(con, alice, "grocer")
    assert {r["title"] for r in rows} == {"groceries", "grocery list two"}


def test_search_is_scoped_to_owner():
    con, alice, bob = _fresh()
    rows = db.search_notes(con, alice, "grocer")
    assert all(r["owner_id"] == alice for r in rows)
    assert "groceries for bob" not in {r["title"] for r in rows}


def test_search_no_match_returns_empty():
    con, alice, _ = _fresh()
    assert db.search_notes(con, alice, "nonexistent") == []


def test_notes_for_returns_only_owner_notes():
    con, alice, bob = _fresh()
    assert len(db.notes_for(con, alice)) == 2
    assert len(db.notes_for(con, bob)) == 1
