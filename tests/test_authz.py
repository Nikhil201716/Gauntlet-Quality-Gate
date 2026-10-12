"""Unit tests for the authorisation rules.

This is the suite the mutation gate judges: if these tests cannot tell a correct
``can_view`` from a broken one, their green checkmark is worthless. They are
written to pin down every branch -- owner, admin, other user, and anonymous --
so that the clean mutation score is high and any real weakening of the suite
(defect T1) shows up as a drop.
"""
from app.authz import can_edit, can_view, is_admin, owns, visible_notes

ALICE = {"id": 1, "username": "alice", "is_admin": 0}
BOB = {"id": 2, "username": "bob", "is_admin": 0}
ROOT = {"id": 9, "username": "root", "is_admin": 1}


def note(owner_id, note_id=100):
    return {"id": note_id, "owner_id": owner_id, "title": "t", "body": "b"}


# --- is_admin -----------------------------------------------------------------

def test_is_admin_true_for_admin():
    assert is_admin(ROOT) is True


def test_is_admin_false_for_ordinary_user():
    assert is_admin(ALICE) is False


def test_is_admin_false_for_anonymous():
    assert is_admin(None) is False


# --- owns ---------------------------------------------------------------------

def test_owns_true_for_owner():
    assert owns(note(1), ALICE) is True


def test_owns_false_for_other_user():
    assert owns(note(2), ALICE) is False


def test_owns_false_for_anonymous():
    assert owns(note(1), None) is False


# --- can_view -----------------------------------------------------------------

def test_can_view_owner_sees_own_note():
    assert can_view(note(1), ALICE) is True


def test_can_view_admin_sees_other_users_note():
    assert can_view(note(2), ROOT) is True


def test_can_view_other_user_is_denied():
    assert can_view(note(2), ALICE) is False


def test_can_view_anonymous_is_denied():
    assert can_view(note(1), None) is False


# --- can_edit (admins may read, not rewrite, others' notes) -------------------

def test_can_edit_owner_may_edit():
    assert can_edit(note(1), ALICE) is True


def test_can_edit_admin_may_not_edit_others():
    assert can_edit(note(2), ROOT) is False


def test_can_edit_other_user_denied():
    assert can_edit(note(2), ALICE) is False


# --- visible_notes ------------------------------------------------------------

def test_visible_notes_filters_to_owner():
    rows = [note(1, 10), note(2, 20)]
    vis = visible_notes(rows, ALICE)
    assert [n["id"] for n in vis] == [10]


def test_visible_notes_admin_sees_all():
    rows = [note(1, 10), note(2, 20)]
    assert len(visible_notes(rows, ROOT)) == 2


def test_visible_notes_anonymous_sees_none():
    assert visible_notes([note(1, 10)], None) == []
