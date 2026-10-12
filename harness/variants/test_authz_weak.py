"""Defect T1: a plausible but toothless authz suite.

This is what a green suite looks like when nobody checked the edges. It tests the
two cases a developer thinks of first -- the owner can see their note, a stranger
cannot -- and stops there. It never passes ``None`` (anonymous) and never checks
the admin override, so the boolean-operator mutants that only misbehave on those
inputs survive. Every test here passes; pytest is green. Only the mutation gate
notices the suite lost its teeth.
"""
from app.authz import can_view, owns


def note(owner_id):
    return {"id": 100, "owner_id": owner_id, "title": "t", "body": "b"}


def test_owner_can_view_own_note():
    assert can_view(note(1), {"id": 1, "is_admin": 0})


def test_other_user_cannot_view():
    assert not can_view(note(2), {"id": 1, "is_admin": 0})


def test_owns_is_true_for_owner():
    assert owns(note(1), {"id": 1, "is_admin": 0})
