"""Authorisation rules -- pure functions, no framework, no database.

These are the rules the whole app's security *should* rest on: who may see a
note, who may edit it, who is an admin. Because they are small and pure they are
the natural home for a thorough unit test suite, and therefore the substrate the
mutation-testing gate mutates: if the suite cannot tell a correct ``can_view``
from a broken one, the gate says so.

The capstone lesson of the project lives in the gap between this module and the
web layer. These rules can be perfectly correct and exhaustively tested, and the
app can *still* leak data -- because a single route (the IDOR defect, G1) forgets
to call ``can_view`` at all. A mutation score of 100% here proves the rules have
teeth; it proves nothing about whether they are wired in.
"""
from __future__ import annotations

from typing import Mapping, Sequence


def is_admin(user: Mapping | None) -> bool:
    """True iff ``user`` is a signed-in administrator."""
    return user is not None and user["is_admin"] == 1


def owns(note: Mapping, user: Mapping | None) -> bool:
    """True iff ``user`` is the owner of ``note``."""
    return user is not None and note["owner_id"] == user["id"]


def can_view(note: Mapping, user: Mapping | None) -> bool:
    """A note may be viewed by its owner or by any admin."""
    return owns(note, user) or is_admin(user)


def can_edit(note: Mapping, user: Mapping | None) -> bool:
    """A note may be edited only by its owner -- admins may read, not rewrite."""
    return owns(note, user)


def visible_notes(notes: Sequence[Mapping], user: Mapping | None) -> list:
    """Filter ``notes`` down to the ones ``user`` is allowed to see."""
    return [n for n in notes if can_view(n, user)]
