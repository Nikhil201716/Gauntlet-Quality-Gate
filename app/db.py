"""SQLite storage and the one query that matters: note search.

The clean ``search_notes`` is a parameterised, owner-scoped query -- the safe,
boring way. The SQL-injection defect (S1) rebuilds the same query as an f-string
with the owner id and the search term interpolated straight in. That change is
visible two ways: statically (bandit B608 sees a string-built SQL statement) and
dynamically (a probe that searches for ``' OR '1'='1`` gets back notes belonging
to another user). Both gates catch it; a functional "search finds my note" test
does not, because search still works.
"""
from __future__ import annotations

import sqlite3

from app.security import hash_password

SCHEMA = """
CREATE TABLE users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    pw       TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE notes (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    title    TEXT NOT NULL,
    body     TEXT NOT NULL
);
"""


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def create_user(con: sqlite3.Connection, username: str, password: str,
                is_admin: int = 0) -> int:
    cur = con.execute(
        "INSERT INTO users (username, pw, is_admin) VALUES (?, ?, ?)",
        (username, hash_password(password), is_admin),
    )
    con.commit()
    return int(cur.lastrowid)


def get_user(con: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return con.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def get_user_by_id(con: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return con.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def add_note(con: sqlite3.Connection, owner_id: int, title: str, body: str) -> int:
    cur = con.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (owner_id, title, body),
    )
    con.commit()
    return int(cur.lastrowid)


def get_note(con: sqlite3.Connection, note_id: int) -> sqlite3.Row | None:
    return con.execute(
        "SELECT * FROM notes WHERE id = ?", (note_id,)
    ).fetchone()


def notes_for(con: sqlite3.Connection, owner_id: int) -> list[sqlite3.Row]:
    return con.execute(
        "SELECT * FROM notes WHERE owner_id = ? ORDER BY id", (owner_id,)
    ).fetchall()


def all_notes(con: sqlite3.Connection) -> list[sqlite3.Row]:
    return con.execute("SELECT * FROM notes ORDER BY id").fetchall()


def search_notes(con: sqlite3.Connection, owner_id: int,
                 query: str) -> list[sqlite3.Row]:
    """Return the caller's own notes whose title matches ``query``.

    Parameterised and owner-scoped: the search term is a *bound value*, never
    part of the SQL text, so ``' OR '1'='1`` is matched as a literal title
    fragment and finds nothing.
    """
    sql = "SELECT * FROM notes WHERE owner_id = ? AND title LIKE ? ORDER BY id"
    return con.execute(sql, (owner_id, f"%{query}%")).fetchall()
