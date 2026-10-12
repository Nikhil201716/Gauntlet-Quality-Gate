"""Notekeeper: the small Flask application the quality gate is run against.

It is deliberately ordinary -- users register, log in, write notes, search
them, and an admin can export everything. Ordinary is the point: every defect
the harness injects (an SQL-injectable search, an unescaped render, a hard-coded
secret, MD5 password hashing, a missing admin check, missing security headers, a
toothless test, an IDOR on the note route) is the kind of thing that reaches
production in an ordinary app whose acceptance tests are green.
"""
