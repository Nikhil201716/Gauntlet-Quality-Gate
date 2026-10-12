"""The defect catalog: one known problem per entry, injected as a source patch.

Each defect is one or more edits to the clean source (a literal find/replace) or
a whole-file swap. ``expected`` names the layers we *predict* will catch it; the
harness measures what actually happens and ``score.py`` checks the prediction.
Nothing about ``expected`` drives detection -- it exists only so the run can be
held to its own claims.

The classes span what a real pipeline faces:
  * ``logic``      -- a feature is wrong (the acceptance suite's job).
  * ``weak-test``  -- the tests pass but assert nothing useful (mutation's job).
  * ``vuln``       -- a security hole (SAST and/or DAST).
  * ``benign``     -- a harmless change that must trip nothing (false-positive check).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Edit:
    """A literal find/replace in one file (relative to the repo root)."""
    file: str
    old: str
    new: str


@dataclass(frozen=True)
class FileSwap:
    """Replace ``file`` wholesale with the contents of ``source``."""
    file: str
    source: str


@dataclass(frozen=True)
class Defect:
    id: str
    name: str
    klass: str
    is_defect: bool
    expected: tuple[str, ...]
    desc: str
    edits: tuple = field(default_factory=tuple)


# --- the clean strings each edit targets (kept here so a source edit that drifts
#     from the code fails loudly instead of silently no-op'ing) -----------------

_CLEAN_SEARCH_DB = (
    '    sql = "SELECT * FROM notes WHERE owner_id = ? AND title LIKE ? ORDER BY id"\n'
    '    return con.execute(sql, (owner_id, f"%{query}%")).fetchall()'
)
_CLEAN_SEARCH_ROUTE = (
    '        q = request.args.get("q", "")\n'
    '        results = db.search_notes(con, user["id"], q)'
)
_CLEAN_VIEW_RENDER = (
    "        if not can_view(note, user):\n"
    "            abort(403)\n"
    "        return render_template_string(NOTE_TMPL, note=note, user=user)"
)
_CLEAN_ADMIN_GUARD = (
    "        user = current_user()\n"
    "        if not is_admin(user):\n"
    "            abort(403)\n"
    "        notes = db.all_notes(con)"
)
_CLEAN_HEADERS = (
    "    @app.after_request\n"
    "    def _apply_security_headers(response):\n"
    "        for name, value in config.SECURITY_HEADERS.items():\n"
    "            response.headers[name] = value\n"
    "        return response"
)
_CLEAN_HASH = (
    '    digest = hashlib.pbkdf2_hmac(\n'
    '        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS\n'
    '    )\n'
    '    return salt.hex() + "$" + digest.hex()'
)
_CLEAN_VERIFY = (
    '    salt_hex, _, digest_hex = stored.partition("$")\n'
    '    try:\n'
    '        salt = bytes.fromhex(salt_hex)\n'
    '    except ValueError:\n'
    '        return False\n'
    '    check = hashlib.pbkdf2_hmac(\n'
    '        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS\n'
    '    )\n'
    '    return hmac.compare_digest(check.hex(), digest_hex)'
)
_CLEAN_TOKEN = 'API_TOKEN = os.environ.get("GAUNTLET_API_TOKEN", "")'


CATALOG: tuple[Defect, ...] = (
    Defect(
        id="L1", name="search ignores the query", klass="logic", is_defect=True,
        expected=("bdd",),
        desc="the /search route returns all of the user's notes regardless of the "
             "query -- a plain functional bug the acceptance suite should catch.",
        edits=(Edit("app/web.py", _CLEAN_SEARCH_ROUTE,
                    '        q = request.args.get("q", "")\n'
                    '        results = db.notes_for(con, user["id"])'),),
    ),
    Defect(
        id="L2", name="search drops owner scoping", klass="logic", is_defect=True,
        expected=("unit", "dast"),
        desc="search no longer filters by owner, so one user's search returns "
             "another user's notes -- caught by the storage unit test and by a "
             "runtime probe, but it leaves no dangerous pattern for SAST.",
        edits=(Edit("app/db.py", _CLEAN_SEARCH_DB,
                    '    sql = "SELECT * FROM notes WHERE title LIKE ? ORDER BY id"\n'
                    '    return con.execute(sql, (f"%{query}%",)).fetchall()'),),
    ),
    Defect(
        id="T1", name="toothless authz unit tests", klass="weak-test", is_defect=True,
        expected=("mutation",),
        desc="the authz unit suite is swapped for a shallow one that still passes "
             "(green!) but no longer pins the admin/anonymous branches; only the "
             "mutation gate notices the lost coverage.",
        edits=(FileSwap("tests/test_authz.py",
                        "harness/variants/test_authz_weak.py"),),
    ),
    Defect(
        id="S1", name="SQL-injectable search", klass="vuln", is_defect=True,
        expected=("sast", "dast"),
        desc="search is rebuilt as an f-string, so owner_id and the term are "
             "interpolated into the SQL -- Bandit (B608) sees it statically and a "
             "probe confirms it leaks other users' notes.",
        edits=(Edit("app/db.py", _CLEAN_SEARCH_DB,
                    '    sql = f"SELECT * FROM notes WHERE owner_id = {owner_id} '
                    "AND title LIKE '%{query}%' ORDER BY id\"\n"
                    '    return con.execute(sql).fetchall()'),),
    ),
    Defect(
        id="S2", name="stored XSS on the note page", klass="vuln", is_defect=True,
        expected=("sast", "dast"),
        desc="the note view builds HTML by string concatenation and passes it to "
             "render_template_string, bypassing autoescaping -- a custom SAST rule "
             "flags the dynamic template and a probe confirms the script survives.",
        edits=(Edit("app/web.py", _CLEAN_VIEW_RENDER,
                    '        return render_template_string("<h1>" + note["title"] '
                    '+ "</h1><div class=body>" + note["body"] + "</div>")'),),
    ),
    Defect(
        id="S3", name="hard-coded secret", klass="vuln", is_defect=True,
        expected=("sast",),
        desc="a live-looking API token is hard-coded into config -- invisible to "
             "every runtime test (the app behaves identically) and caught only by "
             "static analysis (Bandit B105).",
        edits=(Edit("app/config.py", _CLEAN_TOKEN,
                    'API_TOKEN = "tok_live_9a8b7c6d5e4f3a2b1c0d"'),),
    ),
    Defect(
        id="S4", name="MD5 password hashing", klass="vuln", is_defect=True,
        expected=("sast",),
        desc="passwords are hashed with bare MD5 instead of PBKDF2 -- login still "
             "works so no functional test fails; only SAST (Bandit B324) sees the "
             "weak hash.",
        edits=(
            Edit("app/security.py", _CLEAN_HASH,
                 '    return hashlib.md5(password.encode("utf-8")).hexdigest()'),
            Edit("app/security.py", _CLEAN_VERIFY,
                 '    return hmac.compare_digest(\n'
                 '        hashlib.md5(password.encode("utf-8")).hexdigest(), stored)'),
        ),
    ),
    Defect(
        id="S5", name="missing admin authorization", klass="vuln", is_defect=True,
        expected=("dast",),
        desc="the admin export drops its is_admin check, so any logged-in user can "
             "export every note -- there is no dangerous pattern for SAST, and no "
             "acceptance scenario tests it; only a runtime probe catches it.",
        edits=(Edit("app/web.py", _CLEAN_ADMIN_GUARD,
                    "        user = current_user()\n"
                    "        notes = db.all_notes(con)"),),
    ),
    Defect(
        id="S6", name="missing security headers", klass="vuln", is_defect=True,
        expected=("dast",),
        desc="the after_request hook stops adding X-Content-Type-Options / CSP / "
             "X-Frame-Options -- an absence no static rule flags, caught only by "
             "inspecting a real response.",
        edits=(Edit("app/web.py", _CLEAN_HEADERS,
                    "    @app.after_request\n"
                    "    def _apply_security_headers(response):\n"
                    "        return response"),),
    ),
    Defect(
        id="G1", name="IDOR on the note route", klass="vuln", is_defect=True,
        expected=(),  # the honest gap: no layer here catches it
        desc="the note view stops calling can_view, so any logged-in user can read "
             "any note by id. The authz rules are still correct and fully tested "
             "(mutation stays 100%); the app leaks anyway because one route forgot "
             "to call them -- and no layer in this gate happens to probe for it.",
        edits=(Edit("app/web.py", _CLEAN_VIEW_RENDER,
                    "        return render_template_string"
                    "(NOTE_TMPL, note=note, user=user)"),),
    ),
    Defect(
        id="N1", name="benign display constant", klass="benign", is_defect=False,
        expected=(),
        desc="a harmless, unused display-name constant -- the control: a change "
             "that is not a defect, to check the gate does not cry wolf.",
        edits=(Edit("app/config.py", _CLEAN_TOKEN,
                    _CLEAN_TOKEN + '\nAPP_NAME = "Notekeeper"  '
                    "# benign display name, nothing security-relevant"),),
    ),
)
