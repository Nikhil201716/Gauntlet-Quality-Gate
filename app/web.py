"""The Flask application factory.

Every route here is the clean, secure version. The harness produces each
insecure variant by patching exactly one spot:

* ``/search``            -- calls ``db.search_notes`` (parameterised).   [S1 target]
* ``view_note``          -- renders via a constant template, autoescaped. [S2 target]
* ``view_note``          -- guards with ``can_view`` before returning.    [G1 target]
* ``admin_export``       -- guards with ``is_admin``.                     [S5 target]
* ``_apply_security_headers`` -- adds the headers on every response.      [S6 target]
* ``/search`` result set -- honours the query string.                    [L1 target]

The secret/crypto defects (S3/S4) live in ``config`` and ``security``.
"""
from __future__ import annotations

from flask import (
    Flask, abort, redirect, render_template_string, request, session, url_for,
)

from app import config, db
from app.authz import can_view, is_admin

# --- templates (constant strings; render_template_string autoescapes them) ----

_PAGE = """<!doctype html><title>Notekeeper</title>
<style>body{{font-family:sans-serif;max-width:40rem;margin:2rem auto}}</style>
<h2>Notekeeper</h2>{body}"""

LOGIN_TMPL = _PAGE.format(body="""
<form method=post><h3>Log in</h3>
<p><input name=username placeholder=username></p>
<p><input name=password type=password placeholder=password></p>
<button>Log in</button></form>
<p><a href="{{ url_for('register') }}">register</a></p>
{% if error %}<p style=color:red>{{ error }}</p>{% endif %}""")

REGISTER_TMPL = _PAGE.format(body="""
<form method=post><h3>Register</h3>
<p><input name=username placeholder=username></p>
<p><input name=password type=password placeholder=password></p>
<button>Register</button></form>
{% if error %}<p style=color:red>{{ error }}</p>{% endif %}""")

DASHBOARD_TMPL = _PAGE.format(body="""
<p>Signed in as <b>{{ user['username'] }}</b>
{% if user['is_admin'] %}(admin){% endif %}
&mdash; <a href="{{ url_for('logout') }}">log out</a></p>
<form method=get action="{{ url_for('search') }}">
<input name=q placeholder="search titles"><button>Search</button></form>
<h3>Your notes</h3><ul>
{% for n in notes %}<li><a href="{{ url_for('view_note', note_id=n['id']) }}">
{{ n['title'] }}</a></li>{% endfor %}</ul>
<form method=post action="{{ url_for('new_note') }}"><h3>New note</h3>
<p><input name=title placeholder=title></p>
<p><textarea name=body placeholder=body></textarea></p>
<button>Save</button></form>""")

NOTE_TMPL = _PAGE.format(body="""
<p><a href="{{ url_for('dashboard') }}">&larr; back</a></p>
<h3>{{ note['title'] }}</h3>
<div class=body>{{ note['body'] }}</div>""")

SEARCH_TMPL = _PAGE.format(body="""
<p><a href="{{ url_for('dashboard') }}">&larr; back</a></p>
<h3>Results for &ldquo;{{ q }}&rdquo;</h3><ul>
{% for n in notes %}<li><a href="{{ url_for('view_note', note_id=n['id']) }}">
{{ n['title'] }}</a> &mdash; owner {{ n['owner_id'] }}</li>{% endfor %}</ul>""")

ADMIN_TMPL = _PAGE.format(body="""
<h3>All notes (admin export)</h3><ul>
{% for n in notes %}<li>#{{ n['id'] }} owner {{ n['owner_id'] }}:
{{ n['title'] }}</li>{% endfor %}</ul>""")


def create_app(seed: bool = True) -> Flask:
    app = Flask(__name__)
    app.secret_key = config.SECRET_KEY
    con = db.connect()
    app.config["DB"] = con
    if seed:
        _seed(con)

    def current_user() -> dict | None:
        uid = session.get("uid")
        if uid is None:
            return None
        row = db.get_user_by_id(con, uid)
        return dict(row) if row is not None else None

    @app.after_request
    def _apply_security_headers(response):
        for name, value in config.SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not username or not password:
                return render_template_string(REGISTER_TMPL, error="both fields required")
            if db.get_user(con, username) is not None:
                return render_template_string(REGISTER_TMPL, error="username taken")
            uid = db.create_user(con, username, password)
            session["uid"] = uid
            return redirect(url_for("dashboard"))
        return render_template_string(REGISTER_TMPL, error=None)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = db.get_user(con, username)
            from app.security import verify_password
            if user is None or not verify_password(password, user["pw"]):
                return render_template_string(LOGIN_TMPL, error="bad credentials")
            session["uid"] = user["id"]
            return redirect(url_for("dashboard"))
        return render_template_string(LOGIN_TMPL, error=None)

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    def dashboard():
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        notes = db.notes_for(con, user["id"])
        return render_template_string(DASHBOARD_TMPL, user=user, notes=notes)

    @app.post("/note/new")
    def new_note():
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "")
        if title:
            db.add_note(con, user["id"], title, body)
        return redirect(url_for("dashboard"))

    @app.get("/note/<int:note_id>")
    def view_note(note_id):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        note = db.get_note(con, note_id)
        if note is None:
            abort(404)
        if not can_view(note, user):
            abort(403)
        return render_template_string(NOTE_TMPL, note=note, user=user)

    @app.get("/search")
    def search():
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        q = request.args.get("q", "")
        results = db.search_notes(con, user["id"], q)
        return render_template_string(SEARCH_TMPL, q=q, notes=results)

    @app.get("/admin/export")
    def admin_export():
        user = current_user()
        if not is_admin(user):
            abort(403)
        notes = db.all_notes(con)
        return render_template_string(ADMIN_TMPL, notes=notes)

    return app


def _seed(con) -> None:
    """Deterministic seed: an admin and two ordinary users with notes.

    The two ordinary users exist so a dynamic probe can prove cross-user data
    leakage (SQL injection, IDOR): if alice's request ever returns one of bob's
    notes, something is broken.
    """
    admin = db.create_user(con, "root", "root-pw", is_admin=1)
    alice = db.create_user(con, "alice", "alice-pw")
    bob = db.create_user(con, "bob", "bob-pw")
    db.add_note(con, admin, "ops runbook", "restart the worker pool nightly")
    db.add_note(con, alice, "groceries", "milk, eggs, bread")
    db.add_note(con, alice, "ideas", "a quality gate that measures itself")
    db.add_note(con, bob, "taxes", "file before April, keep the receipts")
    db.add_note(con, bob, "secret plan", "bob's confidential note, not for alice")
