"""Dynamic application security testing (DAST) gate.

SAST reads the code; DAST attacks the running app and reports what actually
works. It drives the real Flask app through its test client with malicious
inputs and checks the responses:

* **SQL injection** -- search as alice for ``' OR '1'='1``; if the results ever
  include a note owned by someone else, the query is injectable.
* **Reflected XSS** -- store a note whose body is ``<script>...</script>`` and
  fetch it; if the script tag comes back unescaped, the page is XSS-able.
* **Broken access control** -- call ``/admin/export`` as a non-admin; a 200 means
  the authorization check is missing.
* **Missing security headers** -- fetch a normal page and check for the headers
  every response should carry.

These are the runtime-only findings: the missing admin check and the absent
headers leave no dangerous *pattern* in the source for SAST to see, yet the app
is plainly exploitable. The clean app passes every probe.
"""
from __future__ import annotations

import json
import os
import re
import sys

# When run as a script (python gate/dast.py) the app package lives in the current
# working directory, not next to this file. The harness runs us inside a patched
# copy of the repo, so resolve the app from cwd.
sys.path.insert(0, os.getcwd())

REQUIRED_HEADERS = ["X-Content-Type-Options", "Content-Security-Policy", "X-Frame-Options"]
XSS_PAYLOAD = "<script>gauntlet_xss()</script>"
# Breaks out of the LIKE '%...%' wrapper and comments out the trailing %' so the
# OR is always true. Harmless as a bound value (clean app matches it literally).
SQLI_PAYLOAD = "%' OR '1'='1' -- "
# A term that appears in another seeded user's note title (bob's "secret plan").
# A correctly owner-scoped search for it returns nothing to alice.
SCOPE_PROBE_TERM = "plan"


def _login(client, username, password):
    return client.post("/login", data={"username": username, "password": password})


def probe_sql_injection(app) -> dict | None:
    """Alice searches with an injection payload; flag if she sees another owner's note."""
    c = app.test_client()
    _login(c, "alice", "alice-pw")
    alice_id = _uid(app, "alice")
    r = c.get("/search", query_string={"q": SQLI_PAYLOAD})
    owners = {int(o) for o in re.findall(r"owner (\d+)", r.get_data(as_text=True))}
    leaked = owners - {alice_id}
    if leaked:
        return {"probe": "sqli", "severity": "HIGH",
                "detail": f"search leaked notes owned by {sorted(leaked)} to alice"}
    return None


def probe_broken_object_level_auth(app) -> dict | None:
    """Alice searches for a term only another user's note has; flag any leak.

    This catches a *scoping* bug (search that forgets the owner filter) even when
    the query is not injectable -- a different failure from SQL injection.
    """
    c = app.test_client()
    _login(c, "alice", "alice-pw")
    alice_id = _uid(app, "alice")
    r = c.get("/search", query_string={"q": SCOPE_PROBE_TERM})
    owners = {int(o) for o in re.findall(r"owner (\d+)", r.get_data(as_text=True))}
    leaked = owners - {alice_id}
    if leaked:
        return {"probe": "search-scope", "severity": "HIGH",
                "detail": f"owner-scoped search leaked notes owned by {sorted(leaked)}"}
    return None


def probe_xss(app) -> dict | None:
    """Store a scripted note and fetch it; flag if the script survives unescaped."""
    c = app.test_client()
    _login(c, "alice", "alice-pw")
    c.post("/note/new", data={"title": "probe", "body": XSS_PAYLOAD})
    r = c.get("/search", query_string={"q": "probe"})
    m = re.search(r"/note/(\d+)", r.get_data(as_text=True))
    if not m:
        return None
    r = c.get(f"/note/{m.group(1)}")
    if XSS_PAYLOAD in r.get_data(as_text=True):
        return {"probe": "xss", "severity": "HIGH",
                "detail": "stored <script> reflected unescaped on the note page"}
    return None


def probe_broken_access_control(app) -> dict | None:
    """Non-admin alice hits the admin export; flag any success."""
    c = app.test_client()
    _login(c, "alice", "alice-pw")
    r = c.get("/admin/export")
    if r.status_code == 200:
        return {"probe": "authz", "severity": "HIGH",
                "detail": "/admin/export returned 200 to a non-admin user"}
    return None


def probe_security_headers(app) -> dict | None:
    c = app.test_client()
    _login(c, "alice", "alice-pw")
    r = c.get("/")
    missing = [h for h in REQUIRED_HEADERS if h not in r.headers]
    if missing:
        return {"probe": "headers", "severity": "MEDIUM",
                "detail": f"missing security headers: {missing}"}
    return None


def _uid(app, username) -> int:
    from app import db
    return db.get_user(app.config["DB"], username)["id"]


PROBES = [probe_sql_injection, probe_broken_object_level_auth, probe_xss,
          probe_broken_access_control, probe_security_headers]


def scan() -> dict:
    from app.web import create_app
    findings = []
    for probe in PROBES:
        app = create_app()          # a fresh, freshly seeded app per probe
        result = probe(app)
        if result is not None:
            findings.append(result)
    return {"findings": findings, "n": len(findings), "passed": len(findings) == 0}


def main() -> None:
    print(json.dumps(scan(), indent=2))


if __name__ == "__main__":
    main()
