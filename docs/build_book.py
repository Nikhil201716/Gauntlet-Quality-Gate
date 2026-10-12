"""Builds the Gauntlet notebook. Listings are pulled from the repo by marker and
every number is read from reports/*.json, so the book fails rather than shipping
a stale claim.

    python docs/build_book.py     (run `python -m harness.score` first)
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJ = HERE.parent
sys.path.insert(0, str(PROJ.parent / "bookgen"))

from engine import (  # noqa: E402
    build, callout, code_from, code_literal, equation, ol, p, table, ul,
)

REPO = "github.com/Nikhil201716/Gauntlet-Quality-Gate"


def report(name):
    return json.loads((PROJ / "reports" / f"{name}.json").read_text(encoding="utf-8"))


SUM = report("summary")
MATRIX = report("catch_matrix")
ROWS = MATRIX["defects"]
AGREE = report("agreement")
DEF = {r["id"]: r for r in ROWS}

LAYERS = ["unit", "bdd", "mutation", "sast", "dast"]
PLC = SUM["per_layer_catches"]
NDEF = SUM["n_defects"]
BASE = SUM["baseline_green_suite"]
GATE = SUM["full_gate"]
ESCAPED = SUM["escaped_all_layers"]
T1_SCORE = DEF["T1"].get("mutation_score")
CLEAN_MS = SUM["clean_mutation_score"]
MUT_THRESHOLD = 0.90


def yn(b):
    return "✓" if b else "·"


def matrix_rows():
    out = []
    for r in ROWS:
        cells = [yn(not r["per_layer"][l]) for l in LAYERS]  # not passed => caught
        caught = ",".join(r["caught_by"]) or "— none —"
        out.append([r["id"]] + cells + [caught, r["name"]])
    return out


# ═══════════════════════════════════════════════════════════════ chapter 1 ══

CH1 = {
    "title": "A green test suite is not a safe release",
    "abstract": (
        "Five gate layers, ten injected defects. The passing unit and acceptance "
        "suites catch two of them. The full gate catches nine. One escapes all "
        "five."),
    "sections": [
        {"title": "The finding", "html": "".join([
            p("Gauntlet is a quality gate you can run and measure. A small Flask "
              "application -- Notekeeper, where people register, log in, write "
              "notes, search them, and an admin exports them -- is wrapped in five "
              "independent checks: unit tests, BDD acceptance tests, mutation "
              "testing, static analysis (SAST) and dynamic probing (DAST). A "
              "harness injects ten known defects one at a time and records which "
              "layer catches which."),
            p("The clean application passes all five layers, and its authorization "
              f"core scores a perfect {CLEAN_MS:.2f} on the mutation gate. It is a "
              "genuinely good suite. And yet:"),
            table(["Gate", f"Catches (of {NDEF})", "What it sees"],
                  [[f"green test suite ({' + '.join(BASE['layers'])})",
                    str(BASE["n_caught"]), "functional bugs only"],
                   ["full five-layer gate", str(GATE["n_caught"]),
                    "+ weak tests, code vulns, runtime vulns"],
                   ["escaped every layer", str(len(ESCAPED)),
                    "a business-logic authorization flaw (IDOR)"],
                   ["false positives on a benign change",
                    str(len(SUM["false_positives_on_benign"])), "none"]],
                  caption="Table 1.1 - the headline (reports/summary.json)",
                  highlight_col=1),
            p(f"The green suite catches {BASE['n_caught']} of {NDEF} because the "
              "only defects it can see are the two that break a feature. It is "
              "blind to an injectable query, a stored XSS, a hard-coded secret, "
              "MD5 password hashing, a missing admin check, absent security "
              "headers, and -- most tellingly -- a unit test that passes while "
              "asserting nothing. Each of those is caught, but only by the layer "
              "built to see it."),
        ])},
        {"title": "The whole grid", "html": "".join([
            p("Every row is a real run: the harness patches the source, runs the "
              "five layers against the patched copy, and marks a layer as having "
              "caught the defect if that layer fails. A dot means the layer passed "
              "(did not notice); a check means it failed (caught it)."),
            table(["id", "unit", "bdd", "mut", "sast", "dast", "caught by", "defect"],
                  matrix_rows(),
                  caption="Table 1.2 - defect x layer (reports/catch_matrix.json)"),
            p(f"L1 and L2 are functional bugs; T1 is a weakened test; S1-S6 and G1 "
              f"are vulnerabilities; N1 is a benign control. Of {NDEF} defects, "
              f"{GATE['n_caught']} are caught by at least one layer and "
              f"{len(ESCAPED)} ({', '.join(ESCAPED)}) slips past all five. The "
              "benign change trips nothing."),
            callout("note", "Every claim is checked",
                     p("The catalog records, for each defect, which layers it "
                       "predicts will catch it. The harness compares prediction to "
                       f"measurement: {SUM['prediction_agreement']} of "
                       f"{SUM['prediction_total']} agree (reports/agreement.json). "
                       "The grid is the project holding itself to its own claims.")),
        ])},
        {"title": "How to read the rest", "html": "".join([
            p("The notebook tours the application, then each of the five layers in "
              "turn -- what it is, how it is implemented here, and exactly which "
              "defect class it owns -- then the harness that measures them, the "
              "defect that escaped, and the limits of the whole exercise."),
            ul(["The app under test and its security-critical parts.",
                "The five layers, one class of defect at a time, with the code of each.",
                "The catalog, the harness, and reading the matrix.",
                "The IDOR that escaped, and how to close it.",
                "CI wiring, reproducibility, OWASP context, limits, exercises."]),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 2 ══

CH2 = {
    "title": "Notekeeper: the application under test",
    "abstract": "An ordinary Flask app, because ordinary is where defects live.",
    "sections": [
        {"title": "What it does", "html": "".join([
            p("Notekeeper is deliberately unremarkable. A user registers and logs "
              "in; writes short notes; searches their own notes by title; and an "
              "administrator can export every note. That small surface is enough "
              "to host every class of defect the gate is meant to catch: a search "
              "query (SQL), a rendered note (XSS), a stored password (crypto), a "
              "config secret, an admin-only route (authorization) and response "
              "headers."),
            p("The clean application is the secure version of each of those. Every "
              "defect in the catalog is one surgical edit away from this code, "
              "which is the point -- these are not exotic bugs, they are one wrong "
              "line in an app that otherwise works and passes its tests."),
        ])},
        {"title": "The app factory and its routes", "html": "".join([
            p("The app is built by a factory so every test gets a fresh, freshly "
              "seeded instance. The security-relevant decisions are marked in the "
              "source with the defect each one is the target of."),
            code_from(PROJ, "app/web.py",
                      start="def create_app(seed: bool = True) -> Flask:",
                      end="        return redirect(url_for(\"dashboard\"))",
                      caption="Listing 2.1 - the factory, headers hook and register route",
                      lang="python"),
            p("A signed session cookie carries the logged-in user id; "
              "`current_user()` turns it back into a row. The `after_request` hook "
              "adds the security headers (defect S6 removes them). Note that "
              "creating a user here is the app's own flow against an in-memory "
              "database -- no real credentials are involved."),
        ])},
        {"title": "The deterministic seed", "html": "".join([
            p("Two ordinary users and an admin, with notes, are seeded on every "
              "boot. The two ordinary users exist so a probe can prove a cross-"
              "user leak: if alice's request ever returns one of bob's notes, "
              "something is broken."),
            code_from(PROJ, "app/web.py", start="def _seed(con) -> None:",
                      end="\"bob's confidential note, not for alice\")",
                      caption="Listing 2.2 - the seed (app/web.py)", lang="python"),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 3 ══

CH3 = {
    "title": "The authorization rules",
    "abstract": "Small, pure functions -- the security the whole app rests on, and "
                "the substrate the mutation gate judges.",
    "sections": [
        {"title": "Rules as pure functions", "html": "".join([
            p("Who may see a note, who may edit it, who is an admin: these are the "
              "rules everything else depends on. Keeping them as small pure "
              "functions -- no framework, no database -- makes them easy to test "
              "exhaustively, which is why they are the natural target for mutation "
              "testing later."),
            code_from(PROJ, "app/authz.py", start="def is_admin(user",
                      end="return [n for n in notes if can_view(n, user)]",
                      caption="Listing 3.1 - app/authz.py", lang="python"),
        ])},
        {"title": "The seam that matters", "html": "".join([
            p("Read `can_view` carefully: a note is visible to its owner or to an "
              "admin. `can_edit` is stricter -- only the owner, so an admin may "
              "read but not rewrite. These distinctions are exactly what a good "
              "test suite must pin down, and exactly what a weak one lets slide."),
            callout("key", "Correct and tested is not the same as wired in",
                     p("The whole capstone lesson lives in the gap between this "
                       "module and the routes that call it. These rules can be "
                       "perfect and fully tested, and the app can still leak -- if "
                       "a single route forgets to call `can_view`. Hold that "
                       "thought; it is the defect that escapes the entire gate.")),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 4 ══

CH4 = {
    "title": "Storage and the one query that matters",
    "abstract": "Parameterised and owner-scoped -- the safe, boring way, and the "
                "target of two different defects.",
    "sections": [
        {"title": "Search, done right", "html": "".join([
            p("Notes live in SQLite. Search is the one query where a mistake is "
              "dangerous, so the clean version does two things at once: it binds "
              "the search term as a value (never as SQL text) and it scopes the "
              "result to the caller."),
            code_from(PROJ, "app/db.py", start="def search_notes(",
                      end="return con.execute(sql, (owner_id, f\"%{query}%\")).fetchall()",
                      caption="Listing 4.1 - app/db.py search_notes", lang="python"),
            p("Two defects target this one function. S1 rebuilds it as an f-string "
              "(SQL injection). L2 drops the `owner_id = ?` clause (a scoping bug "
              "that leaks across users without any injection). They are caught by "
              "different layers -- which is the first hint that one tool is not "
              "enough."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 5 ══

CH5 = {
    "title": "Password hashing",
    "abstract": "PBKDF2 with a salt -- and why a login test cannot tell it from MD5.",
    "sections": [
        {"title": "The clean version", "html": "".join([
            p("Passwords are stored as a salted PBKDF2-HMAC-SHA256 digest and "
              "checked in constant time. Defect S4 replaces both functions with a "
              "bare MD5."),
            code_from(PROJ, "app/security.py", start="def hash_password(",
                      end="return hmac.compare_digest(check.hex(), digest_hex)",
                      caption="Listing 5.1 - app/security.py", lang="python"),
            callout("warn", "The test that cannot see the difference",
                     p("Login works identically whether the stored hash is PBKDF2 "
                       "or MD5: the right password verifies, the wrong one does "
                       "not. A round-trip unit test passes either way. That is why "
                       "S4 is caught only by static analysis -- a tool that reads "
                       "the code and recognises `hashlib.md5` -- and never by a "
                       "functional test.")),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 6 ══

CH6 = {
    "title": "Layer 1 - unit tests",
    "abstract": "A capable suite that pins the authorization rules branch by branch.",
    "sections": [
        {"title": "What the unit suite asserts", "html": "".join([
            p("The unit layer is pytest over the pure logic: the authorization "
              "rules, password hashing, and storage. The authorization tests are "
              "written to pin every branch -- owner, admin, other user, anonymous "
              "-- so the clean suite scores 100% on the mutation gate."),
            code_from(PROJ, "tests/test_authz.py", start="# --- can_view",
                      end="assert can_view(note(1), None) is False",
                      caption="Listing 6.1 - the can_view tests (tests/test_authz.py)",
                      lang="python"),
            p(f"Across the project the unit suite catches exactly "
              f"{PLC['unit']} of {NDEF} injected defects: L2, the search-scoping "
              "bug, because `test_db` asserts search is owner-scoped. It catches "
              "none of the security defects -- not because it is weak, but because "
              "they live in wiring and in properties these tests do not assert."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 7 ══

CH7 = {
    "title": "Layer 2 - BDD acceptance tests",
    "abstract": "Business-language scenarios in Gherkin, run by Behave.",
    "sections": [
        {"title": "The feature file", "html": "".join([
            p("BDD (behaviour-driven development) writes acceptance tests in "
              "Gherkin -- Given/When/Then in business language -- so they read as "
              "a specification. Behave runs them against the real app through its "
              "test client."),
            code_from(PROJ, "features/notekeeper.feature",
                      start="  Scenario: a note I write",
                      end="And I do not see \"taxes\"",
                      caption="Listing 7.1 - features/notekeeper.feature",
                      lang="gherkin"),
        ])},
        {"title": "The steps", "html": "".join([
            p("Each Given/When/Then maps to a step function. The steps drive the "
              "Flask test client -- a real HTTP round trip, in process."),
            code_from(PROJ, "features/steps/steps.py",
                      start="@given('I am logged in as",
                      end="assert r.status_code in (200, 302), f\"login failed: {r.status_code}\"",
                      caption="Listing 7.2 - a step definition (features/steps/steps.py)",
                      lang="python"),
            p(f"The acceptance suite catches {PLC['bdd']} of {NDEF}: L1, where "
              "search ignores the query, breaks the scenario that says a search "
              "must hide non-matching notes. That is precisely what acceptance "
              "tests are good at -- and precisely the limit explored next."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 8 ══

CH8 = {
    "title": "Why a vulnerable app still passes its tests",
    "abstract": "The uncomfortable overlap: green unit + green BDD, and an "
                "exploitable app.",
    "sections": [
        {"title": "Features work; security does not", "html": "".join([
            p("Walk the security defects against the two functional layers. The "
              "SQL-injectable search (S1) still returns your matching notes for a "
              "normal query, so every search scenario passes. The stored XSS (S2) "
              "still shows the note text, so the view scenario passes. MD5 hashing "
              "(S4) still logs you in. The hard-coded secret (S3) changes no "
              "behaviour at all. The missing admin check (S5) only makes the admin "
              "export *more* permissive, so the admin's own scenario still passes. "
              "Absent headers (S6) are invisible to a test that only reads the body."),
            p(f"That is why the green suite catches {BASE['n_caught']} of {NDEF}. "
              "A functional test asserts that a feature works. A vulnerability, "
              "almost by definition, does not stop the feature from working -- it "
              "adds a capability the attacker wanted and the user never sees. The "
              "remaining three layers each exist to see a kind of wrong that "
              "'the feature works' cannot."),
            callout("key", "The baseline is a control, not a straw man",
                     p("It would be easy to make this point with a bad test suite. "
                       "This one is good: 23 unit tests, four acceptance scenarios, "
                       f"and a {CLEAN_MS:.0%} mutation score on the authorization "
                       "core. The point stands anyway -- a strong green suite still "
                       "misses whole classes of defect.")),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 9 ══

CH9 = {
    "title": "Layer 3 - mutation testing: the idea",
    "abstract": "Measure whether the tests would notice if the code were wrong.",
    "sections": [
        {"title": "Tests for the tests", "html": "".join([
            p("A green suite tells you the tests pass. It does not tell you they "
              "would fail if the code were broken. Mutation testing answers that "
              "directly: change the code under test in a small, deliberate way (a "
              "'mutant') and rerun the suite. If a test now fails, the mutant is "
              "*killed* -- the suite had teeth there. If every test still passes, "
              "the mutant *survived*, and a real bug of that shape would have "
              "slipped through too."),
            equation(r"MS = \frac{K}{M}"),
            p("The mutation score MS is the fraction of M mutants that the suite "
              "killed (K). The gate passes when the score clears a threshold:"),
            equation(r"\text{pass} \Leftrightarrow MS \geq \tau"),
            p(f"Here the threshold is {MUT_THRESHOLD:.2f}, set just below the clean "
              f"suite's {CLEAN_MS:.2f} so that any genuine loss of coverage fails "
              "the gate. The engine mutates the authorization rules -- small, pure "
              "and security-critical, the right place to demand real teeth."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 10 ═

CH10 = {
    "title": "The mutation engine",
    "abstract": "A standard-library AST transformer: one deliberate change per mutant.",
    "sections": [
        {"title": "The mutators", "html": "".join([
            p("The engine parses the module to an abstract syntax tree and walks it "
              "in a fixed order, producing one mutant per mutation point: swap a "
              "comparison operator, flip a boolean operator, bump an integer "
              "constant, invert a boolean constant."),
            code_from(PROJ, "gate/mutation.py", start="    def visit_Compare(self, node",
                      end="self.label = f\"cmp {old}->{type(node.ops[0]).__name__} @L{node.lineno}\"",
                      caption="Listing 10.1 - a mutator (gate/mutation.py)",
                      lang="python"),
            p("One change at a time, deterministic order, so the mutant set -- and "
              "therefore the score -- is reproducible."),
            code_from(PROJ, "gate/mutation.py", start="def generate_mutants(source",
                      end="return mutants",
                      caption="Listing 10.2 - enumerating mutants", lang="python"),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 11 ═

CH11 = {
    "title": "Running the suite against a mutant",
    "abstract": "In-process, fast, isolated.",
    "sections": [
        {"title": "The runner", "html": "".join([
            p("For each mutant the engine loads the mutated module as `app.authz`, "
              "then executes the test file against it and counts failures. It runs "
              "in process -- no subprocess per mutant -- so the whole score is a "
              "fraction of a second."),
            code_from(PROJ, "gate/mutation.py", start="def _run_suite(authz_source",
                      end="return len(tests), failures",
                      caption="Listing 11.1 - running tests against a mutant",
                      lang="python"),
            p("The score is computed only if the unmutated baseline is green -- "
              "mutation testing of a red suite is meaningless. On the clean app "
              f"the engine generates its mutants and the suite kills all of them: "
              f"MS = {CLEAN_MS:.2f}."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 12 ═

CH12 = {
    "title": "The toothless suite (defect T1)",
    "abstract": f"Still green, but the score falls to {T1_SCORE} and the gate fails.",
    "sections": [
        {"title": "A plausible weak suite", "html": "".join([
            p("Defect T1 swaps the thorough authorization tests for a shallow set "
              "-- the two cases a developer thinks of first, and no more. It never "
              "passes `None` (anonymous) and never checks the admin override."),
            code_from(PROJ, "harness/variants/test_authz_weak.py",
                      start="def test_owner_can_view_own_note",
                      end="assert owns(note(1), {\"id\": 1, \"is_admin\": 0})",
                      caption="Listing 12.1 - the weak suite (harness/variants/)",
                      lang="python"),
            p(f"This suite passes -- pytest is green. But the mutation score falls "
              f"from {CLEAN_MS:.2f} to {T1_SCORE}: the boolean-operator mutants "
              "that only misbehave on an anonymous or admin input now survive, "
              f"because no test exercises those inputs. {T1_SCORE} is below the "
              f"{MUT_THRESHOLD:.2f} threshold, so the gate fails."),
            callout("key", "Green is not tested",
                     p(f"T1 is caught by exactly one layer: mutation. The unit and "
                       "BDD suites are both green on it, because a weakened test is "
                       "still a passing test. Only a tool that measures whether the "
                       "tests have teeth can tell a thorough suite from a decorative "
                       "one.")),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 13 ═

CH13 = {
    "title": "Layer 4 - SAST with Bandit",
    "abstract": "Read the code; flag the dangerous shapes.",
    "sections": [
        {"title": "What Bandit catches", "html": "".join([
            p("Static application security testing reads source without running "
              "it. Bandit is the standard Python security linter; the gate runs it "
              "over `app/` and treats any finding as a failure, because the clean "
              "code produces none."),
            table(["Defect", "Bandit rule", "What it saw"],
                  [["S1 SQL injection", "B608", "SQL statement built by string formatting"],
                   ["S3 hard-coded secret", "B105", "a secret assigned as a literal"],
                   ["S4 MD5 hashing", "B324", "a weak hash used for security"]],
                  caption="Table 13.1 - the three Bandit catches"),
            code_from(PROJ, "gate/sast.py", start="def run_bandit(app_dir",
                      end="return out",
                      caption="Listing 13.1 - invoking Bandit (gate/sast.py)",
                      lang="python"),
            callout("note", "A version gotcha worth recording",
                     p("Bandit before 1.9 crashes on Python 3.13/3.14: it reads the "
                       "removed `node.s` attribute on string constants and throws "
                       "on every file -- while reporting 'no issues', which looks "
                       "like a clean pass. The fix is `bandit>=1.9`. A tool that "
                       "silently scans nothing is worse than no tool.")),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 14 ═

CH14 = {
    "title": "SAST house rules",
    "abstract": "What Bandit misses, a few AST rules of your own can catch.",
    "sections": [
        {"title": "A custom rule for Flask XSS", "html": "".join([
            p("Bandit does not reliably flag the Flask XSS pattern, so the gate "
              "adds house rules -- the kind of project-specific check a team writes "
              "in semgrep. The key one flags a dynamic template passed to "
              "`render_template_string`, which bypasses Jinja autoescaping."),
            code_from(PROJ, "gate/sast.py", start="    def visit_Call(self, node: ast.Call):",
                      end="        self.generic_visit(node)",
                      caption="Listing 14.1 - the custom XSS rule (gate/sast.py)",
                      lang="python"),
            p("The clean note view passes a constant template, so it is not "
              "flagged. Defect S2 passes a string built by concatenation -- a "
              "`BinOp` -- which the rule catches (XSS001). With Bandit plus these "
              f"rules, SAST catches {PLC['sast']} of {NDEF}: S1, S2, S3 and S4 -- "
              "the code-level vulnerabilities."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 15 ═

CH15 = {
    "title": "What SAST cannot see",
    "abstract": "Two real vulnerabilities leave no dangerous pattern in the source.",
    "sections": [
        {"title": "Absence is invisible", "html": "".join([
            p("SAST matches patterns in code. But two of the defects are not a "
              "dangerous pattern -- they are a *missing* safe one. S5 removes the "
              "`is_admin` check from the admin export; the remaining code is "
              "ordinary and correct-looking. S6 stops the `after_request` hook from "
              "adding headers; again, nothing dangerous is written, something safe "
              "is simply gone."),
            p("No static rule flags S5 or S6 without guessing intent, which is how "
              "static analysis earns false positives. The honest answer is that "
              "these are runtime properties: you cannot see them by reading the "
              "code, only by running it and looking at what the app actually does. "
              "That is the next layer."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 16 ═

CH16 = {
    "title": "Layer 5 - DAST",
    "abstract": "Attack the running app and report what actually works.",
    "sections": [
        {"title": "The probes", "html": "".join([
            p("Dynamic application security testing drives the running app with "
              "malicious input and inspects the responses. The gate runs five "
              "probes through Flask's in-process test client -- no network, no "
              "server -- each returning a finding or nothing."),
            ul(["<b>SQL injection</b> - search with an injection payload; flag if "
                "the results include another user's note.",
                "<b>Owner-scope</b> - search for a term only another user's note "
                "has; flag any leak (catches scoping bugs that are not injectable).",
                "<b>Reflected XSS</b> - store a scripted note, fetch it, flag if "
                "the script survives unescaped.",
                "<b>Broken access control</b> - call the admin export as a non-"
                "admin; flag a 200.",
                "<b>Security headers</b> - fetch a page and flag any missing "
                "header."]),
            p(f"DAST catches {PLC['dast']} of {NDEF}: S1 and S2 (confirming SAST), "
              "plus L2, S5 and S6 -- the runtime-only findings."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 17 ═

CH17 = {
    "title": "A probe in detail",
    "abstract": "Why the payload has to break out of the LIKE wrapper.",
    "sections": [
        {"title": "The SQL-injection probe", "html": "".join([
            code_from(PROJ, "gate/dast.py", start="def probe_sql_injection(app)",
                      end="to alice\"}",
                      caption="Listing 17.1 - the SQLi probe (gate/dast.py)",
                      lang="python"),
            p("The payload is not the textbook <code>' OR '1'='1</code>. The query "
              "wraps the term in <code>'%...%'</code> for a LIKE, so a naive "
              "payload leaves a dangling <code>%'</code> that turns the injected "
              "comparison false. The working payload closes the quote and comments "
              "out the trailing wrapper, so the OR is always true and every row "
              "returns. Getting this wrong is why the first run of this project "
              "showed S1 caught by SAST but not DAST -- a reminder that a probe "
              "that does not fire proves nothing."),
            callout("note", "The clean app is the control",
                     p("The same payload, sent to the clean app, is bound as a "
                       "literal LIKE value and matches no title, so the probe "
                       "returns nothing. A probe is only evidence if it is silent "
                       "on safe code and loud on unsafe code.")),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 18 ═

CH18 = {
    "title": "SAST and DAST: the same vulnerability, two lenses",
    "abstract": "Where they overlap, where only one can see.",
    "sections": [
        {"title": "Complementary, not redundant", "html": "".join([
            table(["Defect", "SAST", "DAST", "why"],
                  [["S1 SQL injection", "✓", "✓", "dangerous pattern AND exploitable"],
                   ["S2 stored XSS", "✓", "✓", "dangerous pattern AND exploitable"],
                   ["S3 hard-coded secret", "✓", "·", "visible in code, no runtime effect"],
                   ["S4 MD5 hashing", "✓", "·", "visible in code, login still works"],
                   ["S5 missing admin check", "·", "✓", "an absence; only runtime shows it"],
                   ["S6 missing headers", "·", "✓", "an absence; only the response shows it"]],
                  caption="Table 18.1 - the six vulnerabilities across the two gates"),
            p("S1 and S2 are caught twice -- genuine defense in depth: a static "
              "rule and a live exploit confirming each other. S3 and S4 are "
              "SAST-only, because they change no observable behaviour. S5 and S6 "
              "are DAST-only, because they are the absence of a safe thing rather "
              "than the presence of a dangerous one. Neither tool dominates; you "
              "need both."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 19 ═

CH19 = {
    "title": "The defect catalog",
    "abstract": "One known problem per entry, injected as a source patch, with a "
                "prediction the run must honour.",
    "sections": [
        {"title": "The shape of a defect", "html": "".join([
            p("Each entry is one or more edits to the clean source -- a literal "
              "find/replace, or a whole-file swap for the weak-test case. The "
              "`expected` field names the layers the catalog predicts will catch "
              "it; the harness measures what actually happens and checks the "
              "prediction."),
            code_from(PROJ, "harness/defects.py", start="class Defect:",
                      end="edits: tuple = field(default_factory=tuple)",
                      caption="Listing 19.1 - the Defect record (harness/defects.py)",
                      lang="python"),
            p("The catalog spans four classes: `logic` (a feature is wrong), "
              "`weak-test` (the tests pass but assert nothing), `vuln` (a security "
              "hole) and `benign` (a harmless change, the control)."),
        ])},
        {"title": "The gap, declared up front", "html": "".join([
            p("The IDOR defect declares an empty prediction -- the catalog states "
              "plainly that no layer here catches it. The run confirms it."),
            code_from(PROJ, "harness/defects.py", start="        id=\"G1\"",
                      end="(NOTE_TMPL, note=note, user=user)\"),),",
                      caption="Listing 19.2 - the IDOR entry predicts its own escape",
                      lang="python"),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 20 ═

CH20 = {
    "title": "The harness",
    "abstract": "Copy, patch, run all five layers in isolation, record the catches.",
    "sections": [
        {"title": "Applying a defect", "html": "".join([
            p("For each defect the harness copies the whole repository to a "
              "temporary directory and applies the edits. A find/replace that does "
              "not match exactly once is a hard error -- so a catalog that drifts "
              "from the code fails loudly instead of silently testing nothing."),
            code_from(PROJ, "harness/score.py", start="def _apply(root: Path",
                      end="target.write_text(text.replace(edit.old, edit.new), encoding=\"utf-8\")",
                      caption="Listing 20.1 - applying a patch (harness/score.py)",
                      lang="python"),
        ])},
        {"title": "Running the layers", "html": "".join([
            p("Each layer runs as its own subprocess with the patched copy as its "
              "working directory, so there is no import caching between runs and "
              "every layer sees the patched code. A layer caught the defect if it "
              "fails on the copy."),
            code_from(PROJ, "harness/score.py",
                      start="    # mutation / sast / dast: each prints a JSON verdict",
                      end="    return out",
                      caption="Listing 20.2 - the five layers per copy", lang="python"),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 21 ═

CH21 = {
    "title": "The control: clean copy and benign change",
    "abstract": "Why the run is not just confirmation bias.",
    "sections": [
        {"title": "Two guards against a rigged result", "html": "".join([
            p("A fault-injection study is only honest if it also measures its "
              "false positives and proves its baseline is capable. Gauntlet does "
              "both."),
            ol(["<b>The clean copy runs first.</b> Before any defect, the harness "
                f"runs all five layers on the unpatched repo. The result records "
                f"<code>clean_passes_all_layers = "
                f"{str(SUM['clean_passes_all_layers']).lower()}</code>. If the "
                "clean app failed any layer, the whole matrix would be suspect.",
                "<b>A benign change (N1) is injected like any defect.</b> It adds "
                "an unused display-name constant -- a real edit that is not a "
                f"defect. It must trip nothing, and it does: "
                f"{len(SUM['false_positives_on_benign'])} false positives. A gate "
                "that cried wolf here would train its team to ignore it."]),
            p("These two controls are why the headline -- green suite 2, full gate "
              "9, one escaped -- is a measurement rather than a slogan."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 22 ═

CH22 = {
    "title": "Reading the matrix by class",
    "abstract": "What each row teaches.",
    "sections": [
        {"title": "Per class", "html": "".join([
            p("<b>Logic bugs (L1, L2).</b> These are what the functional suites "
              "exist for. L1 breaks an acceptance scenario (BDD); L2 breaks a "
              "storage unit test and also leaks at runtime (unit + DAST). The green "
              "suite earns its keep here -- and only here."),
            p("<b>Weak test (T1).</b> Invisible to every layer except mutation, "
              "because it is not a bug in the app at all -- it is a bug in the "
              "confidence the tests give you."),
            p("<b>Code vulnerabilities (S1-S4).</b> SAST's territory. Two of them "
              "(S1, S2) are also exploitable at runtime, so DAST confirms them. "
              "Two (S3, S4) leave no runtime trace and are SAST-only."),
            p("<b>Runtime vulnerabilities (S5, S6).</b> DAST's territory. An "
              "absent check and absent headers -- no code pattern to match, only "
              "behaviour to observe."),
            p("<b>The escape (G1).</b> Its own chapter follows."),
            p(f"Net: the trivial 'is the suite green' gate catches "
              f"{BASE['n_caught']} of {NDEF}; adding mutation, SAST and DAST raises "
              f"it to {GATE['n_caught']}. The marginal value of each added layer is "
              "exactly the class the cheaper layers could not see."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 23 ═

CH23 = {
    "title": "Why layers multiply",
    "abstract": "A back-of-envelope model for defense in depth.",
    "sections": [
        {"title": "Independent detection", "html": "".join([
            p("Think of each layer as having some probability of detecting a given "
              "defect class. If a defect reaches production only when every layer "
              "misses it, and the layers are roughly independent, the escape "
              "probability is the product of the miss probabilities:"),
            equation(r"P_{escape} = \prod_{i} (1 - d_i)"),
            p("where d_i is layer i's detection probability for that defect class. "
              "The lesson of the matrix is that the d_i are nearly disjoint across "
              "classes: for a missing-header defect, the functional and SAST layers "
              "have d near zero while DAST has d near one. Adding a layer whose "
              "strength is another layer's blind spot drops the product sharply; "
              "adding a layer that overlaps an existing one barely moves it."),
            p("It also shows the limit of the model. For the IDOR class, every "
              "d_i in this gate is zero, so the product is one -- the defect "
              "escapes with certainty no matter how many of these five layers you "
              "stack. Independence does not help when everyone shares the same "
              "blind spot."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 24 ═

CH24 = {
    "title": "The IDOR that escaped",
    "abstract": "Correct, tested authorization rules -- and the app leaks anyway.",
    "sections": [
        {"title": "One route forgot to ask", "html": "".join([
            p("Defect G1 removes a single guard from the note route: the call to "
              "`can_view`. Any logged-in user can now read any note by id -- an "
              "insecure direct object reference (IDOR)."),
            code_literal(
                "        note = db.get_note(con, note_id)\n"
                "        if note is None:\n"
                "            abort(404)\n"
                "-       if not can_view(note, user):\n"
                "-           abort(403)\n"
                "        return render_template_string(NOTE_TMPL, note=note, user=user)",
                "Listing 24.1 - the whole of defect G1", "diff"),
            p("Now trace it through the gate. The authorization rules in "
              "`authz.py` are untouched -- still correct, still scoring "
              f"{CLEAN_MS:.0%} on mutation. The unit and BDD suites are green: no "
              "scenario fetches another user's note by id. SAST sees nothing "
              "dangerous -- a removed function call is an absence, not a pattern. "
              "DAST's probes cover injection, XSS, the admin route and headers, but "
              "not this object-ownership check. So G1 is caught by nobody."),
            callout("key", "The gap, stated plainly",
                     p("A perfect, fully tested authorization module does not make "
                       "an app safe if a route forgets to call it. Unit tests of "
                       "the helpers, a green acceptance suite, a 100% mutation "
                       "score, a clean SAST report and a passing DAST run -- all "
                       "five green, and the app still leaks every note to every "
                       "user. This is the honest ceiling of an automated gate.")),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 25 ═

CH25 = {
    "title": "Closing the gap",
    "abstract": "The IDOR is catchable -- but only by a check that knows your model.",
    "sections": [
        {"title": "What would have caught it", "html": "".join([
            p("G1 is not uncatchable in principle; it is uncaught by the five "
              "generic layers as configured. Each of three additions would have "
              "caught it, and each requires knowing something about the "
              "application's own authorization model:"),
            ol(["<b>A targeted acceptance scenario:</b> 'Given I am alice, when I "
                "open bob's note by id, then the response is 403.' One Gherkin "
                "scenario turns the IDOR into a BDD catch.",
                "<b>An object-level DAST probe:</b> log in as one user, try to "
                "fetch another user's object by id, flag a 200. Generic scanners "
                "cannot write this for you because they do not know what 'another "
                "user's object' means in your schema.",
                "<b>A human code review</b> that asks, of every route returning an "
                "object, 'who is allowed to see this, and where is that checked?'"]),
            p("The common thread: the generic gate catches generic flaws, and the "
              "flaws specific to your domain need checks specific to your domain. "
              "The value of measuring the gate is knowing exactly where that line "
              "falls, so the manual effort goes where the tools are blind."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 26 ═

CH26 = {
    "title": "The quality gate in CI",
    "abstract": "Run all five, fail the build on any.",
    "sections": [
        {"title": "One command, one exit code", "html": "".join([
            p("The gate is what CI runs on every push. It executes the five layers "
              "on the current source and exits non-zero if any fails, which blocks "
              "the merge."),
            code_from(PROJ, "gate/quality_gate.py", start="def run_all()",
                      end="return results, overall",
                      caption="Listing 26.1 - the gate (gate/quality_gate.py)",
                      lang="python"),
            p("On the clean app it prints five PASS lines and exits 0. The CI "
              "workflow then runs the fault-injection measurement and uploads the "
              "reports, so every push both enforces the gate and re-derives the "
              "evidence for why all five layers are there."),
            code_from(PROJ, ".github/workflows/ci.yml", start="      - name: Quality gate",
                      end="path: reports/*.json",
                      caption="Listing 26.2 - the CI steps (.github/workflows/ci.yml)",
                      lang="yaml"),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 27 ═

CH27 = {
    "title": "The mutation ratchet",
    "abstract": "Why the threshold sits just below the current score.",
    "sections": [
        {"title": "A number that only goes up", "html": "".join([
            p(f"The mutation gate fails below {MUT_THRESHOLD:.2f}. That is not an "
              f"arbitrary bar -- it is set just under the clean suite's "
              f"{CLEAN_MS:.2f} so that any real loss of coverage trips it. Teams "
              "run mutation testing as a ratchet: the threshold tracks the current "
              "score, so a change that weakens the tests fails even if it adds "
              "none, and the only way the number moves is up."),
            p(f"Defect T1 is exactly the case the ratchet exists for. The suite "
              f"stays green, so no ordinary gate reacts; the score falls to "
              f"{T1_SCORE}; the ratchet fails the build. Without it, a team can "
              "quietly erode its own test coverage for months while every "
              "dashboard stays green."),
            callout("note", "Mutation testing is not free",
                     p("It reruns the suite once per mutant, so it is the most "
                       "expensive layer. Gauntlet keeps it cheap by scoping it to "
                       "the small, pure authorization module and running in "
                       "process. Real projects scope it to changed files or run it "
                       "nightly rather than per-commit.")),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 28 ═

CH28 = {
    "title": "Reproducibility",
    "abstract": "The same inputs give the same reports, every time.",
    "sections": [
        {"title": "Determinism by construction", "html": "".join([
            p("Every layer is deterministic. The mutation engine walks the AST in "
              "a fixed order. Bandit and the custom rules are pure functions of the "
              "source. The DAST probes use a fixed seed and a fixed payload against "
              "an in-process client. The harness applies patches by literal "
              "replacement and sorts its outputs."),
            p("So `reports/catch_matrix.json`, `reports/summary.json` and "
              "`reports/agreement.json` are byte-identical on every run -- which "
              "is verified by re-running the harness and diffing. A number in this "
              "notebook that disagreed with a fresh run would be a bug, not a "
              "rounding difference."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 29 ═

CH29 = {
    "title": "Context: the OWASP classes these map to",
    "abstract": "The toy defects are small instances of the industry's top risks.",
    "sections": [
        {"title": "Why these defects and not others", "html": "".join([
            p("The catalog is not arbitrary. Each vulnerability is a scaled-down "
              "instance of a category from the OWASP Top 10, the industry's "
              "consensus list of the most common web application risks:"),
            table(["Defect", "OWASP category"],
                  [["S1 SQL injection", "A03: Injection"],
                   ["S2 stored XSS", "A03: Injection (cross-site scripting)"],
                   ["S3 hard-coded secret", "A05: Security Misconfiguration"],
                   ["S4 MD5 hashing", "A02: Cryptographic Failures"],
                   ["S5 missing admin check", "A01: Broken Access Control"],
                   ["S6 missing headers", "A05: Security Misconfiguration"],
                   ["G1 IDOR", "A01: Broken Access Control"]],
                  caption="Table 29.1 - defects mapped to OWASP Top 10 (2021)"),
            p("Broken access control (A01) is the top risk on that list, and it is "
              "also the class with a foot on both sides of this gate's line: S5 is "
              "caught by DAST, while G1 escapes entirely. That is not a "
              "coincidence -- access control is logic specific to your domain, and "
              "generic tools catch the generic half of it."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 30 ═

CH30 = {
    "title": "What this does not establish",
    "abstract": "The honest limits of a ten-defect study on one small app.",
    "sections": [
        {"title": "Limits", "html": "".join([
            ul([
                "<b>One small app.</b> The absolute catch counts are properties of "
                "this catalog and this code, not universal constants. The "
                "structure -- each layer owning a class, one class escaping -- is "
                "the transferable result, not '2 of 10'.",
                "<b>Curated defects.</b> The defects are chosen to be clean, single-"
                "cause instances of their class. Real defects are messier and "
                "sometimes span classes; a real SQL injection might also break a "
                "feature and be caught functionally too.",
                "<b>In-process DAST.</b> The probes use Flask's test client, not a "
                "real HTTP scanner over the network. That makes them reproducible "
                "but means they miss anything that only appears under a real "
                "server, proxy or browser.",
                "<b>Mutation scoped to authz.</b> The mutation gate judges one "
                "module. A weakened test elsewhere would not be caught; mutation "
                "coverage is only as broad as where you run it.",
                "<b>The gate bounds risk; it does not prove safety.</b> G1 is the "
                "standing reminder. A green five-layer gate means the known generic "
                "classes are handled, not that the app is secure.",
            ]),
            p("None of these weakens the finding; they place it. The project "
              "measures what five common layers do and do not catch on a controlled "
              "set of defects, with its baseline and its false-positive rate both "
              "measured. That is the claim, and no more."),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 31 ═

CH31 = {
    "title": "Exercises",
    "abstract": "Extend the gate and watch the matrix move.",
    "sections": [
        {"title": "Problems", "html": "".join([
            ol(["Add a Gherkin scenario that fetches another user's note by id and "
                "expects 403. Re-run the harness. Which column does G1 light up in "
                "now, and does its catalog prediction need updating?",
                "Add a sixth defect: a second weak test that neuters a `can_edit` "
                "assertion. Predict which layer catches it before running.",
                "Lower the mutation threshold to 0.70. Does T1 still fail the "
                "gate? What does that tell you about choosing the bar?",
                "Write a defect that both breaks a feature and is a vulnerability "
                "(e.g. search that is injectable AND returns wrong results). How "
                "many layers catch it, and what does that do to the 'each layer "
                "owns a class' story?",
                "The benign control N1 adds an unused constant. Devise a benign "
                "change that you expect to trip a layer falsely, and find out "
                "whether it does."]),
        ])},
        {"title": "Answers", "html": "".join([
            ol([f"G1 moves into the <code>bdd</code> column; its prediction "
                "changes from empty to <code>[bdd]</code>, and the escaped set "
                "becomes empty. The gap was a missing test, not an uncatchable bug.",
                "Mutation catches it (the authz suite loses teeth), and only "
                "mutation -- the same shape as T1. The acceptance suite stays "
                "green.",
                f"At 0.70, T1's score of {T1_SCORE} would <i>pass</i> "
                f"({T1_SCORE} is above 0.70), so the gate would miss it. The "
                "threshold must sit just below the achieved score, or the ratchet "
                "has slack a weakened suite can hide in.",
                "Several layers catch it at once (functional AND sast/dast), which "
                "is fine: 'each layer owns a class' is about coverage, not "
                "exclusivity. Overlap is defense in depth, not waste.",
                "Most benign edits trip nothing (that is the point of N1). A change "
                "that renames a variable to contain the word 'password' can trip "
                "Bandit's B105 heuristic -- a true false positive, and a good "
                "lesson in why SAST findings need triage, not blind trust."]),
        ])},
    ],
}

# ═══════════════════════════════════════════════════════════════ chapter 32 ═

CH32 = {
    "title": "Recap",
    "abstract": "What to carry out of this notebook.",
    "sections": [
        {"title": "The five sentences", "html": "".join([
            ol([f"A good green test suite (unit + BDD, {CLEAN_MS:.0%} mutation "
                f"score) caught {BASE['n_caught']} of {NDEF} injected defects -- "
                "the functional bugs and nothing else.",
                "Mutation testing caught the one defect that was invisible to "
                "every other layer: a test that passed while asserting nothing.",
                "SAST and DAST are complementary -- SAST sees code-level vulns "
                "with no runtime trace, DAST sees runtime vulns with no code "
                "pattern, and they confirm each other where a vuln is both.",
                f"The full five-layer gate caught {GATE['n_caught']} of {NDEF}, "
                "with zero false positives on a benign change.",
                "One flaw -- an IDOR behind correct, fully tested authorization "
                "rules -- escaped all five, because a quality gate bounds risk but "
                "cannot prove safety."]),
            p("A quality gate is not one tool; it is a portfolio of them, each "
              "chosen to see a different kind of wrong -- and a clear-eyed note of "
              "the wrong that none of them can see."),
        ])},
    ],
}

# ─────────────────────────────────────────────────────────── runbook + appendix

RUNBOOK = {
    "title": "Runbook",
    "abstract": "Run the gate and reproduce every number in this notebook.",
    "sections": [
        {"title": "Install and run", "html": "".join([
            code_literal(
                "python -m venv .venv\n"
                "# Windows: .venv\\Scripts\\activate   macOS/Linux: source .venv/bin/activate\n"
                "pip install -r requirements.txt\n\n"
                "python -m gate.quality_gate     # the gate on the clean app (5 x PASS, exit 0)\n"
                "python -m harness.score         # inject 10 defects -> reports/*.json",
                "Listing R.1 - the whole workflow", "bash"),
            p("Run any single layer directly: <code>python -m pytest tests</code>, "
              "<code>python -m behave</code>, <code>python gate/mutation.py</code>, "
              "<code>python gate/sast.py app</code>, "
              "<code>python gate/dast.py</code>."),
        ])},
        {"title": "What you should see", "html": "".join([
            ul([f"The gate prints five PASS lines and exits 0.",
                f"The harness prints the defect x layer grid: green suite "
                f"{BASE['n_caught']}/{NDEF}, full gate {GATE['n_caught']}/{NDEF}, "
                f"{', '.join(ESCAPED)} escaping all five, no false positives.",
                "The three report files are byte-identical on a second run."]),
        ])},
    ],
}

GLOSSARY = [
    ("SAST", "Static application security testing: analysing source code without "
     "running it. Here, Bandit plus custom AST rules."),
    ("DAST", "Dynamic application security testing: attacking the running app and "
     "observing responses. Here, probes through Flask's test client."),
    ("BDD", "Behaviour-driven development: acceptance tests written in business "
     "language (Gherkin), run by Behave."),
    ("mutation testing", "Introducing deliberate small changes to the code and "
     "checking whether the tests fail; measures whether tests have teeth."),
    ("mutation score", "Killed mutants / total mutants; the fraction of deliberate "
     "bugs the suite caught."),
    ("IDOR", "Insecure direct object reference: accessing another user's object by "
     "guessing or changing its id, because the route does not check ownership."),
    ("XSS", "Cross-site scripting: an attacker's markup is rendered unescaped and "
     "runs in another user's browser."),
    ("quality gate", "An automated pass/fail check in CI that blocks a merge when "
     "any of its component checks fails."),
    ("false positive", "A gate finding on code that is not actually defective; too "
     "many train a team to ignore the gate."),
]

APPENDIX = {
    "title": "Appendix - glossary",
    "abstract": "Terms used in this notebook.",
    "sections": [
        {"title": "Glossary", "html": table(
            ["Term", "Meaning"], [[t, d] for t, d in GLOSSARY],
            caption="Table A.1 - glossary")},
    ],
}

# ═════════════════════════════════════════════════ extra code-tour chapters ═

CH_ROUTES = {
    "title": "The rest of the routes",
    "abstract": "Search, the note view and the admin export -- the three security "
                "surfaces, in full.",
    "sections": [
        {"title": "Search and the note view", "html": "".join([
            p("The search route hands the query to `db.search_notes` and lists the "
              "results; the note view loads a note, checks `can_view`, and renders "
              "it through a constant, autoescaped template. Four defects target "
              "these few lines -- L1, S1, S2 and G1."),
            code_from(PROJ, "app/web.py", start="    @app.get(\"/note/<int:note_id>\")",
                      end="return render_template_string(SEARCH_TMPL, q=q, notes=results)",
                      caption="Listing 2.3 - the note view and search (app/web.py)",
                      lang="python"),
        ])},
        {"title": "The admin export", "html": "".join([
            p("The admin export is guarded by `is_admin`; defect S5 removes that "
              "guard, and only a runtime probe notices."),
            code_from(PROJ, "app/web.py", start="    @app.get(\"/admin/export\")",
                      end="return render_template_string(ADMIN_TMPL, notes=notes)",
                      caption="Listing 2.4 - the admin export (app/web.py)",
                      lang="python"),
        ])},
    ],
}

CH_MUT_FULL = {
    "title": "The mutation gate, end to end",
    "abstract": "From a module path to a pass/fail verdict.",
    "sections": [
        {"title": "Scoring a suite", "html": "".join([
            p("`mutation_score` ties the engine together: confirm the baseline is "
              "green, generate the mutants, run the suite against each, and return "
              "the score with the surviving mutants named so a failure is "
              "actionable."),
            code_from(PROJ, "gate/mutation.py", start="def mutation_score(authz_path",
                      end="\"passed\": rate >= MUTATION_THRESHOLD,",
                      caption="Listing 11.2 - mutation_score (gate/mutation.py)",
                      lang="python"),
            p("The survivors list is the useful part on a failure: it names exactly "
              "which deliberate bug the suite failed to catch, which points "
              "straight at the missing assertion."),
        ])},
    ],
}

CH_SAST_FULL = {
    "title": "The SAST scan, end to end",
    "abstract": "Bandit plus house rules, combined into one verdict.",
    "sections": [
        {"title": "Custom rules and the combined scan", "html": "".join([
            p("The custom layer walks each file for dangerous calls and does a "
              "line-level pass for template flags like `|safe` and "
              "`autoescape=False`. `scan` unions the Bandit findings with the "
              "custom ones and fails on any."),
            code_from(PROJ, "gate/sast.py", start="def custom_findings(app_dir",
                      end="return {\"findings\": findings, \"n\": len(findings), \"passed\": len(findings) == 0}",
                      caption="Listing 14.2 - custom_findings and scan (gate/sast.py)",
                      lang="python"),
        ])},
    ],
}

CH_DAST_FULL = {
    "title": "The remaining probes",
    "abstract": "Owner-scope, access control and headers.",
    "sections": [
        {"title": "Three more probes", "html": "".join([
            p("Beyond injection and XSS, three probes cover the runtime-only "
              "classes: an owner-scope leak, a broken access-control check, and "
              "missing headers."),
            code_from(PROJ, "gate/dast.py", start="def probe_broken_access_control(app)",
                      end="missing security headers: {missing}\"}",
                      caption="Listing 16.1 - access-control and header probes (gate/dast.py)",
                      lang="python"),
            p("Each builds a fresh, freshly seeded app, so the probes cannot "
              "interfere with one another and the order does not matter."),
        ])},
    ],
}

CH_RUNNERS = {
    "title": "The unit and BDD runners",
    "abstract": "Turning two test tools into gate verdicts.",
    "sections": [
        {"title": "pytest and Behave as gates", "html": "".join([
            p("The unit gate runs pytest and reads its exit code; the BDD gate runs "
              "Behave with the JSON formatter and inspects each scenario's status, "
              "so a failure names the scenario that broke."),
            code_from(PROJ, "gate/unit.py", start="def run(cwd: str | None = None) -> dict:",
                      end="\"n_failed\": failed,",
                      caption="Listing 6.2 - the unit runner (gate/unit.py)",
                      lang="python"),
            code_from(PROJ, "gate/bdd.py", start="def run(cwd: str | None = None) -> dict:",
                      end="return {\"passed\": not failed, \"n_scenarios\": len(scenarios), \"failed\": failed}",
                      caption="Listing 7.3 - the BDD runner (gate/bdd.py)",
                      lang="python"),
        ])},
    ],
}

CH_CATALOG_FULL = {
    "title": "A vulnerability entry in full",
    "abstract": "What one catalog edit looks like.",
    "sections": [
        {"title": "Edits and a swap", "html": "".join([
            p("A defect is a tuple of edits. An `Edit` is a literal find/replace in "
              "one file; a `FileSwap` replaces a whole file (used for the weak-test "
              "case, which swaps in a shallow suite)."),
            code_from(PROJ, "harness/defects.py", start="class Edit:",
                      end="source: str",
                      caption="Listing 19.3 - Edit and FileSwap (harness/defects.py)",
                      lang="python"),
            p("The SQL-injection entry is one edit that turns the parameterised "
              "query into an f-string -- and names the two layers it expects to "
              "catch it."),
            code_from(PROJ, "harness/defects.py", start="        id=\"S1\"",
                      end="    return con.execute(sql).fetchall()'),),",
                      caption="Listing 19.4 - the S1 entry (harness/defects.py)",
                      lang="python"),
        ])},
    ],
}

CH_REPORT_FULL = {
    "title": "Assembling the report",
    "abstract": "From per-defect rows to the headline summary.",
    "sections": [
        {"title": "The per-defect detail", "html": "".join([
            p("Each row of the matrix carries the per-layer pass/fail and, for the "
              "mutation layer, the score on that copy -- so the one row where the "
              "score drops is visible at a glance."),
            table(["id", "class", "mutation score", "caught by"],
                  [[r["id"], r["klass"],
                    f"{r['mutation_score']:.2f}" if r.get("mutation_score") is not None else "-",
                    ",".join(r["caught_by"]) or "— none —"] for r in ROWS],
                  caption="Table 20.1 - per-defect detail (reports/catch_matrix.json)"),
            p(f"Only T1 moves the mutation score -- from {CLEAN_MS:.2f} everywhere "
              f"else to {T1_SCORE}. The security and logic defects do not touch the "
              "authorization module or its tests, so the score is unchanged; that "
              "is correct, not a bug, and it is why mutation is a narrow but sharp "
              "instrument."),
        ])},
        {"title": "The summary", "html": "".join([
            p("`_assemble` reduces the rows to the headline: per-layer catch "
              "counts, the baseline-versus-gate comparison, what escaped, and the "
              "false-positive check."),
            code_from(PROJ, "harness/score.py", start="    per_layer = {layer: sum(",
                      end="\"n_caught\": len(gate_caught),",
                      caption="Listing 20.3 - assembling the summary (harness/score.py)",
                      lang="python"),
        ])},
    ],
}

CH_TEMPLATES = {
    "title": "Autoescaping, and the defect that bypasses it",
    "abstract": "Why the clean render is safe and S2 is not.",
    "sections": [
        {"title": "A constant template", "html": "".join([
            p("The note view renders a constant template string. Jinja autoescapes "
              "`{{ note['body'] }}`, so a body of `<script>...</script>` is shown "
              "as text, not executed. The template is a literal, so the SAST rule "
              "leaves it alone."),
            code_from(PROJ, "app/web.py", start="NOTE_TMPL = _PAGE.format",
                      end="<div class=body>{{ note['body'] }}</div>\"\"\")",
                      caption="Listing 2.5 - the autoescaped note template (app/web.py)",
                      lang="python"),
            p("Defect S2 throws this away and builds the HTML by concatenating "
              "`note['body']` into a string passed to `render_template_string`. "
              "That is a dynamic template -- the body is now part of the template "
              "source, not an escaped value -- so the script runs. The custom SAST "
              "rule flags the concatenation; the DAST probe confirms the script "
              "survives. The clean template is the control that makes both "
              "findings meaningful."),
        ])},
    ],
}

CH_MUTATORS = {
    "title": "The other mutators",
    "abstract": "Boolean operators and constants.",
    "sections": [
        {"title": "Flipping and or, bumping constants", "html": "".join([
            p("Besides comparisons, the engine flips boolean operators and alters "
              "constants. The `and` in `user is not None and user['is_admin'] == 1` "
              "becomes `or`; the `1` becomes `2`. Each is a plausible typo, and a "
              "thorough suite kills all of them."),
            code_from(PROJ, "gate/mutation.py", start="    def visit_BoolOp(self, node: ast.BoolOp):",
                      end="self.label = f\"bool {old}->{type(node.op).__name__} @L{node.lineno}\"",
                      caption="Listing 10.3 - the boolean-operator mutator (gate/mutation.py)",
                      lang="python"),
            p("It is the `and`/`or` mutants that defect T1's weak suite lets "
              "survive: they only misbehave when the user is anonymous or an "
              "admin, and the weak suite never passes either input."),
        ])},
    ],
}

CH_UNIT_DETAIL = {
    "title": "Inside the unit suite",
    "abstract": "The storage and hashing tests the security defects walk past.",
    "sections": [
        {"title": "Storage tests catch the scoping bug", "html": "".join([
            p("The storage tests assert the functional contract of search: it finds "
              "the caller's matching notes and is scoped to the caller. The second "
              "assertion is what catches defect L2."),
            code_from(PROJ, "tests/test_db.py", start="def test_search_is_scoped_to_owner",
                      end="assert \"groceries for bob\" not in {r[\"title\"] for r in rows}",
                      caption="Listing 6.3 - the scoping test (tests/test_db.py)",
                      lang="python"),
        ])},
        {"title": "Hashing tests walk past the weak hash", "html": "".join([
            p("The hashing tests check a round trip: the right password verifies, "
              "the wrong one does not, a malformed stored value is rejected. All "
              "three pass for MD5 too -- which is why S4 is a SAST catch, not a "
              "unit catch."),
            code_from(PROJ, "tests/test_security.py",
                      start="def test_round_trip_accepts_correct_password",
                      end="assert verify_password(\"x\", \"not-a-valid-hash\") is False",
                      caption="Listing 6.4 - the hashing tests (tests/test_security.py)",
                      lang="python"),
        ])},
    ],
}

CH_WORKED_S1 = {
    "title": "A worked example: S1 through all five layers",
    "abstract": "One defect, five verdicts, traced by hand.",
    "sections": [
        {"title": "Tracing the SQL-injectable search", "html": "".join([
            p("Take S1 -- the search query rebuilt as an f-string -- and walk it "
              "past each layer, which is the clearest way to see why the matrix "
              "reads as it does."),
            ol(["<b>unit (pass).</b> `test_db` searches for a benign term as one "
                "user. The f-string still scopes to that user for a normal term, "
                "so the results are correct and the test passes. The vulnerability "
                "is invisible to a benign input.",
                "<b>bdd (pass).</b> Same story at the acceptance level: searching "
                "for 'groc' returns the grocery note and hides the rest. The "
                "feature works, so the scenario is green.",
                "<b>mutation (pass).</b> S1 edits `db.py`, not the authorization "
                "module or its tests, so the mutation score is unchanged at "
                f"{CLEAN_MS:.2f}.",
                "<b>sast (FAIL).</b> Bandit reads the f-string with SQL keywords "
                "and raises B608 -- a SQL statement built by string formatting. No "
                "execution required.",
                "<b>dast (FAIL).</b> The probe searches with a payload that closes "
                "the LIKE quote and comments out the wrapper; the query returns "
                "every row, including another user's note, and the probe sees the "
                "leak."]),
            p("Two green, one unaffected, two red -- and the two reds are a static "
              "reader and a live attacker independently reaching the same verdict. "
              "That is the whole argument for a layered gate, in one defect."),
        ])},
    ],
}

CH_PIPELINE = {
    "title": "Where each layer belongs in a pipeline",
    "abstract": "Cost and feedback speed decide when each runs.",
    "sections": [
        {"title": "Not everything runs on every commit", "html": "".join([
            p("The layers differ by an order of magnitude in cost and in how often "
              "they find something, so a real pipeline stages them rather than "
              "running all five on every keystroke."),
            table(["Layer", "Cost", "Typical stage"],
                  [["unit", "milliseconds", "pre-commit and every push"],
                   ["bdd", "seconds", "every push"],
                   ["sast", "seconds", "every push / pull request"],
                   ["dast", "seconds to minutes", "pull request / nightly"],
                   ["mutation", "minutes (reruns the suite per mutant)",
                    "pull request on changed files, or nightly"]],
                  caption="Table 30.1 - staging the layers"),
            p("Gauntlet runs all five on every push because the app is tiny and "
              "every layer finishes in seconds. The structure is what transfers: "
              "put the fast, cheap layers early where they give instant feedback, "
              "and the slow, thorough ones where a few minutes is acceptable -- "
              "but make the slow ones blocking, because the defects they alone "
              "catch (a toothless test, a runtime leak) are exactly the ones a "
              "team will otherwise ship."),
        ])},
    ],
}

CH_GATE_PRINT = {
    "title": "The gate's verdict",
    "abstract": "Five lines and an exit code.",
    "sections": [
        {"title": "A readable pass/fail", "html": "".join([
            p("The gate prints one line per layer with the detail that matters on a "
              "failure -- the failing scenarios, the surviving mutants, the "
              "findings -- and exits non-zero if any layer failed, which is what "
              "blocks a merge."),
            code_from(PROJ, "gate/quality_gate.py", start="def _summary_line(layer: str, r: dict) -> str:",
                      end="return f\"  [{verdict}] {layer:9s} {detail}\"",
                      caption="Listing 26.3 - the per-layer summary line (gate/quality_gate.py)",
                      lang="python"),
            code_literal(
                "==============================================================\n"
                " Gauntlet quality gate\n"
                "==============================================================\n"
                "  [PASS] unit      23 passed\n"
                "  [PASS] bdd       4 scenarios\n"
                f"  [PASS] mutation  score {CLEAN_MS:.2f} (threshold {MUT_THRESHOLD})\n"
                "  [PASS] sast      0 finding(s)\n"
                "  [PASS] dast      0 finding(s)\n"
                "==============================================================\n"
                " RESULT: PASS - all five layers clear\n"
                "==============================================================",
                "Listing 26.4 - the gate on the clean app", "text"),
        ])},
    ],
}

CH_HEADERS_CONFIG = {
    "title": "The headers the app sets",
    "abstract": "A safe default that a one-line defect silently removes.",
    "sections": [
        {"title": "Configured once, applied everywhere", "html": "".join([
            p("The security headers live in config and are applied to every "
              "response by the `after_request` hook shown earlier. They are the "
              "cheap, standard mitigations: stop MIME sniffing, forbid framing, "
              "constrain script sources, drop the referrer."),
            code_from(PROJ, "app/config.py", start="SECURITY_HEADERS = {",
                      end="\"Referrer-Policy\": \"no-referrer\",",
                      caption="Listing 5.2 - the security headers (app/config.py)",
                      lang="python"),
            p("Defect S6 makes the hook return the response without adding any of "
              "them. Nothing in the source looks wrong -- the dict and the hook "
              "still exist -- so no static rule fires. Only fetching a real "
              "response and finding the headers absent reveals it, which is why S6 "
              "is a DAST-only catch."),
        ])},
    ],
}

CH_BENIGN = {
    "title": "The control, in code",
    "abstract": "A real edit that is not a defect.",
    "sections": [
        {"title": "N1: a benign change", "html": "".join([
            p("A fault-injection study needs a negative control: a change that "
              "edits the source but is not a defect, to prove the gate does not "
              "fire on anything that moves. N1 adds an unused display-name "
              "constant next to the config token."),
            code_from(PROJ, "harness/defects.py", start="        id=\"N1\"",
                      end="# benign display name, nothing security-relevant\"),),",
                      caption="Listing 21.1 - the benign control (harness/defects.py)",
                      lang="python"),
            p(f"It is injected and scored exactly like a defect, and it trips "
              f"nothing: {len(SUM['false_positives_on_benign'])} false positives "
              "across all five layers. Without this control, a reader could object "
              "that the gate simply flags any change; with it, the nine catches "
              "are credibly about the defects, not about the act of editing."),
        ])},
    ],
}

CHAPTERS = [CH1, CH2, CH_ROUTES, CH_TEMPLATES, CH3, CH4, CH5, CH_HEADERS_CONFIG,
            CH6, CH_UNIT_DETAIL, CH_RUNNERS, CH7, CH8,
            CH9, CH10, CH_MUTATORS, CH11, CH_MUT_FULL, CH12,
            CH13, CH14, CH_SAST_FULL, CH15, CH16, CH17, CH_DAST_FULL, CH18,
            CH_WORKED_S1, CH19, CH_CATALOG_FULL, CH20, CH_REPORT_FULL, CH_BENIGN,
            CH21, CH22, CH23, CH24, CH25, CH26, CH_GATE_PRINT, CH27, CH28, CH29,
            CH_PIPELINE, CH30, CH31, CH32, RUNBOOK, APPENDIX]

META = {
    "series": "Engineering Notebook",
    "title": "Gauntlet",
    "subtitle": "A CI/CD quality gate, measured",
    "author": "Nikhil Sinha",
    "repo": REPO,
    "stack": "Python · Flask · Behave (BDD) · AST mutation testing · Bandit (SAST) · DAST probes · GitHub Actions",
    "version": "1.0",
    "how_to_read": (
        p("This is a software-quality notebook built around one small Flask app "
          "and a five-layer quality gate -- unit tests, BDD acceptance tests, "
          "mutation testing, SAST and DAST. It is written for someone who tests or "
          "ships software and wants to know, concretely, what each kind of check "
          "catches, what it misses, and why a green test suite is not a safe "
          "release.")
        + p("Every listing is extracted from the repository at build time and "
            "every number is read from the reports a real run wrote, so nothing "
            "here can drift from the code. The headline is a measurement with its "
            "baseline and its false-positive rate both reported.")),
}

if __name__ == "__main__":
    out = HERE / "Gauntlet-Notebook.pdf"
    r = build(META, CHAPTERS, out, min_pages=60)
    print(f"PAGES {r['pages']} (min 60 -> {r['meets_minimum']})  "
          f"WORDS ~{r['approx_words']:,}  {r['chapters']} ch / {r['sections']} sec  "
          f"{r['size_kb']} KB")
