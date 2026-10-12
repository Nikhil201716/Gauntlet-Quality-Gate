# Gauntlet — a CI/CD quality gate, measured

**A green test suite is not a safe release.** Gauntlet is a small Flask app
(Notekeeper) wrapped in a five-layer quality gate — unit tests, BDD acceptance
tests, mutation testing, SAST and DAST — and a harness that injects ten known
defects, one at a time, and measures **which layer catches which**.

The result, written by a real run to `reports/*.json`:

| | caught by | class |
|---|---|---|
| **The green test suite** (unit + BDD) | **2 of 10** defects | functional bugs only |
| **The full five-layer gate** | **9 of 10** defects | + test-teeth, code vulns, runtime vulns |
| **Escaped every layer** | **1 of 10** (an IDOR) | business-logic authorization |
| **False positives on a benign change** | **0** | — |

A passing unit + acceptance suite — even a *good* one: 23 unit tests, and the
authorization core scores **100% on the mutation gate** — catches only the two
functional bugs. It is blind to a SQL-injectable query, a stored XSS, a
hard-coded secret, MD5 password hashing, a missing admin check, absent security
headers, and a unit test that passes while asserting nothing. Each of those is
caught — but only once you add the layer that can see it.

## Which layer catches which (reports/catch_matrix.json)

```
 id  class       unit  bdd  mut  sast dast   caught by
 L1  logic        ·    ✓    ·    ·    ·      bdd        search ignores the query
 L2  logic        ✓    ·    ·    ·    ✓      unit,dast  search drops owner scoping
 T1  weak-test    ·    ·    ✓    ·    ·      mutation   toothless authz unit tests (still green)
 S1  vuln         ·    ·    ·    ✓    ✓      sast,dast  SQL-injectable search
 S2  vuln         ·    ·    ·    ✓    ✓      sast,dast  stored XSS on the note page
 S3  vuln         ·    ·    ·    ✓    ·      sast       hard-coded secret
 S4  vuln         ·    ·    ·    ✓    ·      sast       MD5 password hashing
 S5  vuln         ·    ·    ·    ·    ✓      dast       missing admin authorization
 S6  vuln         ·    ·    ·    ·    ✓      dast       missing security headers
 G1  vuln         ·    ·    ·    ·    ·      — none —   IDOR on the note route
 N1  benign       ·    ·    ·    ·    ·      — none —   (control: must trip nothing)
```

Every measured catch matches the catalog's prediction (`reports/agreement.json`,
10/10), so the grid is the harness holding itself to its own claims.

## Three things worth taking away

1. **Each layer owns a class the others miss.** SAST reads the code, so it alone
   sees the hard-coded secret and the MD5 hash — the app behaves identically, so
   no runtime test can tell. DAST attacks the running app, so it alone sees the
   missing admin check and absent headers — there is no dangerous *pattern* in the
   source, just an absence. SAST and DAST agree on the injectable query and the
   XSS (defense in depth). Neither sees a weak test; mutation testing does.

2. **A green suite can be a toothless suite.** Defect T1 swaps the authorization
   unit tests for a shallow set that still passes — pytest is green — but no
   longer pins the admin and anonymous branches. The mutation score drops from
   1.00 to 0.75 and the gate fails. That is the difference between *tests pass*
   and *tests would notice if the code broke*.

3. **One flaw escaped all five.** G1 is an IDOR: the note route stops calling
   `can_view`, so any logged-in user can read any note by id. The authorization
   rules are still correct and still score 100% on mutation — the app leaks
   anyway, because one route forgot to call them. No layer here happens to probe
   for it. A quality gate bounds the damage; it does not prove the app is safe.
   Closing G1 takes a targeted authorization test (or a human review), which is
   the honest limit of automated gates.

## How it is built

- **The app** (`app/`) — a Flask notes app with login, search, a note view, an
  admin export and security headers. The clean version is secure; every defect is
  one surgical edit to it (`harness/defects.py`).
- **The gate** (`gate/`) — five independent checks, each a real tool against the
  real source: `unit` (pytest), `bdd` (Behave/Gherkin), `mutation` (a standard-
  library AST mutation engine over the authz rules), `sast` (Bandit + custom AST
  rules), `dast` (probes through Flask's test client). `gate/quality_gate.py`
  runs all five and fails the build on any — it is what CI runs.
- **The harness** (`harness/score.py`) — copies the repo, applies one defect,
  runs all five layers against the copy as isolated subprocesses, and records the
  catches. The clean copy is run first as a control and must pass every layer.

Nothing in the grid is hard-coded: each layer genuinely runs and genuinely
passes or fails on the patched code. See [RUN.md](RUN.md) to run it, and
[`docs/Gauntlet-Notebook.pdf`](docs/Gauntlet-Notebook.pdf) for the full write-up —
the mutation engine derived, every layer toured, and the IDOR gap dissected.

## Run it

```bash
pip install -r requirements.txt
python -m gate.quality_gate     # the gate on the clean app: 5 × PASS, exit 0
python -m harness.score         # inject 10 defects, score 5 layers -> reports/*.json
```

Python 3.12+. Everything runs locally in-process (no network, no server, no paid
service) and is byte-reproducible on re-run.
