# Running Gauntlet

**Python 3.12+.** The mutation engine and the custom SAST rules are pure standard
library; the dependencies are the app under test (Flask), the BDD runner (Behave)
and the SAST tool (Bandit). On Python 3.13/3.14 you need `bandit>=1.9` — older
Bandit crashes on string constants — which `requirements.txt` already pins.

## One-click (devcontainer / Codespaces)

```bash
bash .devcontainer/run-project.sh
```

Installs dependencies, runs the quality gate on the clean app, then runs the
fault-injection measurement.

## Manual

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

python -m gate.quality_gate     # the gate: unit + BDD + mutation + SAST + DAST
python -m harness.score         # inject 10 defects, score 5 layers -> reports/*.json
```

You can run any single layer on its own:

```bash
python -m pytest tests          # unit suite (23 tests)
python -m behave                # BDD acceptance suite (4 scenarios)
python gate/mutation.py         # mutation score of the authz suite
python gate/sast.py app         # Bandit + custom rules over app/
python gate/dast.py             # runtime probes against the app
```

## What you should see

- `gate.quality_gate` prints five `[PASS]` lines and exits 0 on the clean app.
- `harness.score` prints the defect × layer grid and writes
  `reports/catch_matrix.json`, `reports/summary.json` and
  `reports/agreement.json`, identical on every run.
- The grid shows the green test suite catching only the functional bugs, each
  security layer catching its own class, and one defect (the IDOR) escaping all
  five.

## The app under test

```bash
# run the Flask app yourself (Notekeeper: register, log in, write/search notes)
GAUNTLET_SECRET=dev python -m flask --app app.web:create_app run
```

`gate/mutation.py`, `gate/sast.py`, `harness/score.py` are deterministic, so the
reports are byte-reproducible. The DAST probes use Flask's in-process test client,
so no network or running server is needed.
