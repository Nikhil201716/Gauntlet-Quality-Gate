#!/usr/bin/env bash
# What Codespaces runs on attach: a stranger opening this repo sees the real
# quality gate run, and then the measurement of which layer catches which defect
# -- not a README claiming it.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=============================================================="
echo " Gauntlet - a CI/CD quality gate, measured"
echo "=============================================================="

pip install -q -r requirements.txt

echo
echo "[1/2] the quality gate on the clean app: unit + BDD + mutation + SAST + DAST"
python -m gate.quality_gate

echo
echo "[2/2] fault injection: inject each defect, see which layer catches it"
python -m harness.score

echo
echo "=============================================================="
echo " A green test suite (unit + BDD) catches the functional bugs and"
echo " nothing else. Mutation catches the test that lost its teeth; SAST"
echo " catches the code-level vulnerabilities; DAST catches the runtime"
echo " ones. One flaw -- an IDOR on the note route -- slips past all five,"
echo " because the authz rules are correct and tested but one route forgot"
echo " to call them. Numbers in reports/*.json."
echo "=============================================================="
