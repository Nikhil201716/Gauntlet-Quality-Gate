"""The quality gate: run all four layers and fail the build if any fails.

This is what a CI pipeline calls on every push. It is deliberately strict -- a
single finding from any layer blocks the merge -- because the whole point of the
project is that no one layer is sufficient, so the gate is only as good as the
union of all four.

Run it with ``python -m gate.quality_gate``. Exit code 0 means every layer
passed; 1 means at least one blocked the build.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.getcwd())

from gate import bdd, dast, mutation, sast, unit  # noqa: E402

LAYERS = ("unit", "bdd", "mutation", "sast", "dast")


def run_all() -> tuple[dict, bool]:
    results = {
        "unit": unit.run(),
        "bdd": bdd.run(),
        "mutation": mutation.mutation_score("app/authz.py", "tests/test_authz.py"),
        "sast": sast.scan("app"),
        "dast": dast.scan(),
    }
    overall = all(r["passed"] for r in results.values())
    return results, overall


def _summary_line(layer: str, r: dict) -> str:
    verdict = "PASS" if r["passed"] else "FAIL"
    if layer == "unit":
        detail = f"{r['n_passed']} passed" + (
            "" if r["passed"] else f", {r['n_failed']} failed")
    elif layer == "bdd":
        detail = f"{r['n_scenarios']} scenarios" + (
            "" if r["passed"] else f"; failed: {r['failed']}")
    elif layer == "mutation":
        detail = f"score {r.get('kill_rate', 0):.2f} (threshold {r.get('threshold')})"
        if r.get("survivors"):
            detail += f"; survivors: {r['survivors']}"
    else:
        detail = f"{r['n']} finding(s)"
        if not r["passed"]:
            detail += ": " + ", ".join(
                f.get("id", f.get("probe", "?")) for f in r["findings"])
    return f"  [{verdict}] {layer:9s} {detail}"


def main() -> None:
    results, overall = run_all()
    print("=" * 62)
    print(" Gauntlet quality gate")
    print("=" * 62)
    for layer in LAYERS:
        print(_summary_line(layer, results[layer]))
    print("=" * 62)
    print(f" RESULT: {'PASS - all five layers clear' if overall else 'FAIL - build blocked'}")
    print("=" * 62)
    if "--json" in sys.argv:
        print(json.dumps(results, indent=2))
    sys.exit(0 if overall else 1)


if __name__ == "__main__":
    main()
