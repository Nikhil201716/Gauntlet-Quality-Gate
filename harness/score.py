"""Inject every defect, run every gate layer, and record which layer caught it.

For each catalog entry the harness copies the whole repo to a temporary
directory, applies the defect's source edits, and runs all five layers against
that copy as separate subprocesses (so each sees the patched code, with no import
caching between runs). A layer "caught" the defect if that layer fails on the
patched copy. The clean copy is run first and must pass every layer -- that is
the control that keeps the baseline honest.

Writes three reports, byte-reproducible across runs:
  * ``catch_matrix.json`` -- the full defect x layer grid.
  * ``summary.json``      -- headline counts, the baseline-vs-gate comparison,
                             what escaped, and the false-positive check.
  * ``agreement.json``    -- measured catches vs the catalog's predictions.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from harness.defects import CATALOG, Defect, Edit, FileSwap

REPO = Path(__file__).resolve().parent.parent
REPORTS = REPO / "reports"
LAYERS = ("unit", "bdd", "mutation", "sast", "dast")
BASELINE_LAYERS = ("unit", "bdd")  # the trivial "the test suite is green" gate

_IGNORE = shutil.ignore_patterns(
    ".venv", ".git", "docs", "reports", "__pycache__", "*.pyc",
    ".pytest_cache", ".github", ".devcontainer",
)


def _copy_repo(dst: Path) -> None:
    shutil.copytree(REPO, dst, ignore=_IGNORE, dirs_exist_ok=True)


def _apply(root: Path, defect: Defect) -> None:
    for edit in defect.edits:
        target = root / edit.file
        if isinstance(edit, FileSwap):
            source = root / edit.source
            target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        elif isinstance(edit, Edit):
            text = target.read_text(encoding="utf-8")
            count = text.count(edit.old)
            if count != 1:
                raise RuntimeError(
                    f"{defect.id}: edit target found {count} times in {edit.file} "
                    f"(expected exactly 1). The source drifted from the catalog."
                )
            target.write_text(text.replace(edit.old, edit.new), encoding="utf-8")


def _py(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], cwd=cwd,
                          capture_output=True, text=True)


def _json_stdout(proc: subprocess.CompletedProcess) -> dict:
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"passed": False, "error": (proc.stderr or proc.stdout)[-300:]}


def _run_layers(root: Path) -> dict:
    out: dict = {}

    # unit: pytest (passed == exit 0)
    p = _py(["-m", "pytest", "-q", "-p", "no:cacheprovider"], root)
    out["unit"] = {"passed": p.returncode == 0}

    # bdd: behave via json report
    _fd, _bjpath = tempfile.mkstemp(suffix=".json")
    import os as _os
    _os.close(_fd)
    bj = Path(_bjpath)
    _py(["-m", "behave", "-f", "json", "-o", str(bj), "-q", "--no-summary"], root)
    try:
        data = json.loads(bj.read_text(encoding="utf-8"))
        failed = [e["name"] for f in data for e in f.get("elements", [])
                  if e.get("type") == "scenario" and e.get("status") != "passed"]
        out["bdd"] = {"passed": not failed, "failed": failed}
    except (json.JSONDecodeError, FileNotFoundError, OSError):
        out["bdd"] = {"passed": False, "failed": ["<behave did not run>"]}
    finally:
        bj.unlink(missing_ok=True)

    # mutation / sast / dast: each prints a JSON verdict
    out["mutation"] = _json_stdout(_py(["gate/mutation.py"], root))
    out["sast"] = _json_stdout(_py(["gate/sast.py", "app"], root))
    out["dast"] = _json_stdout(_py(["gate/dast.py"], root))
    return out


def _caught_by(layers: dict) -> list[str]:
    return [name for name in LAYERS if not layers[name].get("passed", False)]


def run() -> dict:
    with tempfile.TemporaryDirectory(prefix="gauntlet_") as tmp:
        tmp = Path(tmp)

        # control: the clean copy must pass every layer
        clean_root = tmp / "clean"
        _copy_repo(clean_root)
        clean_layers = _run_layers(clean_root)
        clean_caught = _caught_by(clean_layers)

        rows = []
        for defect in CATALOG:
            root = tmp / defect.id
            _copy_repo(root)
            _apply(root, defect)
            layers = _run_layers(root)
            caught = _caught_by(layers)
            rows.append({
                "id": defect.id, "name": defect.name, "klass": defect.klass,
                "is_defect": defect.is_defect, "expected": list(defect.expected),
                "caught_by": caught,
                "per_layer": {k: layers[k].get("passed", False) for k in LAYERS},
                "mutation_score": clean_or_defect_mut(layers),
            })

    return _assemble(clean_layers, clean_caught, rows)


def clean_or_defect_mut(layers: dict):
    m = layers.get("mutation", {})
    return m.get("kill_rate")


def _assemble(clean_layers: dict, clean_caught: list[str], rows: list[dict]) -> dict:
    defects = [r for r in rows if r["is_defect"]]
    benign = [r for r in rows if not r["is_defect"]]

    per_layer = {layer: sum(1 for r in defects if layer in r["caught_by"])
                 for layer in LAYERS}
    baseline_caught = [r["id"] for r in defects
                       if any(l in r["caught_by"] for l in BASELINE_LAYERS)]
    gate_caught = [r["id"] for r in defects if r["caught_by"]]
    escaped = [r["id"] for r in defects if not r["caught_by"]]
    false_positives = [r["id"] for r in benign if r["caught_by"]]

    # agreement with the catalog's predictions
    agree = []
    for r in defects:
        agree.append({
            "id": r["id"],
            "expected": sorted(r["expected"]),
            "measured": sorted(r["caught_by"]),
            "match": sorted(r["expected"]) == sorted(r["caught_by"]),
        })

    summary = {
        "n_defects": len(defects),
        "clean_passes_all_layers": not clean_caught,
        "clean_mutation_score": clean_layers["mutation"].get("kill_rate"),
        "per_layer_catches": per_layer,
        "baseline_green_suite": {
            "layers": list(BASELINE_LAYERS),
            "caught": baseline_caught,
            "n_caught": len(baseline_caught),
            "n_missed": len(defects) - len(baseline_caught),
        },
        "full_gate": {
            "caught": gate_caught,
            "n_caught": len(gate_caught),
        },
        "escaped_all_layers": escaped,
        "false_positives_on_benign": false_positives,
        "prediction_agreement": sum(1 for a in agree if a["match"]),
        "prediction_total": len(agree),
    }
    matrix = {
        "clean": {"caught_by": clean_caught,
                  "per_layer": {k: clean_layers[k].get("passed", False)
                                for k in LAYERS}},
        "defects": rows,
    }
    return {"summary": summary, "matrix": matrix, "agreement": agree}


def _print(summary: dict, rows: list[dict]) -> None:
    print("=" * 74)
    print(" Gauntlet: which gate layer catches which defect")
    print("=" * 74)
    head = f"{'id':3s} {'class':10s} " + " ".join(f"{l:4.4s}" for l in LAYERS) + "  caught by"
    print(head)
    print("-" * 74)
    for r in rows:
        cells = " ".join(("X" if r["per_layer"][l] is False else ".").center(4)
                         for l in LAYERS)
        tag = "" if r["is_defect"] else "(benign)"
        print(f"{r['id']:3s} {r['klass']:10s} {cells}  {','.join(r['caught_by']) or '— none —'} {tag}")
    print("-" * 74)
    b = summary["baseline_green_suite"]
    print(f" green test suite ({'+'.join(b['layers'])}) catches "
          f"{b['n_caught']}/{summary['n_defects']}; "
          f"full gate catches {summary['full_gate']['n_caught']}/{summary['n_defects']}")
    print(f" escaped every layer: {summary['escaped_all_layers'] or 'none'}")
    print(f" false positives on benign change: "
          f"{summary['false_positives_on_benign'] or 'none'}")
    print("=" * 74)


def main() -> None:
    result = run()
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "catch_matrix.json").write_text(
        json.dumps(result["matrix"], indent=2), encoding="utf-8")
    (REPORTS / "summary.json").write_text(
        json.dumps(result["summary"], indent=2), encoding="utf-8")
    (REPORTS / "agreement.json").write_text(
        json.dumps(result["agreement"], indent=2), encoding="utf-8")
    _print(result["summary"], result["matrix"]["defects"])


if __name__ == "__main__":
    main()
