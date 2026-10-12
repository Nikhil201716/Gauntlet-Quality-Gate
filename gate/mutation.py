"""Mutation-testing gate.

A green unit suite tells you the tests pass; it does not tell you they would
notice if the code were wrong. Mutation testing settles the question directly:
introduce a small deliberate change ("mutant") into the code under test and rerun
the suite. If a test fails, the mutant is *killed* -- the suite had teeth there.
If every test still passes, the mutant *survived* -- a real bug would have slipped
through too.

This module mutates ``app/authz.py`` (small, pure, security-critical) and runs
``tests/test_authz.py`` against each mutant. The mutation score is
killed / total; the gate fails when the score drops below a threshold set just
under the clean suite's score, which is how teams ratchet mutation coverage.

Mutators (one change per mutant, deterministic walk order):
  * comparison operators  (``==`` <-> ``!=``, ``is`` <-> ``is not``, ``<`` <-> ``>=`` ...)
  * boolean operators     (``and`` <-> ``or``)
  * integer constants     (``n`` -> ``n + 1``)
  * boolean constants     (``True`` <-> ``False``)
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
import types
from pathlib import Path

# The gate fails below this score. The clean authz suite scores 1.0; 0.90 leaves
# no room for a genuinely weakened suite (defect T1) to pass.
MUTATION_THRESHOLD = 0.90

_CMP_SWAP = {
    ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
    ast.Lt: ast.GtE, ast.GtE: ast.Lt,
    ast.Gt: ast.LtE, ast.LtE: ast.Gt,
    ast.Is: ast.IsNot, ast.IsNot: ast.Is,
    ast.In: ast.NotIn, ast.NotIn: ast.In,
}


def _is_int_const(node: ast.AST) -> bool:
    return (isinstance(node, ast.Constant)
            and isinstance(node.value, int)
            and not isinstance(node.value, bool))


class _Mutator(ast.NodeTransformer):
    """Apply exactly the ``target``-th mutation in deterministic walk order."""

    def __init__(self, target: int):
        self.target = target
        self.counter = 0
        self.label = None

    def _hit(self) -> bool:
        hit = self.counter == self.target
        self.counter += 1
        return hit

    def visit_Compare(self, node: ast.Compare):
        self.generic_visit(node)
        if len(node.ops) == 1 and type(node.ops[0]) in _CMP_SWAP:
            if self._hit():
                old = type(node.ops[0]).__name__
                node.ops[0] = _CMP_SWAP[type(node.ops[0])]()
                self.label = f"cmp {old}->{type(node.ops[0]).__name__} @L{node.lineno}"
        return node

    def visit_BoolOp(self, node: ast.BoolOp):
        self.generic_visit(node)
        if self._hit():
            old = type(node.op).__name__
            node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
            self.label = f"bool {old}->{type(node.op).__name__} @L{node.lineno}"
        return node

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, bool):
            if self._hit():
                self.label = f"const {node.value}->{not node.value} @L{node.lineno}"
                return ast.copy_location(ast.Constant(value=not node.value), node)
        elif _is_int_const(node):
            if self._hit():
                self.label = f"const {node.value}->{node.value + 1} @L{node.lineno}"
                return ast.copy_location(ast.Constant(value=node.value + 1), node)
        return node


def _count_points(source: str) -> int:
    counter = _Mutator(-1)  # never hits; just counts
    counter.visit(ast.parse(source))
    return counter.counter


def generate_mutants(source: str) -> list[tuple[str, str]]:
    """Return ``[(label, mutated_source), ...]`` -- one mutant per mutation point."""
    mutants = []
    for k in range(_count_points(source)):
        m = _Mutator(k)
        tree = m.visit(ast.parse(source))
        ast.fix_missing_locations(tree)
        mutants.append((m.label, ast.unparse(tree)))
    return mutants


def _run_suite(authz_source: str, test_source: str) -> tuple[int, int]:
    """Run the test functions against ``authz_source`` in-process.

    Returns ``(n_tests, n_failures)``. A test "fails" if it raises anything.
    """
    app_pkg = types.ModuleType("app")
    app_pkg.__path__ = []  # mark as a package
    authz_mod = types.ModuleType("app.authz")
    saved = {k: sys.modules.get(k) for k in ("app", "app.authz")}
    sys.modules["app"] = app_pkg
    sys.modules["app.authz"] = authz_mod
    try:
        exec(compile(authz_source, "app/authz.py", "exec"), authz_mod.__dict__)
        ns: dict = {}
        exec(compile(test_source, "tests/test_authz.py", "exec"), ns)
        tests = [v for k, v in sorted(ns.items())
                 if k.startswith("test_") and callable(v)]
        failures = 0
        for t in tests:
            try:
                t()
            except Exception:
                failures += 1
        return len(tests), failures
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


def mutation_score(authz_path: str, tests_path: str) -> dict:
    authz_source = Path(authz_path).read_text(encoding="utf-8")
    test_source = Path(tests_path).read_text(encoding="utf-8")

    n_tests, base_fail = _run_suite(authz_source, test_source)
    if base_fail:
        return {"baseline_green": False, "baseline_failures": base_fail,
                "n_tests": n_tests, "total": 0, "killed": 0,
                "kill_rate": 0.0, "survivors": [], "passed": False}

    mutants = generate_mutants(authz_source)
    killed, survivors = 0, []
    for label, msrc in mutants:
        _, fails = _run_suite(msrc, test_source)
        if fails:
            killed += 1
        else:
            survivors.append(label)
    total = len(mutants)
    rate = killed / total if total else 1.0
    return {
        "baseline_green": True,
        "n_tests": n_tests,
        "total": total,
        "killed": killed,
        "kill_rate": round(rate, 4),
        "survivors": survivors,
        "threshold": MUTATION_THRESHOLD,
        "passed": rate >= MUTATION_THRESHOLD,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--authz", default="app/authz.py")
    ap.add_argument("--tests", default="tests/test_authz.py")
    args = ap.parse_args()
    print(json.dumps(mutation_score(args.authz, args.tests), indent=2))


if __name__ == "__main__":
    main()
