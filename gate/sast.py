"""Static application security testing (SAST) gate.

Two static layers, neither of which runs the app:

* **Bandit** -- the standard Python security linter. It catches the SQL-injection
  string build (B608), the hard-coded secret (B105) and the MD5 password hash
  (B324) the instant those patterns appear in the source.
* **Custom AST rules** -- a few project-specific checks for things Bandit does not
  flag in a Flask app, chiefly a dynamic template passed to
  ``render_template_string`` (the XSS/SSTI defect). This is how real pipelines
  extend a scanner with house rules (the semgrep pattern you write yourself).

The clean source produces zero findings from both layers, so the gate's rule is
simply: any finding fails the build.
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path


def run_bandit(app_dir: str) -> list[dict]:
    """Return Bandit findings as ``[{id, severity, confidence, file, line, text}]``."""
    proc = subprocess.run(
        [sys.executable, "-m", "bandit", "-r", app_dir, "-f", "json", "-q"],
        capture_output=True, text=True,
    )
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    out = []
    for r in data.get("results", []):
        out.append({
            "tool": "bandit",
            "id": r["test_id"],
            "severity": r["issue_severity"],
            "confidence": r["issue_confidence"],
            "file": os.path.basename(r["filename"]),
            "line": r["line_number"],
            "text": r["issue_text"].split("\n")[0][:90],
        })
    return out


def _is_dynamic(node: ast.AST) -> bool:
    """True if ``node`` is a built-up string (f-string or concatenation), not a literal."""
    return isinstance(node, (ast.JoinedStr, ast.BinOp))


class _RuleVisitor(ast.NodeVisitor):
    """House SAST rules for the Flask app."""

    def __init__(self, filename: str):
        self.filename = filename
        self.findings: list[dict] = []

    def _add(self, rule: str, line: int, text: str) -> None:
        self.findings.append({
            "tool": "custom", "id": rule, "severity": "HIGH",
            "confidence": "HIGH", "file": self.filename, "line": line, "text": text,
        })

    def visit_Call(self, node: ast.Call):
        fn = node.func
        name = fn.attr if isinstance(fn, ast.Attribute) else (
            fn.id if isinstance(fn, ast.Name) else "")
        if name == "render_template_string" and node.args and _is_dynamic(node.args[0]):
            self._add("XSS001", node.lineno,
                      "dynamic template passed to render_template_string (XSS/SSTI)")
        if name == "Markup" and node.args and _is_dynamic(node.args[0]):
            self._add("XSS002", node.lineno, "Markup() wrapping a built-up string")
        if name in ("eval", "exec"):
            self._add("CODE001", node.lineno, f"use of {name}()")
        self.generic_visit(node)


def custom_findings(app_dir: str) -> list[dict]:
    findings: list[dict] = []
    for path in sorted(Path(app_dir).rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        v = _RuleVisitor(path.name)
        v.visit(ast.parse(source))
        findings.extend(v.findings)
        # text-level checks for template flags that are not expressions
        for i, line in enumerate(source.splitlines(), 1):
            stripped = line.replace(" ", "")
            if "|safe" in stripped:
                findings.append({"tool": "custom", "id": "XSS003", "severity": "HIGH",
                                 "confidence": "MEDIUM", "file": path.name, "line": i,
                                 "text": "Jinja |safe filter disables autoescaping"})
            if "autoescape=False" in stripped:
                findings.append({"tool": "custom", "id": "XSS004", "severity": "HIGH",
                                 "confidence": "HIGH", "file": path.name, "line": i,
                                 "text": "autoescape disabled"})
    return findings


def scan(app_dir: str = "app") -> dict:
    findings = run_bandit(app_dir) + custom_findings(app_dir)
    findings.sort(key=lambda f: (f["file"], f["line"]))
    return {"findings": findings, "n": len(findings), "passed": len(findings) == 0}


def main() -> None:
    app_dir = sys.argv[1] if len(sys.argv) > 1 else "app"
    print(json.dumps(scan(app_dir), indent=2))


if __name__ == "__main__":
    main()
