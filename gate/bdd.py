"""BDD acceptance gate -- runs the Behave suite and reports per-scenario status.

This is the "are the tests green?" layer, and the baseline the whole project
argues against: on its own it catches functional regressions (defect L1 breaks a
scenario) and nothing else, because a green feature suite is blind to injectable
SQL, unescaped output, weak hashing, a missing admin check, absent headers, a
toothless unit suite, and an IDOR that no scenario happens to probe.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile


def run(cwd: str | None = None) -> dict:
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        subprocess.run(
            [sys.executable, "-m", "behave", "-f", "json", "-o", path, "-q",
             "--no-summary"],
            capture_output=True, text=True, cwd=cwd,
        )
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, FileNotFoundError):
        return {"passed": False, "n_scenarios": 0, "failed": ["<behave did not run>"]}
    finally:
        if os.path.exists(path):
            os.unlink(path)

    scenarios = []
    for feature in data:
        for element in feature.get("elements", []):
            if element.get("type") == "scenario":
                scenarios.append((element["name"], element.get("status")))
    failed = [name for name, status in scenarios if status != "passed"]
    return {"passed": not failed, "n_scenarios": len(scenarios), "failed": failed}


def main() -> None:
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
