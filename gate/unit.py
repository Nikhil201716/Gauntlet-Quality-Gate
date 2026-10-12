"""Unit-test gate -- runs the pytest suite and reports pass/fail.

Together with the BDD layer this is the ordinary "are the tests green?" check.
It is a capable suite (23 tests, and the authz corner of it scores 100% on the
mutation gate), which is the point: a *good* green suite still misses whole
classes of defect, so it cannot be the only gate.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys


def run(cwd: str | None = None) -> dict:
    # pytest.ini already supplies -q; adding another would become -qq and
    # suppress the "N passed" summary line we parse here.
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider"],
        capture_output=True, text=True, cwd=cwd,
    )
    out = proc.stdout + proc.stderr
    passed = int(m.group(1)) if (m := re.search(r"(\d+) passed", out)) else 0
    failed = int(m.group(1)) if (m := re.search(r"(\d+) failed", out)) else 0
    return {
        "passed": proc.returncode == 0 and failed == 0,
        "n_passed": passed,
        "n_failed": failed,
    }


def main() -> None:
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
