"""The four gate layers plus the quality gate that runs them.

Each layer is a thing a real CI pipeline runs:

* ``bdd``       -- the Behave acceptance suite (does the app behave?).
* ``mutation``  -- mutation score of the unit suite (do the tests have teeth?).
* ``sast``      -- Bandit plus a few custom AST rules (is the code dangerous?).
* ``dast``      -- probes against the running app (is it exploitable?).

``quality_gate`` runs all four and fails the build if any does. Every layer is a
real check against the real source; nothing here is hard-coded to a known answer.
"""
