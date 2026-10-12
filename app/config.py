"""Application configuration.

Two things here are security-relevant and are each the target of a defect:

* ``SECRET_KEY`` / ``API_TOKEN`` -- secrets. In the clean build they come from
  the environment with a dev-only fallback. The hard-coded-secret defect replaces
  ``API_TOKEN`` with a literal, which static analysis (bandit B105/B106) flags.
* ``SECURITY_HEADERS`` -- the response headers applied to every page. The
  missing-headers defect empties this dict; only a running-app probe (DAST) can
  tell the headers are gone, because the source still *mentions* them.
"""
import os

# The Flask session-signing key. A real deployment sets GAUNTLET_SECRET; the
# fallback is clearly marked dev-only so nobody ships it by accident.
SECRET_KEY = os.environ.get("GAUNTLET_SECRET", "dev-only-not-for-production")

# A token the app would use to call an external service. Clean build: from the
# environment, empty by default. (Defect S3 hard-codes a live-looking value here.)
API_TOKEN = os.environ.get("GAUNTLET_API_TOKEN", "")

# PBKDF2 iteration count. Low enough that the test suite stays fast, high enough
# to be a real stretch; the weak-crypto defect bypasses this entirely with MD5.
PBKDF2_ITERATIONS = 50_000

# Security headers attached to every response. (Defect S6 clears this.)
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "no-referrer",
}
