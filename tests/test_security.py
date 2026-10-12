"""Unit tests for password hashing (round-trip and salting).

Note what these cannot catch: they assert that ``verify_password`` accepts the
right password and rejects the wrong one, which is true for PBKDF2 *and* for the
insecure MD5 the weak-crypto defect swaps in. A passing hash round-trip is not
evidence of a strong hash -- that is a job for static analysis, not a unit test.
"""
from app.security import hash_password, verify_password


def test_round_trip_accepts_correct_password():
    stored = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", stored) is True


def test_rejects_wrong_password():
    stored = hash_password("s3kret")
    assert verify_password("not it", stored) is False


def test_malformed_stored_value_is_rejected():
    assert verify_password("x", "not-a-valid-hash") is False
