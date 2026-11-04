"""Educational hashing demo. Independent of the Streamlit pages."""

from app.demo import SAMPLE_DEMO_PASSWORD, pbkdf2_demo_digest, unsalted_sha1_hex
from src.auth.password import PBKDF2_ITERATIONS


def test_unsalted_sha1_is_identical_for_the_same_input():
    first = unsalted_sha1_hex(SAMPLE_DEMO_PASSWORD)
    second = unsalted_sha1_hex(SAMPLE_DEMO_PASSWORD)
    assert first == second
    assert len(first) == 40


def test_pbkdf2_demo_uses_unique_salts_and_hashes():
    salt_a, hash_a, iterations_a = pbkdf2_demo_digest(SAMPLE_DEMO_PASSWORD)
    salt_b, hash_b, iterations_b = pbkdf2_demo_digest(SAMPLE_DEMO_PASSWORD)
    assert iterations_a == iterations_b == PBKDF2_ITERATIONS
    assert salt_a != salt_b
    assert hash_a != hash_b
    assert SAMPLE_DEMO_PASSWORD not in salt_a
    assert SAMPLE_DEMO_PASSWORD not in hash_a
