"""
Unit tests for Shannon Entropy calculation.
"""

from kagevigil.core.entropy import (
    extract_high_entropy_tokens,
    is_high_entropy,
    shannon_entropy,
)


def test_shannon_entropy_uniform():
    """Identical characters should yield zero entropy."""
    assert shannon_entropy("aaaaaaaaaaaaaaaa") == 0.0


def test_shannon_entropy_low():
    """Simple repeating words have low entropy (< 3.0)."""
    assert shannon_entropy("abcabcabcabcabc") < 3.0


def test_shannon_entropy_high_random():
    """Cryptographically random base64 string should yield high entropy (> 4.5)."""
    random_str = "wK9+2zB7yP8qM1vN4rT6xZ0aC3dE5fG="
    assert shannon_entropy(random_str) > 4.5
    assert is_high_entropy(random_str, threshold=4.3)


def test_extract_high_entropy_tokens():
    """Extract candidate high-entropy tokens from a code line."""
    line = 'const secret = "h8Qk3+Lm9Vp2Nx7Zc0E5rT1wY4uI6oA="; // auth token'
    tokens = extract_high_entropy_tokens(line, threshold=4.2, min_length=16)
    assert len(tokens) >= 1
    assert any("h8Qk3" in t[0] for t in tokens)
