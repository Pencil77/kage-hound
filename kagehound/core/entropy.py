"""
Shannon Entropy calculation and high-randomness secret detection.
"""

import math
import re
from collections import Counter


def shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string (in bits per symbol).
    Higher entropy corresponds to greater randomness/information density.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)


def is_high_entropy(data: str, threshold: float = 4.3, min_length: int = 16) -> bool:
    """
    Determine whether a candidate string exceeds randomness thresholds typical of cryptographic keys.
    """
    if len(data) < min_length:
        return False
    # Avoid flagging simple uniform strings or paths
    if "/" in data or "\\" in data or " " in data:
        return False
    return shannon_entropy(data) >= threshold


# Token boundaries for extracting potential high-entropy substrings
_TOKEN_REGEX = re.compile(r"""[A-Za-z0-9+/=_-]{16,}""")


def extract_high_entropy_tokens(
    line: str, threshold: float = 4.3, min_length: int = 16
) -> list[tuple[str, float]]:
    """
    Scan a line of text for alphanumeric/base64 tokens with high Shannon entropy.
    Returns list of tuples: (token, entropy_score).
    """
    results = []
    for match in _TOKEN_REGEX.finditer(line):
        token = match.group(0)
        # Strip padding characters
        cleaned = token.rstrip("=")
        if len(cleaned) >= min_length:
            score = shannon_entropy(cleaned)
            if score >= threshold:
                results.append((token, score))
    return results
