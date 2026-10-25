"""
Zero-Knowledge cryptographic hashing utilities for k-Anonymity breach radar.
"""

import hashlib

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def hibp_hash(password: str) -> tuple[str, str]:
    """
    Computes SHA-1 hash for HaveIBeenPwned k-Anonymity protocol.
    Returns:
        (prefix_5_chars, suffix_35_chars) in uppercase hexadecimal.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return sha1[:5], sha1[5:]


def hmsl_hash(secret: str) -> tuple[str, str]:
    """
    Computes scrypt hash for HasMySecretLeaked (HMSL) zero-knowledge protocol.
    Standard parameters:
        salt: empty bytes (b"")
        n: 16384 (CPU/memory cost parameter)
        r: 8 (block size parameter)
        p: 1 (parallelization parameter)
        length: 32 bytes (64 hex chars)
    Returns:
        (prefix_5_chars, suffix_59_chars) in lowercase hexadecimal.
    """
    kdf = Scrypt(
        salt=b"",
        length=32,
        n=16384,
        r=8,
        p=1,
    )
    derived = kdf.derive(secret.encode("utf-8")).hex().lower()
    return derived[:5], derived[5:]
