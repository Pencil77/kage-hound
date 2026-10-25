"""
Unit tests for Zero-Knowledge k-Anonymity and HMSL hashing.
"""

from unittest.mock import MagicMock, patch

from kagehound.core.hashing import hibp_hash, hmsl_hash
from kagehound.modules.breach.hibp import HIBPClient
from kagehound.modules.breach.hmsl import HMSLClient


def test_hibp_hash_known_vector():
    """
    Test SHA-1 derivation for 'password'.
    SHA-1 of 'password' is: 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
    Prefix: 5BAA6, Suffix: 1E4C9B93F3F0682250B6CF8331B7EE68FD8
    """
    prefix, suffix = hibp_hash("password")
    assert prefix == "5BAA6"
    assert suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
    assert len(prefix) == 5
    assert len(suffix) == 35


def test_hmsl_hash_length():
    """
    Test HMSL scrypt derivation length (5-char prefix, 59-char suffix = 64 hex chars).
    """
    mock_key = "sk_" + "live_test_dummy_secret_key_12345"
    prefix, suffix = hmsl_hash(mock_key)
    assert len(prefix) == 5
    assert len(suffix) == 59
    assert prefix == prefix.lower()
    assert suffix == suffix.lower()


def test_hibp_client_found():
    """Simulate HIBP response containing the matched suffix."""
    client = HIBPClient()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = (
        "00000000000000000000000000000000000:1\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\n"
    )

    with patch("requests.get", return_value=mock_resp):
        is_pwned, count = client.check_password("password")
        assert is_pwned is True
        assert count == 3861493


def test_hibp_client_clean():
    """Simulate HIBP response not containing the matched suffix."""
    client = HIBPClient()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "00000000000000000000000000000000000:1\n"

    with patch("requests.get", return_value=mock_resp):
        is_pwned, count = client.check_password("extremely_obscure_and_never_leaked_password_99999")
        assert is_pwned is False
        assert count == 0


def test_hmsl_client_matched():
    """Simulate HMSL response containing matched scrypt suffix."""
    client = HMSLClient()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_secret = "sk_" + "live_secret_123"
    prefix, suffix = hmsl_hash(mock_secret)
    mock_resp.json.return_value = {"hashes": [{"hash": suffix}]}

    with patch("requests.get", return_value=mock_resp):
        is_leaked, message = client.check_secret(mock_secret)
        assert is_leaked is True
        assert "EXPOSED" in message
