"""
Unit tests for Live Credential Verifier engine.
"""

from unittest.mock import MagicMock, patch

from kagevigil.core.models import VerificationStatus
from kagevigil.modules.verifier.engine import VerifierEngine
from kagevigil.modules.verifier.pingers.github import verify_github
from kagevigil.modules.verifier.pingers.telegram import verify_telegram


def test_verifier_infer_type():
    engine = VerifierEngine()
    assert engine.infer_type("gh" + "p_1234567890abcdefghijklmnopqrstuv") == "github"
    assert engine.infer_type("sk_" + "live_1234567890abcdef") == "stripe"
    assert engine.infer_type("sk-proj-1234567890abcdef") == "openai"
    assert engine.infer_type("1234567890:abcdefghijklmnopqrstuvwxyz01234") == "telegram"
    assert engine.infer_type("AKIA" + "IOSFODNN7EXAMPLE") == "aws"
    assert engine.infer_type("unknown_token_format") is None


def test_verify_telegram_active():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "ok": True,
        "result": {"id": 12345678, "username": "KageTestBot", "first_name": "Test"},
    }

    with patch("requests.get", return_value=mock_resp):
        res = verify_telegram("123456789:ABCDefgh-TEST")
        assert res.status == VerificationStatus.ACTIVE
        assert "@KageTestBot" in res.message


def test_verify_telegram_revoked():
    mock_resp = MagicMock()
    mock_resp.status_code = 401

    with patch("requests.get", return_value=mock_resp):
        res = verify_telegram("123456789:ABCDefgh-REVOKED")
        assert res.status == VerificationStatus.INACTIVE
        assert "revoked" in res.message.lower()


def test_verify_github_active():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"login": "octocat", "id": 583231}
    mock_resp.headers = {"X-OAuth-Scopes": "repo, user"}

    with patch("requests.get", return_value=mock_resp):
        res = verify_github("ghp_mock_token_12345")
        assert res.status == VerificationStatus.ACTIVE
        assert "@octocat" in res.message
        assert res.details.get("scopes") == "repo, user"


def test_verify_github_revoked():
    mock_resp = MagicMock()
    mock_resp.status_code = 401

    with patch("requests.get", return_value=mock_resp):
        res = verify_github("ghp_mock_revoked_token")
        assert res.status == VerificationStatus.INACTIVE
