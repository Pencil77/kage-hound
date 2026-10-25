"""
Unit tests for Secret Scanner and Rule Detection.
"""

from kagevigil.core.models import Severity
from kagevigil.modules.guard.scanner import Scanner

# Dynamically assembled tokens to prevent triggering Git/GitHub push protection scanners
MOCK_GHP = "gh" + "p_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
MOCK_TG = "1234567890:" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123"
MOCK_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
MOCK_STRIPE = "sk_" + "live_51A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P"


def test_scanner_detects_github_pat():
    scanner = Scanner()
    text = f"const ghToken = '{MOCK_GHP}';"
    matches = scanner.scan_text(text, "test.ts")
    assert len(matches) == 1
    assert matches[0].rule_name == "GitHub Personal Access Token (Classic)"
    assert matches[0].severity == Severity.CRITICAL
    assert "ghp_***6789" in matches[0].redacted_secret


def test_scanner_detects_telegram_bot_token():
    scanner = Scanner()
    text = f'TELEGRAM_BOT_TOKEN="{MOCK_TG}"'
    matches = scanner.scan_text(text, ".env")
    assert len(matches) == 1
    assert matches[0].rule_name == "Telegram Bot API Token"
    assert matches[0].category == "Communication"


def test_scanner_detects_aws_key():
    scanner = Scanner()
    text = f"AWS_ACCESS_KEY_ID={MOCK_AWS}"
    matches = scanner.scan_text(text, "aws.cfg")
    assert len(matches) == 1
    assert matches[0].rule_name == "AWS Access Key ID"


def test_scanner_detects_stripe_key():
    scanner = Scanner()
    text = f"STRIPE_KEY={MOCK_STRIPE}"
    matches = scanner.scan_text(text, "config.py")
    assert len(matches) == 1
    assert matches[0].rule_name == "Stripe Secret / Restricted Key"


def test_scanner_ignores_inline_comment():
    scanner = Scanner()
    text = f"const ghToken = '{MOCK_GHP}'; // kagevigil:ignore"
    matches = scanner.scan_text(text, "example.ts")
    assert len(matches) == 0


def test_clean_text_produces_no_matches():
    scanner = Scanner()
    clean_code = """
    def add(a: int, b: int) -> int:
        return a + b

    class User:
        name: str
        email: str
    """
    matches = scanner.scan_text(clean_code, "clean.py")
    assert len(matches) == 0
