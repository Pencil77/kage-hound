"""
Unit tests for Infisical Vault Integration and Zero-Leakage Guarantees.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from kagehound.cli import cli
from kagehound.core.models import VerificationResult, VerificationStatus
from kagehound.modules.vault.auditor import VaultAuditor
from kagehound.modules.vault.manager import InfisicalVaultClient
from kagehound.modules.vault.models import VaultSecretRef

# Dynamically concatenated mock tokens
MOCK_SECRET_TOKEN = "m" + "k_sec_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
MOCK_PASSWORD = "Pass" + "word123456!@#"


def test_vault_secret_ref_zero_exposure():
    ref = VaultSecretRef(key_name="MOCK_TEST_SECRET", raw_secret=MOCK_SECRET_TOKEN)
    assert ref.key_name == "MOCK_TEST_SECRET"
    assert ref.length == len(MOCK_SECRET_TOKEN)
    assert ref.raw_secret == MOCK_SECRET_TOKEN
    assert ref.sha256 != MOCK_SECRET_TOKEN
    assert len(ref.sha256) == 64

    # String & repr must never expose the raw secret
    assert MOCK_SECRET_TOKEN not in str(ref)
    assert MOCK_SECRET_TOKEN not in repr(ref)
    assert "mk_s***3456" in str(ref)


def test_infisical_vault_client_mock():
    mock_json = (
        '[{"key": "API_KEY", "value": "' + MOCK_SECRET_TOKEN + '"}, '
        '{"key": "PORT", "value": "8080"}, '
        '{"key": "DEBUG_MODE", "value": "true"}]'
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=mock_json, stderr="")
        client = InfisicalVaultClient(project_id="test-proj-123")

        secrets = client.fetch_secrets(env="dev")
        assert len(secrets) == 3
        assert secrets[0].key_name == "API_KEY"

        audit_secrets = client.get_audit_secrets(env="dev", min_length=6)
        # PORT (len 4) and DEBUG_MODE ("true") must be filtered out
        assert len(audit_secrets) == 1
        assert audit_secrets[0].key_name == "API_KEY"

        inventory = client.list_inventory(env="dev")
        assert len(inventory) == 3
        assert "value" not in inventory[0]
        assert inventory[0]["key"] == "API_KEY"


def test_vault_auditor_detects_leaked_variable_name():
    ref = VaultSecretRef(key_name="STRIPE_LIVE_KEY", raw_secret=MOCK_SECRET_TOKEN)
    auditor = VaultAuditor(secret_refs=[ref])

    leaked_code = f"""
    const stripe = require('stripe');
    const client = stripe('{MOCK_SECRET_TOKEN}');
    """

    findings = auditor.audit_text(leaked_code, file_path="server.js")
    assert len(findings) == 1
    finding = findings[0]

    # Finding strictly references the variable name
    assert finding.variable_name == "STRIPE_LIVE_KEY"
    assert finding.file_path == "server.js"
    assert finding.line_number == 3
    # Redacted snippet must NOT contain the raw secret
    assert MOCK_SECRET_TOKEN not in finding.redacted_snippet
    assert "VAULT_SECRET:STRIPE_LIVE_KEY" in finding.redacted_snippet


def test_vault_auditor_respects_ignore_comment():
    ref = VaultSecretRef(key_name="STRIPE_LIVE_KEY", raw_secret=MOCK_SECRET_TOKEN)
    auditor = VaultAuditor(secret_refs=[ref])

    ignored_code = f"const token = '{MOCK_SECRET_TOKEN}'; // kagehound:ignore"
    findings = auditor.audit_text(ignored_code, file_path="config.ts")
    assert len(findings) == 0


def test_vault_auditor_clean_code():
    ref = VaultSecretRef(key_name="STRIPE_LIVE_KEY", raw_secret=MOCK_SECRET_TOKEN)
    auditor = VaultAuditor(secret_refs=[ref])

    clean_code = "const token = process.env.STRIPE_LIVE_KEY;"
    findings = auditor.audit_text(clean_code, file_path="clean.ts")
    assert len(findings) == 0


def test_vault_auditor_directory(tmp_path: Path):
    ref = VaultSecretRef(key_name="SECRET_TOKEN", raw_secret=MOCK_SECRET_TOKEN)
    auditor = VaultAuditor(secret_refs=[ref])

    # Leaked file
    leaked_file = tmp_path / "app.py"
    leaked_file.write_text(f"KEY = '{MOCK_SECRET_TOKEN}'\n", encoding="utf-8")

    # Clean file
    clean_file = tmp_path / "util.py"
    clean_file.write_text("def test(): pass\n", encoding="utf-8")

    findings, total = auditor.audit_directory(tmp_path)
    assert total >= 2
    assert len(findings) == 1
    assert findings[0].variable_name == "SECRET_TOKEN"
    assert findings[0].file_path == str(leaked_file)


def test_vault_auditor_breach_radar_mock():
    ref = VaultSecretRef(key_name="LEAKED_VAULT_KEY", raw_secret=MOCK_SECRET_TOKEN)
    auditor = VaultAuditor(secret_refs=[ref])

    with patch("kagehound.modules.vault.auditor.HMSLClient.check_secret") as mock_hmsl:
        mock_hmsl.return_value = (True, "Found in public breach dump")
        findings = auditor.audit_breaches(secret_refs=[ref])

        assert len(findings) == 1
        assert findings[0].variable_name == "LEAKED_VAULT_KEY"
        assert findings[0].breach_source == "HasMySecretLeaked (HMSL)"
        assert findings[0].severity == "CRITICAL"


def test_vault_auditor_liveness_mock():
    ref = VaultSecretRef(key_name="TELEGRAM_BOT_TOKEN", raw_secret="1234567890:ABC-DEF")
    auditor = VaultAuditor(secret_refs=[ref])

    with patch("kagehound.modules.vault.auditor.VerifierEngine.verify_secret") as mock_verify:
        mock_verify.return_value = VerificationResult(
            status=VerificationStatus.ACTIVE,
            message="Bot verified: @TestBot",
        )
        findings = auditor.audit_liveness(secret_refs=[ref])

        assert len(findings) == 1
        assert findings[0].variable_name == "TELEGRAM_BOT_TOKEN"
        assert findings[0].status == VerificationStatus.ACTIVE
        assert "TestBot" in findings[0].details


def test_vault_cli_runner():
    runner = CliRunner()
    result = runner.invoke(cli, ["vault", "--help"])
    assert result.exit_code == 0
    assert "Zero-Knowledge Infisical Vault Security & Leak Auditing" in result.output
    assert "audit" in result.output
    assert "breach-radar" in result.output
    assert "verify" in result.output
    assert "list" in result.output
