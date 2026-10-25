"""
End-to-end tests for KageVigil CLI commands.
"""

import tempfile
from pathlib import Path

from click.testing import CliRunner

from kagevigil.cli import cli


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "KageVigil" in result.output


def test_cli_scan_clean_dir():
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmp_dir:
        clean_file = Path(tmp_dir) / "clean.py"
        with open(clean_file, "w") as f:
            f.write("print('Hello, world!')\n")
        result = runner.invoke(cli, ["scan", tmp_dir])
        assert result.exit_code == 0
        assert "No secret leaks detected" in result.output


def test_cli_scan_leaked_secret_aborts_with_code_1():
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmp_dir:
        bad_file = Path(tmp_dir) / "bad.js"
        mock_pat = "gh" + "p_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        with open(bad_file, "w") as f:
            f.write(f"const token = '{mock_pat}';\n")
        result = runner.invoke(cli, ["scan", tmp_dir])
        assert result.exit_code == 1
        assert "Secret Leaks Detected" in result.output
        assert "GitHub" in result.output


def test_cli_check_password_clean():
    runner = CliRunner()
    from unittest.mock import MagicMock, patch

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = ""

    with patch("requests.get", return_value=mock_resp):
        result = runner.invoke(cli, ["check-password", "UniquePasswordNeverSeenBefore987654"])
        assert result.exit_code == 0
        assert "CLEAN" in result.output
