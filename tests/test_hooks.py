"""
Unit tests for Git pre-commit hook installation and uninstallation.
"""

import subprocess
import tempfile
from pathlib import Path

from kagehound.modules.guard.hooks import install_hook, uninstall_hook


def test_hook_lifecycle():
    with tempfile.TemporaryDirectory() as tmp_dir:
        repo_path = Path(tmp_dir)
        # Initialize dummy git repo
        subprocess.run(["git", "init"], cwd=str(repo_path), check=True, capture_output=True)

        hook_file = repo_path / ".git" / "hooks" / "pre-commit"
        assert not hook_file.exists()

        # 1. Install
        success, msg = install_hook(repo_path)
        assert success is True
        assert hook_file.exists()
        assert hook_file.stat().st_mode & 0o111  # Executable bit set

        # 2. Idempotent install
        success2, msg2 = install_hook(repo_path)
        assert success2 is True
        assert "already installed" in msg2

        # 3. Uninstall
        success3, msg3 = uninstall_hook(repo_path)
        assert success3 is True
        assert not hook_file.exists()
