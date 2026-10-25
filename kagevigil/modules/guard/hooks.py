"""
Git Pre-Commit Hook installation and lifecycle management.
Injects automated secret protection into developer Git workflows.
"""

from pathlib import Path

HOOK_SCRIPT = """#!/usr/bin/env bash
# ==============================================================================
# 🛡️ KageVigil Pre-Commit Secret Shield
# Automatically scans staged Git changes before commit. Aborts on leak detection.
# ==============================================================================

if command -v kagevigil &> /dev/null; then
    kagevigil scan --staged
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo ""
        echo "🚨 [KageVigil] Commit aborted! Sensitive secrets detected in staged changes."
        echo "💡 Use inline comments (e.g. '# kagevigil:ignore') or .kageignore if intentional."
        exit $EXIT_CODE
    fi
else
    # Fallback to python module execution if kagevigil binary is in active venv
    if [ -n "$VIRTUAL_ENV" ] && [ -f "$VIRTUAL_ENV/bin/kagevigil" ]; then
        "$VIRTUAL_ENV/bin/kagevigil" scan --staged
        EXIT_CODE=$?
        if [ $EXIT_CODE -ne 0 ]; then
            exit $EXIT_CODE
        fi
    fi
fi

exit 0
"""


def get_git_hooks_dir(repo_path: Path) -> Path:
    """Resolve .git/hooks directory."""
    return repo_path / ".git" / "hooks"


def install_hook(repo_path: Path) -> tuple[bool, str]:
    """Install KageVigil pre-commit hook into target Git repository."""
    git_dir = repo_path / ".git"
    if not git_dir.is_dir():
        return False, f"Not a valid Git repository: {repo_path}"

    hooks_dir = get_git_hooks_dir(repo_path)
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / "pre-commit"

    if hook_file.exists():
        backup_file = hooks_dir / "pre-commit.kagevigil.bak"
        try:
            with open(hook_file, "r", encoding="utf-8") as f:
                content = f.read()
            if "KageVigil Pre-Commit Secret Shield" in content:
                return True, "KageVigil pre-commit hook is already installed."
            # Backup non-KageVigil hook
            with open(backup_file, "w", encoding="utf-8") as bf:
                bf.write(content)
        except Exception as e:
            return False, f"Failed to inspect existing hook: {e}"

    try:
        with open(hook_file, "w", encoding="utf-8") as f:
            f.write(HOOK_SCRIPT)
        # Grant executable permissions (rwxr-xr-x)
        hook_file.chmod(0o755)
        return True, f"Successfully installed pre-commit hook in {hook_file}"
    except Exception as e:
        return False, f"Failed to write hook file: {e}"


def uninstall_hook(repo_path: Path) -> tuple[bool, str]:
    """Uninstall KageVigil pre-commit hook from target Git repository."""
    hook_file = get_git_hooks_dir(repo_path) / "pre-commit"
    if not hook_file.exists():
        return True, "No pre-commit hook found."

    try:
        with open(hook_file, "r", encoding="utf-8") as f:
            content = f.read()
        if "KageVigil Pre-Commit Secret Shield" not in content:
            return (
                False,
                "Existing pre-commit hook was not installed by KageVigil. Will not overwrite.",
            )

        hook_file.unlink()

        # Restore backup if available
        backup_file = get_git_hooks_dir(repo_path) / "pre-commit.kagevigil.bak"
        if backup_file.exists():
            backup_file.rename(hook_file)
            hook_file.chmod(0o755)
            return True, "Uninstalled KageVigil hook and restored previous backup."

        return True, "Successfully uninstalled KageVigil pre-commit hook."
    except Exception as e:
        return False, f"Failed to uninstall hook: {e}"
