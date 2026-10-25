"""
Infisical Vault Client for KageHound.
Fetches secrets directly into in-memory data structures without writing plaintext to disk.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from kagehound.modules.vault.models import VaultSecretRef

# Trivial values to ignore during workspace leak scanning to prevent false-positives
TRIVIAL_VALUES = {
    "true",
    "false",
    "none",
    "null",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "dev",
    "prod",
    "development",
    "production",
    "test",
    "default",
    "admin",
    "postgres",
    "redis",
    "mongodb",
}


class InfisicalVaultClient:
    """
    Client for interacting with Infisical Vault CLI in-memory.
    All secrets remain sequestered in volatile memory.
    """

    def __init__(
        self,
        project_id: Optional[str] = None,
        infisical_bin: Optional[str] = None,
    ):
        self.infisical_bin = infisical_bin or shutil.which("infisical") or "infisical"
        self.project_id = project_id or self._discover_project_id()

    @staticmethod
    def _discover_project_id() -> Optional[str]:
        """Attempt to discover Infisical project ID from environment or global config."""
        env_id = os.environ.get("INFISICAL_PROJECT_ID")
        if env_id:
            return env_id

        # Check ~/.infisical.yaml
        home_cfg = Path.home() / ".infisical.yaml"
        if home_cfg.is_file():
            try:
                for line in home_cfg.read_text(encoding="utf-8").splitlines():
                    if "project-id:" in line:
                        parts = line.split("project-id:")
                        if len(parts) == 2 and parts[1].strip():
                            return parts[1].strip()
            except Exception:
                pass
        return None

    def is_available(self) -> bool:
        """Check if infisical CLI binary is executable on the system."""
        return shutil.which(self.infisical_bin) is not None

    def fetch_secrets(self, env: str = "dev") -> list[VaultSecretRef]:
        """
        Fetch all secrets from Infisical for a given environment directly into memory.
        Returns a list of VaultSecretRef instances.
        """
        if not self.is_available():
            raise FileNotFoundError(
                f"Infisical CLI binary '{self.infisical_bin}' not found on system PATH."
            )

        cmd = [self.infisical_bin, "export", f"--env={env}", "--format=json"]
        if self.project_id:
            cmd.append(f"--projectId={self.project_id}")

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                env=os.environ.copy(),
            )
        except Exception as e:
            raise RuntimeError(f"Failed to execute Infisical CLI command: {e}") from e

        if res.returncode != 0:
            error_msg = res.stderr.strip() or res.stdout.strip() or "Unknown error"
            raise RuntimeError(f"Infisical export failed (exit code {res.returncode}): {error_msg}")

        try:
            data = json.loads(res.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Infisical JSON export: {e}") from e

        secret_refs: list[VaultSecretRef] = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "key" in item and "value" in item:
                    val = str(item["value"]) if item["value"] is not None else ""
                    secret_refs.append(VaultSecretRef(key_name=item["key"], raw_secret=val))

        return secret_refs

    def get_audit_secrets(self, env: str = "dev", min_length: int = 6) -> list[VaultSecretRef]:
        """
        Get secrets suitable for scanning (filters out empty, short, or trivial values).
        """
        all_secrets = self.fetch_secrets(env=env)
        audit_secrets: list[VaultSecretRef] = []

        for ref in all_secrets:
            raw = ref.raw_secret.strip()
            # Skip empty, too short, or trivial common values
            if len(raw) < min_length:
                continue
            if raw.lower() in TRIVIAL_VALUES:
                continue
            audit_secrets.append(ref)

        return audit_secrets

    def list_inventory(self, env: str = "dev") -> list[dict]:
        """
        Return safe metadata inventory of tracked secrets without raw values.
        """
        secrets = self.fetch_secrets(env=env)
        return [
            {
                "key": s.key_name,
                "length": s.length,
                "redacted": s.redacted,
                "sha256": s.sha256,
            }
            for s in secrets
        ]
