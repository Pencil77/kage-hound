"""
Vault Integration Layer for KageHound.
Enables Zero-Knowledge secret auditing and leak detection directly against Infisical Vault.
Guarantees absolute zero raw secret leakage: only variable names and redacted summaries are ever reported.
"""

from kagehound.modules.vault.auditor import VaultAuditor
from kagehound.modules.vault.manager import InfisicalVaultClient
from kagehound.modules.vault.models import (
    VaultBreachFinding,
    VaultLeakFinding,
    VaultLivenessFinding,
    VaultSecretRef,
)

__all__ = [
    "InfisicalVaultClient",
    "VaultAuditor",
    "VaultBreachFinding",
    "VaultLeakFinding",
    "VaultLivenessFinding",
    "VaultSecretRef",
]
