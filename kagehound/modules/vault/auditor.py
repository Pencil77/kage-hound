"""
Auditor for Infisical Vault Secrets in KageHound.
Performs workspace leak detection, global breach queries, and liveness testing
while strictly preventing raw secret exposure.
"""

import concurrent.futures
import os
import subprocess
from pathlib import Path
from typing import Optional

from kagehound.core.config import DEFAULT_IGNORE_PATHS
from kagehound.modules.breach.hibp import HIBPClient
from kagehound.modules.breach.hmsl import HMSLClient
from kagehound.modules.guard.scanner import is_binary_file, load_kageignore
from kagehound.modules.vault.manager import InfisicalVaultClient
from kagehound.modules.vault.models import (
    VaultBreachFinding,
    VaultLeakFinding,
    VaultLivenessFinding,
    VaultSecretRef,
)
from kagehound.modules.verifier.engine import VerifierEngine


class VaultAuditor:
    """
    Performs security audits against Infisical vault secrets.
    Reports leaks strictly by Variable Name with redacted previews.
    """

    def __init__(
        self,
        client: Optional[InfisicalVaultClient] = None,
        secret_refs: Optional[list[VaultSecretRef]] = None,
    ):
        self.client = client or InfisicalVaultClient()
        self._preset_refs = secret_refs

    def get_audit_secrets(self, env: str = "dev", min_length: int = 6) -> list[VaultSecretRef]:
        """Obtain vault secrets for auditing (from preset or via client)."""
        if self._preset_refs is not None:
            return [r for r in self._preset_refs if len(r.raw_secret.strip()) >= min_length]
        return self.client.get_audit_secrets(env=env, min_length=min_length)

    def audit_text(
        self,
        text: str,
        file_path: str = "in-memory",
        secret_refs: Optional[list[VaultSecretRef]] = None,
    ) -> list[VaultLeakFinding]:
        """
        Scan text for occurrences of vault secrets.
        Never reveals the secret in findings; reports variable_name and safe snippet.
        """
        findings: list[VaultLeakFinding] = []
        if not text:
            return findings

        refs = secret_refs if secret_refs is not None else self.get_audit_secrets()
        if not refs:
            return findings

        lines = text.splitlines()

        # Check multi-line secrets first
        for ref in refs:
            raw = ref.raw_secret
            if "\n" in raw and raw in text:
                # Find the starting line
                first_line = raw.splitlines()[0]
                line_no = 1
                for idx, line in enumerate(lines):
                    if first_line in line:
                        line_no = idx + 1
                        break
                snippet = f"[REDACTED_VAULT_SECRET: {ref.key_name} ({ref.redacted})]"
                findings.append(
                    VaultLeakFinding(
                        variable_name=ref.key_name,
                        file_path=file_path,
                        line_number=line_no,
                        redacted_snippet=snippet,
                        severity="CRITICAL",
                    )
                )

        # Check line-by-line for single-line secrets or substrings
        for line_idx, line in enumerate(lines):
            line_no = line_idx + 1

            # Skip lines with ignore directive
            if "kagehound:ignore" in line:
                continue

            for ref in refs:
                raw = ref.raw_secret
                # Only check single-line secrets or substantial segments
                if "\n" not in raw and raw in line:
                    safe_line = line.replace(
                        raw, f"[VAULT_SECRET:{ref.key_name}:{ref.redacted}]"
                    ).strip()
                    findings.append(
                        VaultLeakFinding(
                            variable_name=ref.key_name,
                            file_path=file_path,
                            line_number=line_no,
                            redacted_snippet=safe_line,
                            severity="CRITICAL",
                        )
                    )

        return findings

    def audit_file(
        self,
        file_path: Path,
        secret_refs: Optional[list[VaultSecretRef]] = None,
    ) -> list[VaultLeakFinding]:
        """Audit an individual file for vault secret leaks."""
        if not file_path.is_file():
            return []
        try:
            # Skip if binary or too large (> 15MB)
            if file_path.stat().st_size > 15 * 1024 * 1024:
                return []
            if is_binary_file(file_path):
                return []
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            return self.audit_text(content, file_path=str(file_path), secret_refs=secret_refs)
        except Exception:
            return []

    def audit_directory(
        self,
        dir_path: Path,
        ignore_patterns: Optional[list[str]] = None,
        env: str = "dev",
        min_length: int = 6,
    ) -> tuple[list[VaultLeakFinding], int]:
        """
        Recursively scan a directory for vault secret leaks.
        Returns: (findings, total_files_scanned)
        """
        ignores = set(ignore_patterns or DEFAULT_IGNORE_PATHS)
        kage_ignores = load_kageignore(dir_path)
        combined_ignores = ignores.union(kage_ignores)

        refs = self.get_audit_secrets(env=env, min_length=min_length)

        findings: list[VaultLeakFinding] = []
        files_scanned = 0

        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [
                d
                for d in dirs
                if d not in combined_ignores
                and not any(d.startswith(p.rstrip("/")) for p in combined_ignores)
            ]

            for file in files:
                if file in combined_ignores or file.endswith(".pyc"):
                    continue

                full_path = Path(root) / file
                try:
                    rel = full_path.relative_to(dir_path)
                    if any(str(rel).startswith(p) for p in combined_ignores):
                        continue
                except ValueError:
                    pass

                file_findings = self.audit_file(full_path, secret_refs=refs)
                findings.extend(file_findings)
                files_scanned += 1

        return findings, files_scanned

    def audit_git_staged(
        self,
        repo_path: Path,
        env: str = "dev",
        min_length: int = 6,
    ) -> list[VaultLeakFinding]:
        """
        Scan staged Git changes for vault secret leaks.
        Ideal for pre-commit checks to intercept uncommitted vault secrets.
        """
        refs = self.get_audit_secrets(env=env, min_length=min_length)
        cmd = ["git", "-C", str(repo_path), "diff", "--cached", "--no-color"]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode != 0 or not res.stdout:
                return []
        except Exception:
            return []

        findings: list[VaultLeakFinding] = []
        current_file = "staged"
        current_line_no = 0

        for line in res.stdout.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
            elif line.startswith("@@"):
                try:
                    # Parse chunk header: @@ -1,1 +1,1 @@
                    parts = line.split("+")[1].split(",")[0]
                    current_line_no = int(parts)
                except Exception:
                    current_line_no = 1
            elif line.startswith("+") and not line.startswith("+++"):
                content = line[1:]
                if "kagehound:ignore" in content:
                    current_line_no += 1
                    continue

                for ref in refs:
                    raw = ref.raw_secret
                    if "\n" not in raw and raw in content:
                        safe_snippet = content.replace(
                            raw, f"[VAULT_SECRET:{ref.key_name}:{ref.redacted}]"
                        ).strip()
                        findings.append(
                            VaultLeakFinding(
                                variable_name=ref.key_name,
                                file_path=current_file,
                                line_number=current_line_no,
                                redacted_snippet=safe_snippet,
                                severity="CRITICAL",
                            )
                        )
                current_line_no += 1

        return findings

    def audit_breaches(
        self,
        env: str = "dev",
        min_length: int = 8,
        secret_refs: Optional[list[VaultSecretRef]] = None,
    ) -> list[VaultBreachFinding]:
        """
        Query global zero-knowledge breach radars (HMSL & HIBP) for vault secrets.
        Never transmits plaintext secrets over the network.
        """
        refs = (
            secret_refs
            if secret_refs is not None
            else self.get_audit_secrets(env=env, min_length=min_length)
        )
        hmsl = HMSLClient()
        hibp = HIBPClient()

        findings: list[VaultBreachFinding] = []

        def _check_single(ref: VaultSecretRef) -> Optional[VaultBreachFinding]:
            raw = ref.raw_secret.strip()
            # Skip massive multi-line JSON or PEM certificates for breach radars
            if "\n" in raw or raw.startswith("{") or raw.startswith("-----BEGIN"):
                return None

            # 1. Check HMSL (API keys, tokens, credentials)
            is_leaked, hmsl_msg = hmsl.check_secret(raw)
            if is_leaked:
                return VaultBreachFinding(
                    variable_name=ref.key_name,
                    breach_source="HasMySecretLeaked (HMSL)",
                    status_message=hmsl_msg,
                    occurrence_count=1,
                    severity="CRITICAL",
                )

            # 2. Check HIBP for passwords or generic tokens
            is_pwned, pwn_count = hibp.check_password(raw)
            if is_pwned:
                return VaultBreachFinding(
                    variable_name=ref.key_name,
                    breach_source="HaveIBeenPwned (HIBP)",
                    status_message=f"Found {pwn_count:,} times in public breach records",
                    occurrence_count=pwn_count,
                    severity="HIGH",
                )
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(_check_single, ref) for ref in refs]
            for future in concurrent.futures.as_completed(futures):
                try:
                    res = future.result()
                    if res is not None:
                        findings.append(res)
                except Exception:
                    pass

        return sorted(findings, key=lambda f: f.variable_name)

    def audit_liveness(
        self,
        env: str = "dev",
        secret_refs: Optional[list[VaultSecretRef]] = None,
    ) -> list[VaultLivenessFinding]:
        """
        Verify the live active status of supported credentials stored in the vault.
        """
        refs = secret_refs if secret_refs is not None else self.get_audit_secrets(env=env)
        engine = VerifierEngine()
        findings: list[VaultLivenessFinding] = []

        for ref in refs:
            v_type = engine.infer_type(ref.raw_secret)
            if v_type and v_type in engine.verifiers:
                res = engine.verify_secret(ref.raw_secret, verifier_type=v_type)
                findings.append(
                    VaultLivenessFinding(
                        variable_name=ref.key_name,
                        service_type=v_type,
                        status=res.status,
                        details=res.message,
                    )
                )

        return findings
