"""
Verification engine coordinating live vendor credential verification.
"""

from kagevigil.core.models import SecretMatch, VerificationResult, VerificationStatus
from kagevigil.modules.verifier.pingers.aws import verify_aws, verify_oci
from kagevigil.modules.verifier.pingers.github import verify_github
from kagevigil.modules.verifier.pingers.openai import verify_openai
from kagevigil.modules.verifier.pingers.stripe import verify_stripe
from kagevigil.modules.verifier.pingers.telegram import verify_telegram


class VerifierEngine:
    """Dispatches secret strings to vendor-specific pingers to test if active."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.verifiers = {
            "telegram": verify_telegram,
            "github": verify_github,
            "stripe": verify_stripe,
            "openai": verify_openai,
            "aws": verify_aws,
            "oci": verify_oci,
        }

    def infer_type(self, secret: str) -> str | None:
        """Infer verifier type from secret prefix or format if not specified."""
        if (
            secret.startswith("ghp_")
            or secret.startswith("github_pat_")
            or secret.startswith("gho_")
        ):
            return "github"
        if (
            secret.startswith("sk_live_")
            or secret.startswith("pk_live_")
            or secret.startswith("rk_live_")
        ):
            return "stripe"
        if (
            secret.startswith("sk-proj-")
            or secret.startswith("sk-admin-")
            or secret.startswith("sk-")
        ):
            return "openai"
        if (
            ":" in secret
            and len(secret.split(":")[0]) in (8, 9, 10, 11)
            and secret.split(":")[0].isdigit()
        ):
            return "telegram"
        if secret.startswith("AKIA") or secret.startswith("ASIA"):
            return "aws"
        if secret.startswith("ocid1."):
            return "oci"
        return None

    def verify_secret(self, secret: str, verifier_type: str | None = None) -> VerificationResult:
        """Execute verification against the specified or inferred vendor."""
        v_type = verifier_type or self.infer_type(secret)
        if not v_type or v_type not in self.verifiers:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIABLE,
                message=f"No automated live verifier available for this secret type ({v_type or 'unknown'}).",
            )

        verifier_func = self.verifiers[v_type]
        return verifier_func(secret, timeout=self.timeout)

    def verify_match(self, match: SecretMatch) -> SecretMatch:
        """Verify a SecretMatch in-place and return it."""
        res = self.verify_secret(match.raw_secret, verifier_type=None)
        match.verification = res
        return match

    def verify_matches(self, matches: list[SecretMatch]) -> list[SecretMatch]:
        """Batch-verify a list of detected matches."""
        for m in matches:
            self.verify_match(m)
        return matches
