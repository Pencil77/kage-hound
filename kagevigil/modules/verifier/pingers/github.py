"""
GitHub Personal Access Token verifier.
Pings https://api.github.com/user
"""

import requests

from kagevigil.core.models import VerificationResult, VerificationStatus


def verify_github(token: str, timeout: int = 5) -> VerificationResult:
    """Validate whether GitHub token is active and extract authorized user & scopes."""
    url = "https://api.github.com/user"
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "KageVigil-Credential-Verifier/1.0",
        "Accept": "application/vnd.github.v3+json",
    }
    try:
        res = requests.get(url, headers=headers, timeout=timeout)
        if res.status_code == 200:
            data = res.json()
            login = data.get("login", "unknown")
            scopes = res.headers.get("X-OAuth-Scopes", "")
            return VerificationResult(
                status=VerificationStatus.ACTIVE,
                message=f"Verified GitHub user: @{login} (Scopes: {scopes or 'none'})",
                details={"login": login, "scopes": scopes, "id": data.get("id")},
            )
        elif res.status_code == 401:
            return VerificationResult(
                status=VerificationStatus.INACTIVE,
                message="GitHub token is revoked or unauthorized (HTTP 401).",
            )
        elif res.status_code == 403 and "rate limit" in res.text.lower():
            return VerificationResult(
                status=VerificationStatus.UNVERIFIABLE,
                message="GitHub API rate limit reached.",
            )
        return VerificationResult(
            status=VerificationStatus.UNVERIFIABLE,
            message=f"Unexpected GitHub response: HTTP {res.status_code}",
        )
    except Exception as e:
        return VerificationResult(
            status=VerificationStatus.UNVERIFIABLE,
            message=f"Network error verifying GitHub token: {e}",
        )
