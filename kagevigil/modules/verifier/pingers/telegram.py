"""
Telegram Bot Token verifier.
Pings https://api.telegram.org/bot<token>/getMe
"""

import requests

from kagevigil.core.models import VerificationResult, VerificationStatus


def verify_telegram(token: str, timeout: int = 5) -> VerificationResult:
    """Validate whether Telegram bot token is active."""
    url = f"https://api.telegram.org/bot{token}/getMe"
    try:
        res = requests.get(url, timeout=timeout)
        if res.status_code == 200:
            data = res.json()
            if data.get("ok"):
                user = data.get("result", {})
                username = user.get("username", "unknown")
                bot_id = user.get("id", "unknown")
                return VerificationResult(
                    status=VerificationStatus.ACTIVE,
                    message=f"Verified Telegram Bot: @{username} (ID: {bot_id})",
                    details={
                        "username": username,
                        "id": bot_id,
                        "first_name": user.get("first_name"),
                    },
                )
        elif res.status_code in (401, 404):
            return VerificationResult(
                status=VerificationStatus.INACTIVE,
                message="Telegram bot token is revoked or invalid.",
                details={"status_code": res.status_code},
            )
        return VerificationResult(
            status=VerificationStatus.UNVERIFIABLE,
            message=f"Unexpected Telegram response: HTTP {res.status_code}",
        )
    except Exception as e:
        return VerificationResult(
            status=VerificationStatus.UNVERIFIABLE,
            message=f"Network error verifying Telegram token: {e}",
        )
