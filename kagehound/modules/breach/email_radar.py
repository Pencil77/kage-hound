"""
Email breach lookup radar using public breach data sources.
"""

import requests

from kagehound.core.models import BreachMatch


class EmailBreachRadar:
    """Queries breach intelligence records for compromised accounts."""

    HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"

    def __init__(self, timeout: int = 8):
        self.timeout = timeout

    def get_known_breaches(self) -> list[dict]:
        """Fetch catalog of all known global breaches."""
        try:
            res = requests.get(
                self.HIBP_BREACHES_URL,
                headers={"User-Agent": "KageHound-Breach-Radar/1.0"},
                timeout=self.timeout,
            )
            if res.status_code == 200:
                return res.json()
            return []
        except Exception:
            return []

    def check_email_directory(self, email: str) -> list[BreachMatch]:
        """
        Query public breach databases for known exposures of an email address.
        """
        matches: list[BreachMatch] = []
        # Query public breach directories (such as XposedOrNot or open catalogs)
        xposed_url = f"https://api.xposedornot.com/v1/check-email/{email}"
        try:
            res = requests.get(
                xposed_url, headers={"User-Agent": "KageHound/1.0"}, timeout=self.timeout
            )
            if res.status_code == 200:
                data = res.json()
                breaches = data.get("breaches", [[]])
                if breaches and isinstance(breaches[0], list):
                    for b_name in breaches[0]:
                        matches.append(
                            BreachMatch(
                                target=email,
                                breach_name=str(b_name),
                                description="Exposed in public data breach dump",
                            )
                        )
        except Exception:
            pass
        return matches
