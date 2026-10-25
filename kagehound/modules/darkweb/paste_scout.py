"""
Public Paste Scout.
Searches public paste mirrors and dump sources for exposed identifiers.
"""

import requests

from kagehound.core.models import LeakMatch


class PasteScout:
    """Scouts public code pastes and dump platforms."""

    def __init__(self, timeout: int = 8):
        self.timeout = timeout

    def search_pastes(self, query: str, limit: int = 10) -> list[LeakMatch]:
        """
        Search public paste mirrors for query references.
        """
        results: list[LeakMatch] = []
        if not query:
            return results

        # Query public paste search indices / DDG paste mirrors
        search_url = "https://html.duckduckgo.com/html/"
        params = {"q": f'site:pastebin.com OR site:rentry.co "{query}"'}
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) KageHound/1.0"}

        try:
            res = requests.post(search_url, data=params, headers=headers, timeout=self.timeout)
            if res.status_code == 200:
                import re
                from urllib.parse import unquote

                matches = re.findall(
                    r'<a class="result__url" href="([^"]+)">(.*?)</a>',
                    res.text,
                )
                for raw_url, display in matches[:limit]:
                    # DDG redirect clean
                    clean_url = raw_url
                    if "uddg=" in raw_url:
                        m = re.search(r"uddg=([^&]+)", raw_url)
                        if m:
                            clean_url = unquote(m.group(1))

                    results.append(
                        LeakMatch(
                            source="pastebin/rentry",
                            target=query,
                            title=display.strip() or "Paste Record",
                            url=clean_url,
                            snippet="Matched in public paste index",
                        )
                    )
            return results
        except Exception:
            return results
