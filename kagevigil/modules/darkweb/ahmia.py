"""
Ahmia Tor Search Engine Client.
Searches Tor hidden services (.onion) indexed by Ahmia for keywords, emails, and identifiers.
"""

import re
import urllib.parse

import requests

from kagevigil.core.models import LeakMatch


class AhmiaScout:
    """Queries Ahmia clearnet gateway for indexed Tor .onion leak references."""

    SEARCH_URL = "https://ahmia.fi/search/"

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def search(self, query: str, limit: int = 10) -> list[LeakMatch]:
        """
        Execute search across indexed Tor hidden services.
        """
        results: list[LeakMatch] = []
        if not query:
            return results

        params = {"q": query}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) KageVigil-ThreatScout/1.0",
            "Accept": "text/html,application/xhtml+xml",
        }

        try:
            res = requests.get(
                self.SEARCH_URL, params=params, headers=headers, timeout=self.timeout
            )
            if res.status_code != 200:
                return results

            html = res.text

            # Parse results from HTML using regex pattern matching
            # Format: <li class="result"><h4><a href="...">Title</a></h4><p>snippet</p>
            item_pattern = re.compile(
                r'<li\s+class="result">[\s\S]*?<h4><a\s+href="([^"]+)">([^<]+)</a></h4>[\s\S]*?<p>([\s\S]*?)</p>',
                re.IGNORECASE,
            )

            for match in item_pattern.finditer(html):
                raw_url = match.group(1).strip()
                raw_title = match.group(2).strip()
                raw_snippet = match.group(3).strip()

                # Clean redirect wrappers if present (e.g. /search/redirect?redirect_url=...)
                url = raw_url
                if "redirect_url=" in raw_url:
                    parsed = urllib.parse.parse_qs(urllib.parse.urlparse(raw_url).query)
                    if parsed.get("redirect_url"):
                        url = parsed["redirect_url"][0]

                # Strip HTML tags from snippet
                snippet = re.sub(r"<[^>]+>", "", raw_snippet).strip()

                results.append(
                    LeakMatch(
                        source="ahmia.tor",
                        target=query,
                        title=raw_title,
                        url=url,
                        snippet=snippet,
                    )
                )

                if len(results) >= limit:
                    break

            return results
        except Exception:
            return results
