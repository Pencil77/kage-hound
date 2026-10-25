"""
Example custom plugin: Detects internal organization or enterprise tokens.
"""

import re

from kagehound.core.models import SecretMatch, Severity
from kagehound.plugins import BaseDetector


class OrgCustomTokenDetector(BaseDetector):
    name = "org_custom_token"

    # Example: custom token with format ORG-SEC-xxxxxxxxxxxx
    PATTERN = re.compile(r"\b(ORG-SEC-[A-Za-z0-9]{24,32})\b")

    def scan(self, content: str, file_path: str = "buffer") -> list[SecretMatch]:
        matches = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            for m in self.PATTERN.finditer(line):
                token = m.group(1)
                matches.append(
                    SecretMatch(
                        rule_id="KH-CUSTOM-001",
                        rule_name="Internal Org Security Token",
                        category="Internal",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        raw_secret=token,
                    )
                )
        return matches
