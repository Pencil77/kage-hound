"""
Scanner engine for local filesystem and Git repositories.
Handles regex pattern matching, Shannon entropy, .kageignore, and git diff analysis.
"""

import os
import re
import subprocess
from pathlib import Path

from kagehound.core.entropy import extract_high_entropy_tokens, shannon_entropy
from kagehound.core.models import Rule, SecretMatch, Severity
from kagehound.modules.guard.rules import DEFAULT_RULES

IGNORE_COMMENTS = ("kagehound:ignore", "kagevigil:ignore")


def is_binary_file(file_path: Path) -> bool:
    """Check if file contains binary null bytes within its first 1024 bytes."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except Exception:
        return True


def load_kageignore(root_path: Path) -> set[str]:
    """Load paths and glob patterns from .kagehoundignore or .kageignore file if present."""
    patterns: set[str] = set()
    for name in (".kagehoundignore", ".kageignore"):
        ignore_file = root_path / name
        if ignore_file.is_file():
            try:
                with open(ignore_file, "r", encoding="utf-8") as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped and not stripped.startswith("#"):
                            patterns.add(stripped)
            except Exception:
                pass
    return patterns


class Scanner:
    def __init__(
        self,
        rules: list[Rule] | None = None,
        check_entropy: bool = False,
        entropy_threshold: float = 4.3,
        entropy_min_length: int = 16,
        max_file_size_mb: int = 10,
    ):
        self.rules = rules or DEFAULT_RULES
        self.check_entropy = check_entropy
        self.entropy_threshold = entropy_threshold
        self.entropy_min_length = entropy_min_length
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024

        # Precompile regular expressions for high throughput
        self._compiled_rules: list[tuple[Rule, re.Pattern]] = []
        for r in self.rules:
            try:
                flags = re.MULTILINE
                pattern = re.compile(r.regex, flags)
                self._compiled_rules.append((r, pattern))
            except re.error:
                continue

    def scan_text(self, text: str, file_path_display: str = "buffer") -> list[SecretMatch]:
        """Scan raw string content for secrets across lines."""
        matches: list[SecretMatch] = []
        lines = text.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            if any(ig in line for ig in IGNORE_COMMENTS):
                continue

            # 1. Regex signature check
            for rule, pattern in self._compiled_rules:
                for match in pattern.finditer(line):
                    # Pick group 1 if captured, otherwise full match
                    secret_val = (
                        match.group(1)
                        if match.lastindex and match.lastindex >= 1
                        else match.group(0)
                    )
                    matches.append(
                        SecretMatch(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            file_path=file_path_display,
                            line_number=line_idx,
                            raw_secret=secret_val,
                            entropy=shannon_entropy(secret_val),
                        )
                    )

            # 2. Shannon entropy check
            if self.check_entropy:
                high_ent_tokens = extract_high_entropy_tokens(
                    line,
                    threshold=self.entropy_threshold,
                    min_length=self.entropy_min_length,
                )
                for token, score in high_ent_tokens:
                    # Avoid duplicate if already caught by regex
                    if any(m.line_number == line_idx and token in m.raw_secret for m in matches):
                        continue
                    matches.append(
                        SecretMatch(
                            rule_id="KH-ENT-001",
                            rule_name="High-Entropy Secret Candidate",
                            category="Entropy",
                            severity=Severity.MEDIUM,
                            file_path=file_path_display,
                            line_number=line_idx,
                            raw_secret=token,
                            entropy=score,
                        )
                    )

        return matches

    def scan_file(self, file_path: Path) -> list[SecretMatch]:
        """Scan a single physical file on disk."""
        if not file_path.is_file():
            return []

        # Size check
        try:
            if file_path.stat().st_size > self.max_file_size_bytes:
                return []
        except Exception:
            return []

        # Binary check
        if is_binary_file(file_path):
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.scan_text(content, str(file_path))
        except Exception:
            return []

    def scan_directory(
        self,
        dir_path: Path,
        ignore_patterns: list[str] | None = None,
    ) -> tuple[list[SecretMatch], int]:
        """
        Recursively walk directory and scan all applicable files.
        Returns:
            (matches, total_files_scanned)
        """
        all_matches: list[SecretMatch] = []
        files_scanned = 0

        ignores = set(ignore_patterns or [])
        kage_ignores = load_kageignore(dir_path)
        combined_ignores = ignores.union(kage_ignores)

        for root, dirs, files in os.walk(dir_path):
            # Prune ignored directories in-place
            dirs[:] = [
                d
                for d in dirs
                if d not in combined_ignores
                and not any(d.startswith(p.rstrip("/")) for p in combined_ignores)
            ]

            for file_name in files:
                if file_name in combined_ignores or file_name.endswith(".pyc"):
                    continue

                full_path = Path(root) / file_name
                # Check relative path against ignore set
                try:
                    rel = full_path.relative_to(dir_path)
                    if any(str(rel).startswith(p) for p in combined_ignores):
                        continue
                except ValueError:
                    pass

                matches = self.scan_file(full_path)
                files_scanned += 1
                all_matches.extend(matches)

        return all_matches, files_scanned

    def scan_git_staged(self, repo_dir: Path) -> list[SecretMatch]:
        """
        Scan only Git staged changes (diff against HEAD) before commit.
        """
        matches: list[SecretMatch] = []
        try:
            res = subprocess.run(
                ["git", "diff", "--cached", "--no-color", "-U0"],
                cwd=str(repo_dir),
                capture_output=True,
                text=True,
                check=True,
            )
            diff_output = res.stdout
        except Exception:
            return []

        current_file = "unknown"
        current_line = 1
        kage_ignores = load_kageignore(repo_dir)

        for line in diff_output.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
                continue
            # Skip ignored files in staged scan
            if any(
                current_file == p or current_file.startswith(p.rstrip("/") + "/")
                for p in kage_ignores
            ):
                continue
            if line.startswith("@@"):
                # Parse hunk header: @@ -start,count +start,count @@
                m = re.search(r"\+(\d+)", line)
                if m:
                    current_line = int(m.group(1))
                continue
            if line.startswith("+") and not line.startswith("+++"):
                added_content = line[1:]
                sub_matches = self.scan_text(added_content, file_path_display=current_file)
                for sm in sub_matches:
                    sm.line_number = current_line
                    matches.append(sm)
                current_line += 1
            elif not line.startswith("-"):
                current_line += 1

        return matches
