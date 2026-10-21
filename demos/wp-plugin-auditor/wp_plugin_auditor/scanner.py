"""
Heuristic PHP scanner for WP Plugin Risk & Hardening Auditor.

This scanner detects risky PHP function patterns using simple regex matching.
Note: This is a heuristic scanner and may produce false positives and false negatives.
It does not execute PHP code or claim to prove vulnerabilities.
"""

from __future__ import annotations

import re
from typing import List
from .models import Finding, Severity


def scan_php_text(source: str, file_path: str = "<memory>") -> List[Finding]:
    """
    Scan PHP source text for risky function patterns.

    Parameters
    ----------
    source : str
        The PHP source code to scan.
    file_path : str, optional
        The file path to associate with findings, by default "<memory>".

    Returns
    -------
    List[Finding]
        List of findings in source order (by line, then by position within line).

    Raises
    ------
    TypeError
        If `source` is not a string.
    """
    if not isinstance(source, str):
        raise TypeError("source must be a string")

    # Define patterns: (rule_id, severity, pattern_regex, description, recommendation)
    patterns = [
        (
            "PHP001",
            Severity.HIGH,
            r"\beval\s*\(",
            "Use of eval() function which can execute arbitrary code and is a common security risk.",
            "Avoid using eval(). If you must, ensure the input is strictly controlled and sanitized.",
        ),
        (
            "PHP002",
            Severity.HIGH,
            r"\bunserialize\s*\(",
            "Use of unserialize() function which can lead to object injection vulnerabilities.",
            "Avoid unserialize() with user input. Use json_decode() for data interchange if possible.",
        ),
        (
            "PHP003",
            Severity.MEDIUM,
            r"\b(shell_exec|exec|system|passthru)\s*\(",
            "Use of shell execution functions that can lead to remote code execution.",
            "Avoid using shell execution functions. If necessary, use strict input validation and whitelisting.",
        ),
        (
            "PHP004",
            Severity.MEDIUM,
            r"\bbase64_decode\s*\(",
            "Use of base64_decode() function which can be used to obfuscate malicious code.",
            "Avoid using base64_decode() to hide code. If used for data, ensure the data is from a trusted source.",
        ),
    ]

    # Compile regex patterns with IGNORECASE flag
    compiled_patterns = [
        (rule_id, severity, re.compile(pattern, re.IGNORECASE), desc, rec)
        for rule_id, severity, pattern, desc, rec in patterns
    ]

    findings: List[Finding] = []
    lines = source.splitlines()

    for line_idx, line in enumerate(lines, start=1):  # 1-based line numbers
        matches: List[tuple[int, str, Severity, str, str]] = []  # (pos, rule_id, severity, desc, rec)

        for rule_id, severity, regex, desc, rec in compiled_patterns:
            for match in regex.finditer(line):
                # Record the start position of the match
                matches.append((match.start(), rule_id, severity, desc, rec))

        # Sort matches by their position in the line
        matches.sort(key=lambda x: x[0])

        for _, rule_id, severity, desc, rec in matches:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=f"Risky PHP function usage ({rule_id})",
                    severity=severity,
                    description=desc,
                    file_path=file_path,
                    line_number=line_idx,
                    recommendation=rec,
                )
            )

    return findings