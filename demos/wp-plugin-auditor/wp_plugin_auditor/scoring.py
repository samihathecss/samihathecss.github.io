"""
Risk scoring utilities for WP Plugin Risk & Hardening Auditor.

This module provides simple deterministic scoring based on finding severity.
Note: This is a basic prioritization score, not a validated measure of
exploitability or overall plugin security.
"""

from __future__ import annotations

from collections.abc import Iterable
from .models import Finding

# Mapping from Severity to numeric weight
_SEVERITY_WEIGHTS = {
    "info": 0,
    "low": 1,
    "medium": 3,
    "high": 6,
    "critical": 10,
}


def score_finding(finding: Finding) -> int:
    """
    Score a single finding based on its severity.

    Parameters
    ----------
    finding : Finding
        The finding to score.

    Returns
    -------
    int
        The weight corresponding to the finding's severity.

    Raises
    ------
    TypeError
        If `finding` is not an instance of Finding.
    """
    if not isinstance(finding, Finding):
        raise TypeError("finding must be an instance of Finding")
    # Access the enum's value (string) and map to weight
    return _SEVERITY_WEIGHTS[finding.severity.value]


def score_findings(findings: Iterable[Finding]) -> int:
    """
    Score an iterable of findings by summing their individual scores.

    Parameters
    ----------
    findings : Iterable[Finding]
        An iterable of findings to score.

    Returns
    -------
    int
        The total weight of all findings.

    Raises
    ------
    TypeError
        If any item in `findings` is not an instance of Finding.
    """
    total = 0
    for i, finding in enumerate(findings):
        if not isinstance(finding, Finding):
            raise TypeError(
                f"All items in findings must be Finding instances; "
                f"item at index {i} is {type(finding).__name__}"
            )
        total += score_finding(finding)
    return total