"""
Reporting utilities for WP Plugin Risk & Hardening Auditor.

This module provides functions to convert findings into a structured report
and JSON string. The risk score is a simple prioritization aid, not a
validated measure of exploitability or overall security.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any, Dict, List, Union
from .models import Finding, Severity
from .scoring import score_findings


def build_report(findings: Iterable[Finding], scanned_path: str) -> Dict[str, Any]:
    """
    Build a structured report from an iterable of findings.

    Parameters
    ----------
    findings : Iterable[Finding]
        The findings to include in the report.
    scanned_path : str
        The path that was scanned (e.g., a file or directory).

    Returns
    -------
    dict
        A dictionary representing the report with the following keys:
        - schema_version: "1.0"
        - scanned_path: the supplied path
        - summary: dict with total_findings, risk_score, and by_severity
        - findings: list of finding dicts

    Raises
    ------
    TypeError
        If `findings` contains a non-Finding item or if `scanned_path` is not a string.
    ValueError
        If `scanned_path` is an empty string.
    """
    if not isinstance(scanned_path, str):
        raise TypeError("scanned_path must be a string")
    if not scanned_path:
        raise ValueError("scanned_path must be a non-empty string")

    # Convert findings to a list to allow multiple passes without consuming a generator twice
    findings_list: List[Finding] = []
    for i, f in enumerate(findings):
        if not isinstance(f, Finding):
            raise TypeError(
                f"All items in findings must be Finding instances; "
                f"item at index {i} is {type(f).__name__}"
            )
        findings_list.append(f)

    # Calculate summary
    total_findings = len(findings_list)
    risk_score = score_findings(findings_list)

    # Count by severity
    severity_counts = {severity.name: 0 for severity in Severity}
    for f in findings_list:
        severity_counts[f.severity.name] += 1

    # Build findings list for the report
    findings_report: List[Dict[str, Any]] = []
    for f in findings_list:
        findings_report.append({
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity.name,
            "description": f.description,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "recommendation": f.recommendation,
        })

    # Construct the report dictionary
    report: Dict[str, Any] = {
        "schema_version": "1.0",
        "scanned_path": scanned_path,
        "summary": {
            "total_findings": total_findings,
            "risk_score": risk_score,
            "by_severity": severity_counts,
        },
        "findings": findings_report,
    }

    return report


def report_to_json(report: Dict[str, Any], indent: int = 2) -> str:
    """
    Convert a report dictionary to a JSON string.

    Parameters
    ----------
    report : dict
        The report dictionary produced by `build_report`.
    indent : int, optional
        The number of spaces to indent in the JSON output, by default 2.

    Returns
    -------
    str
        A JSON string representation of the report.

    Raises
    ------
    TypeError
        If `report` is not a dict or if `indent` is not an integer.
    ValueError
        If `indent` is negative.
    """
    if not isinstance(report, dict):
        raise TypeError("report must be a dictionary")
    if not isinstance(indent, int):
        raise TypeError("indent must be an integer")
    if indent < 0:
        raise ValueError("indent must be non-negative")

    # Ensure the report is JSON serializable by attempting to serialize it.
    # We use sort_keys=True for deterministic ordering.
    try:
        return json.dumps(report, indent=indent, sort_keys=True)
    except (TypeError, ValueError) as e:
        raise ValueError(f"Report data is not JSON serializable: {e}") from e