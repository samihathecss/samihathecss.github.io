from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    recommendation: str = field(default_factory=str)

    def __post_init__(self) -> None:
        # Validate required strings are non-empty
        if not self.rule_id:
            raise ValueError("rule_id must be a non-empty string")
        if not self.title:
            raise ValueError("title must be a non-empty string")
        if not self.description:
            raise ValueError("description must be a non-empty string")

        # Validate line_number if provided
        if self.line_number is not None:
            # Reject booleans (bool is a subclass of int in Python, so we need to check type explicitly)
            if isinstance(self.line_number, bool) or not isinstance(self.line_number, int):
                raise TypeError("line_number must be an integer or None")
            if self.line_number <= 0:
                raise ValueError("line_number must be a positive integer")

        # Validate severity is a Severity member (already enforced by type hint, but we check for safety)
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity enum member")