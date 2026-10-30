"""Findings shared by every module."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

RANK = {"high": 3, "medium": 2, "low": 1}


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    target: str
    detail: str = ""
    remediation: str = ""

    def __post_init__(self):
        if self.severity not in RANK:
            raise ValueError("unknown severity {!r}".format(self.severity))

    @property
    def rank(self) -> int:
        return RANK[self.severity]

    def as_dict(self) -> Dict[str, str]:
        return {"check": self.check_id, "title": self.title, "severity": self.severity,
                "target": self.target, "detail": self.detail, "remediation": self.remediation}


class ModuleUnavailable(Exception):
    """A dependency or network capability is missing. Says which, never guesses."""


def sort_findings(items: List[Finding]) -> List[Finding]:
    return sorted(items, key=lambda f: (-f.rank, f.target, f.check_id))
