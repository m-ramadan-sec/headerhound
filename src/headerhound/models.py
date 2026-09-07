"""Typed data structures shared across the scanner."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Finding:
    code: str
    title: str
    severity: Severity
    deduction: int
    description: str
    remediation: str
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class CookieMetadata:
    """Non-secret attributes parsed from one Set-Cookie response header."""

    name: str
    secure: bool
    httponly: bool
    samesite: str | None
    domain: str | None
    path: str | None
    max_age: int | None
    expires: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    target: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    redirects: tuple[str, ...]
    findings: tuple[Finding, ...]
    score: int
    grade: str
    cookies: tuple[CookieMetadata, ...] = ()
    cors: dict[str, Any] | None = None
    transport: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "status": {"code": self.status_code},
            "headers": self.headers,
            "redirects": list(self.redirects),
            "cookies": [cookie.to_dict() for cookie in self.cookies],
            "cors": self.cors or {},
            "transport": self.transport or {},
            "findings": [finding.to_dict() for finding in self.findings],
            "score": self.score,
            "grade": self.grade,
            "metadata": self.metadata or {"schema_version": "1.0", "analysis_mode": "passive"},
        }
