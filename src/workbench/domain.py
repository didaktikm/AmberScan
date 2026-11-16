"""Shared scanner and security contracts."""

from dataclasses import dataclass, field


class DomainError(Exception):
    """A safe error suitable for showing to an operator."""

    def __init__(self, message: str, code: str = "invalid_input") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


@dataclass
class ScanResult:
    findings: list[dict] = field(default_factory=list)
    coverage: list[dict] = field(default_factory=list)
    versions: dict = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
