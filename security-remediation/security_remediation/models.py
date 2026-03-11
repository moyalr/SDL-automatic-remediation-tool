"""Data models for the security remediation tool."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }[self]

    def __ge__(self, other: Severity) -> bool:
        return self.rank >= other.rank

    def __gt__(self, other: Severity) -> bool:
        return self.rank > other.rank

    def __le__(self, other: Severity) -> bool:
        return self.rank <= other.rank

    def __lt__(self, other: Severity) -> bool:
        return self.rank < other.rank


class ScannerSource(str, Enum):
    BLACKDUCK = "blackduck"
    TWISTLOCK = "twistlock"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class GitPlatform(str, Enum):
    GITHUB = "github"
    EOS2GIT = "eos2git"


class Vulnerability(BaseModel):
    """Unified vulnerability schema — normalized across all scanners."""

    id: str = Field(description="Unique finding ID from the scanner")
    cve: Optional[str] = Field(default=None, description="CVE identifier")
    source: ScannerSource = Field(description="Which scanner reported this")
    component: str = Field(description="Vulnerable package/component name")
    current_version: Optional[str] = Field(default=None, description="Currently installed version")
    fixed_version: Optional[str] = Field(default=None, description="Version that fixes the vulnerability")
    severity: Severity = Field(description="Severity level")
    cvss_score: Optional[float] = Field(default=None, description="CVSS score")
    description: str = Field(default="", description="Short description of the vulnerability")
    references: list[str] = Field(default_factory=list, description="Reference URLs (NVD, etc.)")
    file_path: Optional[str] = Field(default=None, description="Path to the dependency file in the repo")
    scanner_metadata: dict[str, Any] = Field(default_factory=dict, description="Raw scanner-specific data")


class FixAction(str, Enum):
    VERSION_BUMP = "version_bump"
    DEPENDENCY_REPLACEMENT = "dependency_replacement"
    DOCKER_IMAGE_UPDATE = "docker_image_update"
    CONFIG_CHANGE = "config_change"
    CODE_CHANGE = "code_change"
    NO_FIX = "no_fix"


class ProposedFix(BaseModel):
    """A single fix proposed by the AI for a vulnerability."""

    vulnerability_id: str = Field(description="ID of the vulnerability being fixed")
    cve: Optional[str] = Field(default=None)
    component: str = Field(description="Component being fixed")
    action: FixAction = Field(description="Type of fix action")
    file_path: str = Field(description="File to modify")
    old_content: str = Field(description="Content to replace (for diffing)")
    new_content: str = Field(description="Replacement content")
    explanation: str = Field(description="Human-readable explanation of the fix")
    confidence: Confidence = Field(description="Confidence level of the fix")
    breaking_risk: str = Field(default="None", description="Description of potential breaking changes")
    validated: Optional[bool] = Field(default=None, description="Whether the fix passed validation")
    validation_error: Optional[str] = Field(default=None, description="Validation error message if failed")


class RemediationReport(BaseModel):
    """Full report of the remediation run."""

    repo_url: str
    branch: str
    scanner_sources: list[ScannerSource] = Field(default_factory=list)
    scan_dates: dict[str, str] = Field(default_factory=dict)
    total_vulnerabilities: int = 0
    filtered_vulnerabilities: int = 0
    fixes_applied: list[ProposedFix] = Field(default_factory=list)
    fixes_failed: list[ProposedFix] = Field(default_factory=list)
    manual_review: list[Vulnerability] = Field(default_factory=list)
    pr_url: Optional[str] = None
    pr_branch: Optional[str] = None
