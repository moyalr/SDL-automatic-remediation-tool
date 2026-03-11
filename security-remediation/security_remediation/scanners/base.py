"""Base scanner interface."""

from __future__ import annotations

import abc
import logging
from typing import Optional

from security_remediation.models import Vulnerability

logger = logging.getLogger(__name__)


class BaseScanner(abc.ABC):
    """Abstract base class for security scanners."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable scanner name."""
        ...

    @abc.abstractmethod
    def find_project(self, repo_url: str, project_name: Optional[str] = None) -> Optional[str]:
        """
        Locate the project/image in the scanner that corresponds to the given repo.

        Returns a project identifier string, or None if not found.
        """
        ...

    @abc.abstractmethod
    def get_latest_scan_results(self, project_id: str) -> list[Vulnerability]:
        """
        Fetch the most recent scan results for the given project.

        Returns a list of normalized Vulnerability objects.
        """
        ...

    def scan(self, repo_url: str, project_name: Optional[str] = None) -> list[Vulnerability]:
        """Full scan flow: find project → retrieve results."""
        project_id = self.find_project(repo_url, project_name)
        if project_id is None:
            logger.warning(f"[{self.name}] Repository not found: {repo_url}")
            return []

        logger.info(f"[{self.name}] Found project: {project_id}")
        vulns = self.get_latest_scan_results(project_id)
        logger.info(f"[{self.name}] Retrieved {len(vulns)} vulnerabilities")
        return vulns
