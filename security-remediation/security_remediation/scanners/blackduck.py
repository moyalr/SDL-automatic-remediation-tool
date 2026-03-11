"""BlackDuck scanner integration via REST API."""

from __future__ import annotations

import logging
from typing import Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from security_remediation.models import ScannerSource, Severity, Vulnerability
from security_remediation.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

BLACKDUCK_BASE_URL = "https://blackduck.sro.cec.delllabs.net"


class BlackDuckScanner(BaseScanner):
    """BlackDuck SCA scanner client."""

    def __init__(self, api_token: str, base_url: str = BLACKDUCK_BASE_URL):
        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._bearer_token: Optional[str] = None
        self._session = requests.Session()

    @property
    def name(self) -> str:
        return "BlackDuck"

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    def _authenticate(self) -> None:
        """Obtain a bearer token using the API token."""
        url = f"{self._base_url}/api/tokens/authenticate"
        headers = {
            "Authorization": f"token {self._api_token}",
            "Accept": "application/vnd.blackducksoftware.user-4+json",
        }
        resp = self._session.post(url, headers=headers)
        resp.raise_for_status()
        self._bearer_token = resp.json()["bearerToken"]
        logger.debug("BlackDuck authentication successful")

    def _headers(self) -> dict:
        if not self._bearer_token:
            self._authenticate()
        return {
            "Authorization": f"Bearer {self._bearer_token}",
            "Accept": "application/vnd.blackducksoftware.bill-of-materials-6+json",
        }

    # ------------------------------------------------------------------
    # API helpers
    # ------------------------------------------------------------------

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    def _get(self, url: str, params: Optional[dict] = None) -> dict:
        resp = self._session.get(url, headers=self._headers(), params=params)
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Scanner interface
    # ------------------------------------------------------------------

    def find_project(self, repo_url: str, project_name: Optional[str] = None) -> Optional[str]:
        """Search BlackDuck projects by name. Returns the project URL (used as ID)."""
        search_name = project_name or _repo_name_from_url(repo_url)
        url = f"{self._base_url}/api/projects"
        params = {"q": f"name:{search_name}"}

        try:
            data = self._get(url, params=params)
        except requests.HTTPError as exc:
            logger.error(f"BlackDuck project search failed: {exc}")
            return None

        items = data.get("items", [])
        if not items:
            return None

        # Prefer exact name match
        for item in items:
            if item.get("name", "").lower() == search_name.lower():
                return item["_meta"]["href"]

        # Fall back to first result
        return items[0]["_meta"]["href"]

    def get_latest_scan_results(self, project_id: str) -> list[Vulnerability]:
        """Fetch vulnerable BOM components for the most recent version of a project."""
        # 1. Get project versions (latest first)
        versions_url = f"{project_id}/versions"
        versions_data = self._get(versions_url, params={"sort": "createdAt DESC", "limit": 1})
        versions = versions_data.get("items", [])
        if not versions:
            logger.warning("No project versions found in BlackDuck")
            return []

        version_url = versions[0]["_meta"]["href"]
        logger.info(f"BlackDuck latest version: {versions[0].get('versionName', 'unknown')}")

        # 2. Get vulnerable BOM components
        vuln_components_url = f"{version_url}/vulnerable-bom-components"
        vuln_data = self._get(vuln_components_url, params={"limit": 500})
        items = vuln_data.get("items", [])

        # 3. Normalize into unified schema
        vulnerabilities = []
        for item in items:
            vuln = _normalize_blackduck_vuln(item)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _repo_name_from_url(repo_url: str) -> str:
    """Extract a project name from a Git URL."""
    name = repo_url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name


def _map_severity(severity_str: str) -> Severity:
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return mapping.get(severity_str.upper(), Severity.LOW)


def _normalize_blackduck_vuln(item: dict) -> Optional[Vulnerability]:
    """Convert a BlackDuck vulnerable-bom-component entry to a unified Vulnerability."""
    try:
        vuln_info = item.get("vulnerabilityWithRemediation", {})
        component_name = item.get("componentName", "unknown")
        component_version = item.get("componentVersionName", "")

        cve_id = vuln_info.get("vulnerabilityName")
        severity_str = vuln_info.get("severity", "LOW")
        cvss = vuln_info.get("overallScore") or vuln_info.get("baseScore")
        description = vuln_info.get("description", "")
        fixed_version = vuln_info.get("remediationUpdatedAt")  # BlackDuck may provide remediation guidance

        # Extract solution/fixed version from remediation if available
        solution = vuln_info.get("solution", "")
        if solution and not fixed_version:
            fixed_version = solution

        return Vulnerability(
            id=f"bd-{cve_id or component_name}-{component_version}",
            cve=cve_id,
            source=ScannerSource.BLACKDUCK,
            component=component_name,
            current_version=component_version,
            fixed_version=fixed_version,
            severity=_map_severity(severity_str),
            cvss_score=float(cvss) if cvss else None,
            description=description,
            references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"] if cve_id else [],
            scanner_metadata=item,
        )
    except Exception as exc:
        logger.warning(f"Failed to normalize BlackDuck vulnerability: {exc}")
        return None
