"""Twistlock / Prisma Cloud Compute scanner integration."""

from __future__ import annotations

import logging
from typing import Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from security_remediation.models import ScannerSource, Severity, Vulnerability
from security_remediation.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

PRISMA_CONSOLE_URL = "https://us-west1.cloud.twistlock.com/us-3-159266859"


class TwistlockScanner(BaseScanner):
    """Twistlock / Prisma Cloud Compute scanner client."""

    def __init__(
        self,
        access_key: str,
        secret_key: str,
        console_url: str = PRISMA_CONSOLE_URL,
    ):
        self._console_url = console_url.rstrip("/")
        self._access_key = access_key
        self._secret_key = secret_key
        self._session = requests.Session()
        self._token: Optional[str] = None

    @property
    def name(self) -> str:
        return "Twistlock"

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    def _authenticate(self) -> None:
        """Obtain a JWT token from the Prisma Cloud Compute API."""
        url = f"{self._console_url}/api/v1/authenticate"
        payload = {
            "username": self._access_key,
            "password": self._secret_key,
        }
        resp = self._session.post(url, json=payload)
        resp.raise_for_status()
        self._token = resp.json().get("token")
        logger.debug("Twistlock authentication successful")

    def _headers(self) -> dict:
        if not self._token:
            self._authenticate()
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # API helpers
    # ------------------------------------------------------------------

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    def _get(self, endpoint: str, params: Optional[dict] = None) -> list | dict:
        url = f"{self._console_url}{endpoint}"
        resp = self._session.get(url, headers=self._headers(), params=params)
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Scanner interface
    # ------------------------------------------------------------------

    def find_project(self, repo_url: str, image_name: Optional[str] = None) -> Optional[str]:
        """
        Find the scanned image in Prisma Cloud that corresponds to the repo.

        If `image_name` is provided (from config), use it directly.
        Otherwise, search by repo label or image tag derived from the repo name.
        """
        if image_name:
            return image_name

        search_name = _repo_name_from_url(repo_url)

        try:
            # Search images endpoint
            images = self._get("/api/v1/images", params={"search": search_name, "limit": 10})
            if not images:
                return None

            # images is a list of image objects
            if isinstance(images, list) and len(images) > 0:
                # Return the first matching image ID/name
                first = images[0]
                image_id = first.get("_id", "")
                instances = first.get("instances", [])
                if instances:
                    return instances[0].get("image", image_id)
                return image_id

        except requests.HTTPError as exc:
            logger.error(f"Twistlock image search failed: {exc}")

        return None

    def get_latest_scan_results(self, project_id: str) -> list[Vulnerability]:
        """
        Fetch the latest scan results for the given image from Prisma Cloud.

        Uses the /api/v1/images endpoint filtered by the image ID.
        """
        try:
            images = self._get("/api/v1/images", params={"id": project_id, "limit": 1})
        except requests.HTTPError as exc:
            logger.error(f"Twistlock scan retrieval failed: {exc}")
            return []

        if not images or not isinstance(images, list):
            return []

        image_data = images[0]
        vulnerabilities = []

        # Extract vulnerabilities from the image scan data
        for vuln_item in image_data.get("vulnerabilities", []):
            vuln = _normalize_twistlock_vuln(vuln_item, project_id)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def get_scan_results_from_json(self, scan_results_path: str) -> list[Vulnerability]:
        """
        Parse a previously generated scan-results.json file (from the existing
        Twistlock scan workflow) instead of querying the API.
        """
        import json
        from pathlib import Path

        path = Path(scan_results_path)
        if not path.exists():
            logger.error(f"Scan results file not found: {scan_results_path}")
            return []

        with open(path, "r") as f:
            data = json.load(f)

        vulnerabilities = []
        results = data.get("results", [data]) if isinstance(data, dict) else data

        for result in results:
            for vuln_item in result.get("vulnerabilities", []):
                vuln = _normalize_twistlock_vuln(vuln_item, result.get("id", "unknown"))
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _repo_name_from_url(repo_url: str) -> str:
    name = repo_url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name


def _map_severity(severity_str: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "important": Severity.HIGH,
        "moderate": Severity.MEDIUM,
    }
    return mapping.get(severity_str.lower(), Severity.LOW)


def _normalize_twistlock_vuln(item: dict, image_id: str) -> Optional[Vulnerability]:
    """Convert a Twistlock/Prisma Cloud vulnerability entry to unified schema."""
    try:
        cve_id = item.get("cve", "")
        pkg_name = item.get("packageName", "unknown")
        pkg_version = item.get("packageVersion", "")
        severity_str = item.get("severity", "low")
        cvss = item.get("cvss")
        description = item.get("description", "")
        fixed_version = item.get("fixedVersion") or item.get("fixVersion")
        link = item.get("link", "")

        return Vulnerability(
            id=f"tw-{cve_id or pkg_name}-{pkg_version}",
            cve=cve_id if cve_id.startswith("CVE") else None,
            source=ScannerSource.TWISTLOCK,
            component=pkg_name,
            current_version=pkg_version,
            fixed_version=fixed_version,
            severity=_map_severity(severity_str),
            cvss_score=float(cvss) if cvss else None,
            description=description,
            references=[link] if link else [],
            scanner_metadata=item,
        )
    except Exception as exc:
        logger.warning(f"Failed to normalize Twistlock vulnerability: {exc}")
        return None
