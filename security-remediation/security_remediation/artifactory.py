"""Dell internal Artifactory client for Docker image tag verification."""

from __future__ import annotations

import logging
from typing import Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

DEFAULT_REGISTRY = "isgedge.artifactory.cec.lab.emc.com"
DEFAULT_REPO = "isgedge-docker-virtual"


class ArtifactoryClient:
    """Query Dell's internal Artifactory to check Docker image tag availability."""

    def __init__(
        self,
        token: str,
        registry: str = DEFAULT_REGISTRY,
        repo: str = DEFAULT_REPO,
    ):
        self._token = token
        self._registry = registry
        self._repo = repo
        self._base_url = f"https://{registry}"
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self._token}",
        })

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    def list_tags(self, image_name: str) -> list[str]:
        """
        List available tags for an image in the Artifactory Docker registry.

        Uses the Docker Registry V2 API exposed by Artifactory.
        """
        url = f"{self._base_url}/v2/{self._repo}/{image_name}/tags/list"
        try:
            resp = self._session.get(url)
            resp.raise_for_status()
            data = resp.json()
            return data.get("tags", [])
        except requests.HTTPError as exc:
            logger.error(f"Artifactory tag listing failed for {image_name}: {exc}")
            return []

    def tag_exists(self, image_name: str, tag: str) -> bool:
        """Check if a specific tag exists in the internal Artifactory."""
        tags = self.list_tags(image_name)
        return tag in tags

    def find_latest_patched_tag(
        self,
        image_name: str,
        current_tag: str,
        desired_tag: Optional[str] = None,
    ) -> Optional[str]:
        """
        Find the best available tag in Artifactory for a base image update.

        If `desired_tag` is specified, check if it exists. Otherwise, attempt
        to find the latest tag in the same minor version series.
        """
        if desired_tag:
            if self.tag_exists(image_name, desired_tag):
                return desired_tag
            logger.warning(
                f"Desired tag {image_name}:{desired_tag} not found in Artifactory"
            )
            return None

        tags = self.list_tags(image_name)
        if not tags:
            return None

        # Simple heuristic: find tags that share the same major.minor prefix
        prefix = _version_prefix(current_tag)
        if not prefix:
            return None

        candidates = [t for t in tags if t.startswith(prefix) and t != current_tag]
        if not candidates:
            return None

        # Sort and return the latest (lexicographic — works for semver-ish tags)
        candidates.sort(reverse=True)
        return candidates[0]

    @staticmethod
    def parse_dockerfile_image(from_line: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Parse a Dockerfile FROM line into (registry, image_name, tag).

        Example:
            FROM isgedge.artifactory.cec.lab.emc.com/isgedge-docker-virtual/python:3.11-slim
            → ("isgedge.artifactory.cec.lab.emc.com/isgedge-docker-virtual", "python", "3.11-slim")
        """
        line = from_line.strip()
        if line.upper().startswith("FROM "):
            line = line[5:].strip()

        # Remove --platform=... or AS alias
        parts = line.split()
        image_ref = parts[0]
        for p in parts:
            if not p.startswith("--"):
                image_ref = p
                break

        # Split tag
        if ":" in image_ref:
            image_path, tag = image_ref.rsplit(":", 1)
        else:
            image_path, tag = image_ref, "latest"

        # Split registry/repo from image name
        segments = image_path.split("/")
        if len(segments) >= 3:
            # e.g. isgedge.artifactory.cec.lab.emc.com/isgedge-docker-virtual/python
            registry = "/".join(segments[:-1])
            image_name = segments[-1]
        elif len(segments) == 2:
            registry = segments[0]
            image_name = segments[1]
        else:
            registry = None
            image_name = segments[0]

        return registry, image_name, tag


def _version_prefix(tag: str) -> Optional[str]:
    """Extract a major.minor prefix from a tag like '3.11-slim' → '3.11'."""
    import re

    match = re.match(r"(\d+\.\d+)", tag)
    if match:
        return match.group(1)
    return None
