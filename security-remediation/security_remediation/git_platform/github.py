"""Git platform client — handles both GitHub.com and Dell Internal GitHub (EOS2Git).

Both platforms speak the GitHub REST API, so we use a single class with
different base URLs and tokens depending on the detected platform.
"""

from __future__ import annotations

import logging
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from security_remediation.models import GitPlatform

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
EOS2GIT_API = "https://eos2git.cec.lab.emc.com/api/v3"


class GitHubPlatform:
    """Unified GitHub client for both GitHub.com and EOS2Git."""

    def __init__(
        self,
        platform: GitPlatform,
        token: str,
        repo_url: str,
    ):
        self.platform = platform
        self._token = token
        self._repo_url = repo_url
        self._api_base = EOS2GIT_API if platform == GitPlatform.EOS2GIT else GITHUB_API
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"token {self._token}",
            "Accept": "application/vnd.github.v3+json",
        })

        # Parse owner/repo from URL
        self.owner, self.repo = _parse_repo_url(repo_url)

    # ------------------------------------------------------------------
    # Clone
    # ------------------------------------------------------------------

    def clone_repo(self, branch: str, target_dir: Optional[Path] = None) -> Path:
        """Clone the repository to a local directory."""
        if target_dir is None:
            target_dir = Path(tempfile.mkdtemp(prefix="sec-remediate-"))

        clone_url = self._authenticated_clone_url()
        cmd = [
            "git", "clone",
            "--branch", branch,
            "--single-branch",
            "--depth", "50",
            clone_url,
            str(target_dir),
        ]
        logger.info(f"Cloning {self.owner}/{self.repo} (branch: {branch})")
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return target_dir

    def _authenticated_clone_url(self) -> str:
        """Build a clone URL with embedded token for HTTPS auth."""
        if self.platform == GitPlatform.EOS2GIT:
            return f"https://{self._token}@eos2git.cec.lab.emc.com/{self.owner}/{self.repo}.git"
        return f"https://{self._token}@github.com/{self.owner}/{self.repo}.git"

    # ------------------------------------------------------------------
    # Branch operations
    # ------------------------------------------------------------------

    def create_branch(self, repo_dir: Path, branch_name: str) -> str:
        """Create and checkout a new branch in the local repo."""
        subprocess.run(
            ["git", "checkout", "-b", branch_name],
            cwd=str(repo_dir), check=True, capture_output=True, text=True,
        )
        logger.info(f"Created branch: {branch_name}")
        return branch_name

    def commit_and_push(self, repo_dir: Path, branch_name: str, message: str) -> None:
        """Stage all changes, commit, and push."""
        subprocess.run(
            ["git", "add", "-A"],
            cwd=str(repo_dir), check=True, capture_output=True, text=True,
        )

        # Configure git user for the commit
        subprocess.run(
            ["git", "config", "user.email", "security-bot@dell.com"],
            cwd=str(repo_dir), check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Security Auto-Remediation Bot"],
            cwd=str(repo_dir), check=True, capture_output=True, text=True,
        )

        subprocess.run(
            ["git", "commit", "-m", message],
            cwd=str(repo_dir), check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["git", "push", "origin", branch_name],
            cwd=str(repo_dir), check=True, capture_output=True, text=True,
        )
        logger.info(f"Pushed branch {branch_name} to remote")

    # ------------------------------------------------------------------
    # Pull Request
    # ------------------------------------------------------------------

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    def create_pull_request(
        self,
        branch_name: str,
        base_branch: str,
        title: str,
        body: str,
    ) -> dict:
        """Create a Pull Request via the GitHub API."""
        url = f"{self._api_base}/repos/{self.owner}/{self.repo}/pulls"
        payload = {
            "title": title,
            "body": body,
            "head": branch_name,
            "base": base_branch,
        }
        resp = self._session.post(url, json=payload)
        resp.raise_for_status()
        pr_data = resp.json()
        logger.info(f"Pull request created: {pr_data.get('html_url')}")
        return pr_data

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    def add_pr_comment(self, pr_number: int, body: str) -> dict:
        """Post a comment on a Pull Request."""
        url = f"{self._api_base}/repos/{self.owner}/{self.repo}/issues/{pr_number}/comments"
        payload = {"body": body}
        resp = self._session.post(url, json=payload)
        resp.raise_for_status()
        logger.info(f"Comment posted on PR #{pr_number}")
        return resp.json()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def generate_branch_name(self) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"security/auto-remediate-{ts}"

    def generate_pr_title(self, fix_count: int) -> str:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return f"[Security Auto-Remediation] Fix {fix_count} vulnerabilities ({date_str})"


def _parse_repo_url(repo_url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a GitHub-style URL."""
    # HTTPS: https://github.com/owner/repo.git
    # SSH:   git@github.com:owner/repo.git
    patterns = [
        r"https?://[^/]+/([^/]+)/([^/\s]+?)(?:\.git)?/?$",
        r"git@[^:]+:([^/]+)/([^/\s]+?)(?:\.git)?/?$",
    ]
    for pattern in patterns:
        match = re.match(pattern, repo_url)
        if match:
            return match.group(1), match.group(2)

    raise ValueError(f"Cannot parse owner/repo from URL: {repo_url}")
