"""Configuration management — env vars, CLI args, and .security-remediation.yml parsing."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

from security_remediation.models import GitPlatform, Severity


class ScannersConfig(BaseModel):
    blackduck_enabled: bool = True
    blackduck_project_name: Optional[str] = None
    twistlock_enabled: bool = True
    twistlock_image_name: Optional[str] = None


class ArtifactoryConfig(BaseModel):
    registry: str = "isgedge.artifactory.cec.lab.emc.com/isgedge-docker-virtual"
    verify_tags: bool = True


class RemediationConfig(BaseModel):
    severity_threshold: Severity = Severity.HIGH
    max_fixes_per_pr: int = 20
    auto_merge: bool = False
    ignore_cves: list[str] = Field(default_factory=list)
    ignore_components: list[str] = Field(default_factory=list)


class ValidationConfig(BaseModel):
    run_build: bool = True
    run_tests: bool = True
    timeout_minutes: int = 30


class NotificationsConfig(BaseModel):
    slack_channel: Optional[str] = None
    email: Optional[str] = None


class AppConfig(BaseModel):
    """Top-level application configuration."""

    # --- Inputs ---
    repo_url: str
    repo_branch: str = "main"
    scanner: str = "all"  # "blackduck", "twistlock", or "all"
    dry_run: bool = False
    ai_model: str = "gpt-4o"

    # --- Detected ---
    git_platform: GitPlatform = GitPlatform.GITHUB

    # --- Sub-configs ---
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    artifactory: ArtifactoryConfig = Field(default_factory=ArtifactoryConfig)
    remediation: RemediationConfig = Field(default_factory=RemediationConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)

    # --- Secrets (loaded from env) ---
    blackduck_api_token: str = ""
    prisma_access_key: str = ""
    prisma_secret_key: str = ""
    github_token: str = ""
    eos2git_token: str = ""
    artifactory_token: str = ""
    openai_api_key: str = ""


EOS2GIT_HOST = "eos2git.cec.lab.emc.com"


def detect_git_platform(repo_url: str) -> GitPlatform:
    """Detect the git platform from the repo URL."""
    if EOS2GIT_HOST in repo_url:
        return GitPlatform.EOS2GIT
    return GitPlatform.GITHUB


def load_secrets() -> dict:
    """Load all secrets from environment variables."""
    return {
        "blackduck_api_token": os.environ.get("BLACKDUCK_API_TOKEN", ""),
        "prisma_access_key": os.environ.get("PRISMA_ACCESS_KEY", ""),
        "prisma_secret_key": os.environ.get("PRISMA_SECRET_KEY", ""),
        "github_token": os.environ.get("GITHUB_TOKEN", ""),
        "eos2git_token": os.environ.get("EOS2GIT_TOKEN", ""),
        "artifactory_token": os.environ.get("ARTIFACTORY_TOKEN", ""),
        "openai_api_key": os.environ.get("OPENAI_API_KEY", ""),
    }


def load_repo_config(repo_path: Path) -> dict:
    """Load .security-remediation.yml from the repo root if it exists."""
    config_file = repo_path / ".security-remediation.yml"
    if not config_file.exists():
        return {}
    with open(config_file, "r") as f:
        return yaml.safe_load(f) or {}


def build_config(
    repo_url: str,
    repo_branch: str = "main",
    scanner: str = "all",
    severity_threshold: str = "high",
    dry_run: bool = False,
    ai_model: str = "gpt-4o",
    repo_path: Optional[Path] = None,
) -> AppConfig:
    """Build the full AppConfig by merging CLI args, env vars, and repo config file."""
    secrets = load_secrets()
    git_platform = detect_git_platform(repo_url)

    # Start with defaults
    config_data = {
        "repo_url": repo_url,
        "repo_branch": repo_branch,
        "scanner": scanner,
        "dry_run": dry_run,
        "ai_model": ai_model,
        "git_platform": git_platform,
        "remediation": {"severity_threshold": severity_threshold},
        **secrets,
    }

    # Overlay repo-level config file if available
    if repo_path:
        repo_config = load_repo_config(repo_path)
        if repo_config:
            config_data = _merge_repo_config(config_data, repo_config)

    return AppConfig(**config_data)


def _merge_repo_config(base: dict, repo_cfg: dict) -> dict:
    """Merge repo-level .security-remediation.yml into the base config."""
    # Scanners
    scanners_cfg = repo_cfg.get("scanners", {})
    bd = scanners_cfg.get("blackduck", {})
    tw = scanners_cfg.get("twistlock", {})
    base.setdefault("scanners", {})
    if "enabled" in bd:
        base["scanners"]["blackduck_enabled"] = bd["enabled"]
    if "project_name" in bd:
        base["scanners"]["blackduck_project_name"] = bd["project_name"]
    if "enabled" in tw:
        base["scanners"]["twistlock_enabled"] = tw["enabled"]
    if "image_name" in tw:
        base["scanners"]["twistlock_image_name"] = tw["image_name"]

    # Artifactory
    art_cfg = repo_cfg.get("artifactory", {})
    if art_cfg:
        base.setdefault("artifactory", {})
        if "registry" in art_cfg:
            base["artifactory"]["registry"] = art_cfg["registry"]
        if "verify_tags" in art_cfg:
            base["artifactory"]["verify_tags"] = art_cfg["verify_tags"]

    # Remediation
    rem_cfg = repo_cfg.get("remediation", {})
    if rem_cfg:
        base.setdefault("remediation", {})
        for key in ("severity_threshold", "max_fixes_per_pr", "auto_merge", "ignore_cves", "ignore_components"):
            if key in rem_cfg:
                base["remediation"][key] = rem_cfg[key]

    # Validation
    val_cfg = repo_cfg.get("validation", {})
    if val_cfg:
        base.setdefault("validation", {})
        for key in ("run_build", "run_tests", "timeout_minutes"):
            if key in val_cfg:
                base["validation"][key] = val_cfg[key]

    # Notifications
    notif_cfg = repo_cfg.get("notifications", {})
    if notif_cfg:
        base.setdefault("notifications", {})
        for key in ("slack_channel", "email"):
            if key in notif_cfg:
                base["notifications"][key] = notif_cfg[key]

    return base
