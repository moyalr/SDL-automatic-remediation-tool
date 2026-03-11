"""Main CLI entrypoint — orchestrates the full security remediation workflow."""

from __future__ import annotations

import json
import logging
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import click

from security_remediation.analyzers.ai_analyzer import AIAnalyzer
from security_remediation.analyzers.repo_analyzer import RepoAnalyzer
from security_remediation.artifactory import ArtifactoryClient
from security_remediation.config import AppConfig, build_config, detect_git_platform
from security_remediation.git_platform.github import GitHubPlatform
from security_remediation.models import (
    FixAction,
    GitPlatform,
    RemediationReport,
    Severity,
    Vulnerability,
)
from security_remediation.remediation.engine import RemediationEngine
from security_remediation.scanners.blackduck import BlackDuckScanner
from security_remediation.scanners.twistlock import TwistlockScanner

logger = logging.getLogger("security_remediation")


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, stream=sys.stderr)


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------

@click.command()
@click.option("--repo-url", required=True, help="Git clone URL of the target repository")
@click.option("--repo-branch", default="main", help="Branch to remediate (default: main)")
@click.option("--scanner", default="all", type=click.Choice(["blackduck", "twistlock", "all"]),
              help="Scanner(s) to query")
@click.option("--severity-threshold", default="high",
              type=click.Choice(["critical", "high", "medium", "low"]),
              help="Minimum severity to remediate")
@click.option("--dry-run", is_flag=True, help="Generate report without creating a PR")
@click.option("--ai-model", default="gpt-4o", help="OpenAI model to use")
@click.option("--verbose", is_flag=True, help="Enable debug logging")
@click.option("--scan-results-json", default=None, type=click.Path(exists=True),
              help="Path to a Twistlock scan-results.json file (skip API query)")
def main(
    repo_url: str,
    repo_branch: str,
    scanner: str,
    severity_threshold: str,
    dry_run: bool,
    ai_model: str,
    verbose: bool,
    scan_results_json: str | None,
) -> None:
    """Security Vulnerability Auto-Remediation Tool.

    Fetches the latest scan results from BlackDuck and/or Twistlock,
    analyzes them with AI, and raises a PR with fixes.
    """
    setup_logging(verbose)
    logger.info("=" * 60)
    logger.info("Security Vulnerability Auto-Remediation — Starting")
    logger.info("=" * 60)

    # ---- Step 0: Build config ----
    config = build_config(
        repo_url=repo_url,
        repo_branch=repo_branch,
        scanner=scanner,
        severity_threshold=severity_threshold,
        dry_run=dry_run,
        ai_model=ai_model,
    )
    _validate_secrets(config)

    # ---- Step 1 & 2: Retrieve scan results ----
    logger.info("Step 1-2: Retrieving scan results from scanners...")
    all_vulns = _collect_vulnerabilities(config, scan_results_json)

    if not all_vulns:
        logger.info("No vulnerabilities found. Repository is clean!")
        sys.exit(0)

    # Filter by severity threshold
    threshold = Severity(severity_threshold)
    filtered = [v for v in all_vulns if v.severity >= threshold]
    logger.info(f"Total vulnerabilities: {len(all_vulns)}, after severity filter ({threshold.value}+): {len(filtered)}")

    # Filter out ignored CVEs / components
    filtered = _apply_ignore_lists(filtered, config)

    # Deduplicate across scanners
    filtered = _deduplicate(filtered)
    logger.info(f"After dedup & ignore: {len(filtered)} vulnerabilities to remediate")

    if not filtered:
        logger.info("No vulnerabilities remain after filtering. Nothing to do.")
        sys.exit(0)

    # ---- Step 3: Clone & analyze repo ----
    logger.info("Step 3: Cloning and analyzing repository...")
    git_platform = _create_git_platform(config)
    work_dir = Path(tempfile.mkdtemp(prefix="sec-remediate-"))

    try:
        repo_path = git_platform.clone_repo(repo_branch, work_dir)

        # Reload config with repo-level overrides
        config = build_config(
            repo_url=repo_url,
            repo_branch=repo_branch,
            scanner=scanner,
            severity_threshold=severity_threshold,
            dry_run=dry_run,
            ai_model=ai_model,
            repo_path=repo_path,
        )

        repo_analyzer = RepoAnalyzer(repo_path, config.artifactory.registry)
        analysis = repo_analyzer.analyze()

        # Gather dependency file contents for AI context
        dependency_contents = {}
        for stack, files in analysis.dependency_files.items():
            for f in files:
                content = repo_analyzer.get_file_content(f)
                if content:
                    dependency_contents[f] = content

        # Check Artifactory tags for internal Docker images
        artifactory_tags = {}
        if analysis.docker_base_images and config.artifactory.verify_tags and config.artifactory_token:
            logger.info("Checking internal Artifactory for available Docker tags...")
            art_client = ArtifactoryClient(
                token=config.artifactory_token,
                registry=config.artifactory.registry.split("/")[0],
                repo=config.artifactory.registry.split("/", 1)[1] if "/" in config.artifactory.registry else "",
            )
            for img in analysis.docker_base_images:
                if img.is_internal_artifactory:
                    tags = art_client.list_tags(img.image_name)
                    if tags:
                        artifactory_tags[img.image_name] = tags

        # ---- Step 4: AI-powered fix generation ----
        logger.info("Step 4: Generating fixes with AI...")
        ai = AIAnalyzer(api_key=config.openai_api_key, model=config.ai_model)

        docker_images_info = [
            {
                "file_path": img.file_path,
                "line_number": img.line_number,
                "full_line": img.full_line,
                "registry": img.registry,
                "image_name": img.image_name,
                "tag": img.tag,
                "is_internal_artifactory": img.is_internal_artifactory,
            }
            for img in analysis.docker_base_images
        ]

        proposed_fixes = ai.generate_fixes(
            vulnerabilities=filtered,
            dependency_files=dependency_contents,
            docker_base_images=docker_images_info if docker_images_info else None,
            available_artifactory_tags=artifactory_tags if artifactory_tags else None,
        )

        # Limit fixes per PR
        max_fixes = config.remediation.max_fixes_per_pr
        actionable = [f for f in proposed_fixes if f.action != FixAction.NO_FIX]
        no_fix = [f for f in proposed_fixes if f.action == FixAction.NO_FIX]

        if len(actionable) > max_fixes:
            logger.warning(f"Limiting to {max_fixes} fixes per PR (had {len(actionable)})")
            overflow = actionable[max_fixes:]
            actionable = actionable[:max_fixes]
            no_fix.extend(overflow)

        # ---- Step 5: Apply changes & validate ----
        logger.info("Step 5: Applying fixes and validating...")
        engine = RemediationEngine(repo_path, config.validation.timeout_minutes)
        applied, failed = engine.apply_fixes(actionable)

        validation_results = []
        if applied:
            validation_results = engine.validate(
                tech_stacks=analysis.tech_stacks,
                run_build=config.validation.run_build,
                run_tests=config.validation.run_tests,
            )

        # Identify vulnerabilities needing manual review
        manual_review_vulns = [
            v for v in filtered
            if v.id in {f.vulnerability_id for f in no_fix}
        ]

        # Build report
        report = RemediationReport(
            repo_url=repo_url,
            branch=repo_branch,
            scanner_sources=_active_sources(config),
            scan_dates={},  # Would be populated from scan metadata
            total_vulnerabilities=len(all_vulns),
            filtered_vulnerabilities=len(filtered),
            fixes_applied=applied,
            fixes_failed=failed + no_fix,
            manual_review=manual_review_vulns,
        )

        if dry_run:
            logger.info("DRY RUN — skipping PR creation")
            _print_dry_run_report(report, validation_results, engine)
            sys.exit(0)

        if not applied:
            logger.warning("No fixes were successfully applied. Skipping PR creation.")
            _print_dry_run_report(report, validation_results, engine)
            sys.exit(1)

        # ---- Step 6: Create PR ----
        logger.info("Step 6: Creating Pull Request...")
        branch_name = git_platform.generate_branch_name()
        git_platform.create_branch(repo_path, branch_name)

        commit_msg = (
            f"fix(security): auto-remediate {len(applied)} vulnerabilities\n\n"
            f"Scanner sources: {', '.join(s.value for s in report.scanner_sources)}\n"
            f"Severities addressed: {severity_threshold}+"
        )
        git_platform.commit_and_push(repo_path, branch_name, commit_msg)

        pr_title = git_platform.generate_pr_title(len(applied))
        pr_body = RemediationEngine.build_pr_body(report)
        pr_data = git_platform.create_pull_request(branch_name, repo_branch, pr_title, pr_body)

        report.pr_url = pr_data.get("html_url")
        report.pr_branch = branch_name

        # ---- Step 7: Post PR comment ----
        logger.info("Step 7: Posting remediation report as PR comment...")
        comment_body = RemediationEngine.build_pr_comment(report, validation_results)
        git_platform.add_pr_comment(pr_data["number"], comment_body)

        logger.info("=" * 60)
        logger.info(f"Done! PR created: {report.pr_url}")
        logger.info(f"  Fixes applied: {len(applied)}")
        logger.info(f"  Manual review: {len(report.manual_review) + len(failed)}")
        logger.info("=" * 60)

    finally:
        # Cleanup temp directory
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass


# ------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------

def _validate_secrets(config: AppConfig) -> None:
    """Validate that required secrets are present."""
    missing = []

    if config.scanner in ("blackduck", "all") and not config.blackduck_api_token:
        missing.append("BLACKDUCK_API_TOKEN")
    if config.scanner in ("twistlock", "all") and not config.prisma_access_key:
        missing.append("PRISMA_ACCESS_KEY")
    if config.scanner in ("twistlock", "all") and not config.prisma_secret_key:
        missing.append("PRISMA_SECRET_KEY")

    token_key = "EOS2GIT_TOKEN" if config.git_platform == GitPlatform.EOS2GIT else "GITHUB_TOKEN"
    token_val = config.eos2git_token if config.git_platform == GitPlatform.EOS2GIT else config.github_token
    if not token_val:
        missing.append(token_key)

    if not config.openai_api_key:
        missing.append("OPENAI_API_KEY")

    if missing:
        logger.error(f"Missing required environment variables: {', '.join(missing)}")
        sys.exit(1)


def _collect_vulnerabilities(
    config: AppConfig,
    scan_results_json: str | None,
) -> list[Vulnerability]:
    """Query enabled scanners and collect all vulnerabilities."""
    all_vulns: list[Vulnerability] = []

    # BlackDuck
    if config.scanner in ("blackduck", "all") and config.scanners.blackduck_enabled:
        try:
            bd = BlackDuckScanner(api_token=config.blackduck_api_token)
            vulns = bd.scan(config.repo_url, config.scanners.blackduck_project_name)
            all_vulns.extend(vulns)
            logger.info(f"BlackDuck: {len(vulns)} vulnerabilities")
        except Exception as exc:
            logger.error(f"BlackDuck scan retrieval failed: {exc}")

    # Twistlock
    if config.scanner in ("twistlock", "all") and config.scanners.twistlock_enabled:
        try:
            tw = TwistlockScanner(
                access_key=config.prisma_access_key,
                secret_key=config.prisma_secret_key,
            )
            if scan_results_json:
                vulns = tw.get_scan_results_from_json(scan_results_json)
                logger.info(f"Twistlock (from JSON): {len(vulns)} vulnerabilities")
            else:
                vulns = tw.scan(config.repo_url, config.scanners.twistlock_image_name)
                logger.info(f"Twistlock: {len(vulns)} vulnerabilities")
            all_vulns.extend(vulns)
        except Exception as exc:
            logger.error(f"Twistlock scan retrieval failed: {exc}")

    return all_vulns


def _apply_ignore_lists(vulns: list[Vulnerability], config: AppConfig) -> list[Vulnerability]:
    """Remove vulnerabilities matching the ignore lists."""
    ignore_cves = set(config.remediation.ignore_cves)
    ignore_components = set(config.remediation.ignore_components)

    return [
        v for v in vulns
        if v.cve not in ignore_cves and v.component not in ignore_components
    ]


def _deduplicate(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """Deduplicate vulnerabilities that appear in multiple scanners."""
    seen = {}
    for v in vulns:
        key = (v.cve or "", v.component, v.current_version or "")
        if key not in seen:
            seen[key] = v
        else:
            # Prefer the entry with more info (e.g., fixed_version)
            existing = seen[key]
            if not existing.fixed_version and v.fixed_version:
                seen[key] = v

    return list(seen.values())


def _create_git_platform(config: AppConfig) -> GitHubPlatform:
    """Create the appropriate GitHubPlatform instance."""
    token = (
        config.eos2git_token
        if config.git_platform == GitPlatform.EOS2GIT
        else config.github_token
    )
    return GitHubPlatform(
        platform=config.git_platform,
        token=token,
        repo_url=config.repo_url,
    )


def _active_sources(config: AppConfig) -> list:
    """Return the list of active scanner sources."""
    from security_remediation.models import ScannerSource

    sources = []
    if config.scanner in ("blackduck", "all"):
        sources.append(ScannerSource.BLACKDUCK)
    if config.scanner in ("twistlock", "all"):
        sources.append(ScannerSource.TWISTLOCK)
    return sources


def _print_dry_run_report(
    report: RemediationReport,
    validation_results: list[str],
    engine: RemediationEngine,
) -> None:
    """Print the report to stdout in dry-run mode."""
    comment = engine.build_pr_comment(report, validation_results)
    click.echo("\n" + "=" * 60)
    click.echo("DRY RUN REPORT")
    click.echo("=" * 60)
    click.echo(comment)


if __name__ == "__main__":
    main()
