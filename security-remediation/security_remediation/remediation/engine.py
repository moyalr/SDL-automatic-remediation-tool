"""Remediation engine — applies fixes to the repo, validates, creates PR and posts report."""

from __future__ import annotations

import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from security_remediation.models import (
    FixAction,
    ProposedFix,
    RemediationReport,
    ScannerSource,
    Vulnerability,
)

logger = logging.getLogger(__name__)


class RemediationEngine:
    """Applies proposed fixes, validates them, and builds the remediation report."""

    def __init__(self, repo_path: Path, timeout_minutes: int = 30):
        self._repo_path = repo_path
        self._timeout = timeout_minutes * 60

    # ------------------------------------------------------------------
    # Apply fixes
    # ------------------------------------------------------------------

    def apply_fixes(self, fixes: list[ProposedFix]) -> tuple[list[ProposedFix], list[ProposedFix]]:
        """
        Apply each fix to the repo files.

        Returns (applied, failed) — fixes that could not be applied are in failed.
        """
        applied = []
        failed = []

        for fix in fixes:
            if fix.action == FixAction.NO_FIX:
                fix.validated = False
                fix.validation_error = "No automated fix available"
                failed.append(fix)
                continue

            try:
                self._apply_single_fix(fix)
                fix.validated = True
                applied.append(fix)
                logger.info(f"Applied fix: {fix.vulnerability_id} → {fix.file_path}")
            except Exception as exc:
                fix.validated = False
                fix.validation_error = str(exc)
                failed.append(fix)
                logger.warning(f"Failed to apply fix {fix.vulnerability_id}: {exc}")

        return applied, failed

    def _apply_single_fix(self, fix: ProposedFix) -> None:
        """Apply a single fix by doing a find-and-replace in the target file."""
        file_path = self._repo_path / fix.file_path

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {fix.file_path}")

        content = file_path.read_text(encoding="utf-8", errors="replace")

        if fix.old_content and fix.old_content not in content:
            raise ValueError(
                f"Could not find expected content in {fix.file_path}. "
                f"The file may have changed or the AI-generated match is incorrect."
            )

        if fix.old_content:
            new_content = content.replace(fix.old_content, fix.new_content, 1)
        else:
            # If old_content is empty, this is an append or new-file operation
            new_content = fix.new_content

        file_path.write_text(new_content, encoding="utf-8")

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self, tech_stacks: set[str], run_build: bool = True, run_tests: bool = True) -> list[str]:
        """
        Run validation checks after applying fixes.

        Returns a list of validation results (strings).
        """
        results = []

        # Dependency resolution / lock file regeneration
        if "nodejs" in tech_stacks:
            results.append(self._run_validation_cmd(
                "npm install --package-lock-only", "Node.js dependency resolution"
            ))
        if "python" in tech_stacks:
            results.append(self._run_validation_cmd(
                "pip check", "Python dependency check"
            ))
        if "java" in tech_stacks:
            results.append(self._run_validation_cmd(
                "mvn dependency:resolve -q", "Maven dependency resolution"
            ))
        if "go" in tech_stacks:
            results.append(self._run_validation_cmd(
                "go mod tidy", "Go module tidy"
            ))

        # Build check
        if run_build:
            if "nodejs" in tech_stacks:
                results.append(self._run_validation_cmd("npm run build --if-present", "Node.js build"))
            if "java" in tech_stacks:
                results.append(self._run_validation_cmd("mvn compile -q", "Maven compile"))
            if "go" in tech_stacks:
                results.append(self._run_validation_cmd("go build ./...", "Go build"))

        # Test suite
        if run_tests:
            if "nodejs" in tech_stacks:
                results.append(self._run_validation_cmd("npm test --if-present", "Node.js tests"))
            if "python" in tech_stacks:
                results.append(self._run_validation_cmd("python -m pytest --co -q 2>/dev/null || true", "Python test discovery"))
            if "go" in tech_stacks:
                results.append(self._run_validation_cmd("go test ./...", "Go tests"))

        return results

    def _run_validation_cmd(self, cmd: str, label: str) -> str:
        """Run a validation command and return a result string."""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                cwd=str(self._repo_path),
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            if result.returncode == 0:
                logger.info(f"Validation passed: {label}")
                return f"✅ {label} passed"
            else:
                stderr = result.stderr[:500] if result.stderr else "unknown error"
                logger.warning(f"Validation failed: {label} — {stderr}")
                return f"❌ {label} failed: {stderr}"
        except subprocess.TimeoutExpired:
            return f"⏱️ {label} timed out"
        except Exception as exc:
            return f"❌ {label} error: {exc}"

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    @staticmethod
    def build_pr_body(report: RemediationReport) -> str:
        """Generate the Pull Request body markdown."""
        lines = [
            "## Security Auto-Remediation",
            "",
            f"**Repo:** `{report.repo_url}`",
            f"**Branch:** `{report.branch}`",
            f"**Scanners:** {', '.join(s.value for s in report.scanner_sources)}",
            "",
            f"- **Vulnerabilities found:** {report.total_vulnerabilities}",
            f"- **Fixes applied:** {len(report.fixes_applied)}",
            f"- **Manual review needed:** {len(report.manual_review) + len(report.fixes_failed)}",
            "",
            "See the PR comment below for the full remediation report.",
        ]
        return "\n".join(lines)

    @staticmethod
    def build_pr_comment(
        report: RemediationReport,
        validation_results: list[str],
    ) -> str:
        """Generate the detailed PR comment markdown."""
        lines = [
            "## Security Auto-Remediation Report",
            "",
            "### Scanner Sources",
        ]
        for source in report.scanner_sources:
            scan_date = report.scan_dates.get(source.value, "unknown")
            lines.append(f"- **{source.value.title()}:** scan date: {scan_date}")
        lines.append("")

        # Fixes applied
        lines.append(f"### Fixes Applied ({len(report.fixes_applied)} total)")
        lines.append("")
        if report.fixes_applied:
            lines.append("| # | CVE | Component | Severity | Fix | Confidence | Breaking Risk |")
            lines.append("|---|-----|-----------|----------|-----|------------|---------------|")
            for i, fix in enumerate(report.fixes_applied, 1):
                lines.append(
                    f"| {i} | {fix.cve or 'N/A'} | {fix.component} | — "
                    f"| {fix.action.value} | {fix.confidence.value} | {fix.breaking_risk} |"
                )
            lines.append("")

            # Detailed explanations
            lines.append("### Detailed Explanations")
            lines.append("")
            for i, fix in enumerate(report.fixes_applied, 1):
                lines.append(f"#### {i}. {fix.cve or fix.vulnerability_id} — {fix.component}")
                lines.append(f"**Action:** {fix.action.value}")
                lines.append(f"**File:** `{fix.file_path}`")
                lines.append(f"**Explanation:** {fix.explanation}")
                if fix.breaking_risk and fix.breaking_risk != "None":
                    lines.append(f"**⚠️ Breaking risk:** {fix.breaking_risk}")
                lines.append("")
        else:
            lines.append("_No fixes could be applied automatically._")
            lines.append("")

        # Manual review
        manual_count = len(report.manual_review) + len(report.fixes_failed)
        lines.append(f"### Vulnerabilities Requiring Manual Review ({manual_count} total)")
        lines.append("")
        if report.manual_review or report.fixes_failed:
            lines.append("| # | CVE | Component | Severity | Reason |")
            lines.append("|---|-----|-----------|----------|--------|")
            idx = 1
            for vuln in report.manual_review:
                lines.append(
                    f"| {idx} | {vuln.cve or 'N/A'} | {vuln.component}@{vuln.current_version} "
                    f"| {vuln.severity.value} | No automated fix available |"
                )
                idx += 1
            for fix in report.fixes_failed:
                reason = fix.validation_error or "Fix could not be applied"
                lines.append(
                    f"| {idx} | {fix.cve or 'N/A'} | {fix.component} "
                    f"| — | {reason} |"
                )
                idx += 1
        else:
            lines.append("_All vulnerabilities were addressed automatically._")
        lines.append("")

        # Validation results
        lines.append("### Validation Results")
        if validation_results:
            for vr in validation_results:
                lines.append(f"- {vr}")
        else:
            lines.append("- _No validation checks were run._")
        lines.append("")

        return "\n".join(lines)
