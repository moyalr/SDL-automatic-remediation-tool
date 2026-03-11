"""
End-to-end test for the security remediation tool.

This test:
1. Creates a temporary local git repo with vulnerable dependencies
2. Parses a sample Twistlock scan-results.json
3. Analyzes the repo
4. Sends vulnerabilities to OpenAI for fix generation
5. Applies fixes and generates the PR report (dry-run, no actual PR)

Usage:
    python tests/test_e2e.py
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security_remediation.analyzers.ai_analyzer import AIAnalyzer
from security_remediation.analyzers.repo_analyzer import RepoAnalyzer
from security_remediation.models import Severity, Vulnerability
from security_remediation.remediation.engine import RemediationEngine, RemediationReport
from security_remediation.scanners.twistlock import TwistlockScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("test_e2e")

SAMPLE_PACKAGE_JSON = """{
  "name": "my-vulnerable-app",
  "version": "1.0.0",
  "description": "Sample app with vulnerable dependencies",
  "main": "index.js",
  "dependencies": {
    "express": "4.17.1",
    "lodash": "4.17.20",
    "ws": "7.5.9",
    "follow-redirects": "1.15.2",
    "axios": "1.4.0"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}
"""

SAMPLE_DOCKERFILE = """FROM isgedge.artifactory.cec.lab.emc.com/isgedge-docker-virtual/node:18.19-slim

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .

EXPOSE 3000
CMD ["node", "index.js"]
"""

SAMPLE_INDEX_JS = """const express = require('express');
const _ = require('lodash');
const app = express();

app.get('/', (req, res) => {
  res.send('Hello World');
});

app.listen(3000);
"""


def create_test_repo() -> Path:
    """Create a temporary git repo with vulnerable dependencies."""
    repo_dir = Path(tempfile.mkdtemp(prefix="test-vuln-repo-"))
    logger.info(f"Creating test repo at: {repo_dir}")

    # Write files
    (repo_dir / "package.json").write_text(SAMPLE_PACKAGE_JSON)
    (repo_dir / "Dockerfile").write_text(SAMPLE_DOCKERFILE)
    (repo_dir / "index.js").write_text(SAMPLE_INDEX_JS)

    # Init git repo
    subprocess.run(["git", "init"], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "add", "-A"], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=str(repo_dir), capture_output=True, check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=str(repo_dir), capture_output=True, check=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=str(repo_dir), capture_output=True, check=True,
    )

    return repo_dir


def main():
    print("=" * 60)
    print("Security Remediation Tool — E2E Test")
    print("=" * 60)

    # Check for Dell authentication or OpenAI API key
    import os
    api_key = os.environ.get("OPENAI_API_KEY", "")
    use_dell = False
    use_openai = False

    try:
        # Try to import from local authentication_provider first
        import sys
        # Go up from tests/ to security-remediation/ to project root
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        sys.path.insert(0, project_root)
        import authentication_provider
        auth = authentication_provider.AuthenticationProvider()
        use_dell = True
        print("✅ Dell authentication available")
    except Exception as exc:
        print(f"\n⚠️  Dell authentication not available: {exc}")

    if api_key:
        use_openai = True
        print("✅ OpenAI API key available")
    elif not use_dell:
        print("\n❌ Neither Dell authentication nor OpenAI API key available")
        print("Please set OPENAI_API_KEY to test AI fix generation")
        print("Will test everything except AI fix generation.")
        skip_ai = True
    else:
        skip_ai = False

    if not skip_ai:
        print(f"\n🤖 Will use: {'Dell GenAI Gateway' if use_dell else ''}{' + ' if use_dell and use_openai else ''}{'Public OpenAI' if use_openai else ''}")

    # Step 1: Create test repo
    print("\n--- Step 1: Create test repo ---")
    repo_dir = create_test_repo()
    print(f"✅ Test repo created at: {repo_dir}")

    try:
        # Step 2: Parse sample scan results
        print("\n--- Step 2: Parse Twistlock scan results ---")
        scan_json = Path(__file__).parent / "sample_scan_results.json"
        tw = TwistlockScanner(access_key="dummy", secret_key="dummy")
        vulns = tw.get_scan_results_from_json(str(scan_json))
        print(f"✅ Parsed {len(vulns)} vulnerabilities from scan results:")
        for v in vulns:
            print(f"   - {v.cve} | {v.component}@{v.current_version} | {v.severity.value} | fix: {v.fixed_version}")

        # Step 3: Analyze repo
        print("\n--- Step 3: Analyze repository ---")
        analyzer = RepoAnalyzer(repo_dir)
        analysis = analyzer.analyze()
        print(f"✅ Tech stacks detected: {analysis.tech_stacks}")
        print(f"   Dependency files: {analysis.dependency_files}")
        print(f"   Dockerfiles: {analysis.dockerfiles}")
        print(f"   Docker base images:")
        for img in analysis.docker_base_images:
            print(f"     - {img.file_path}:{img.line_number} → {img.image_name}:{img.tag} (internal: {img.is_internal_artifactory})")

        # Gather dependency file contents
        dep_contents = {}
        for stack, files in analysis.dependency_files.items():
            for f in files:
                content = analyzer.get_file_content(f)
                if content:
                    dep_contents[f] = content

        # Filter by severity
        threshold = Severity.HIGH
        filtered = [v for v in vulns if v.severity >= threshold]
        print(f"\n   Filtered to {len(filtered)} vulns at severity >= {threshold.value}")

        # Step 4: AI fix generation
        print("\n--- Step 4: AI-powered fix generation ---")
        if skip_ai:
            print("⏭️  Skipping AI step (no AI service available)")
            proposed_fixes = []
        else:
            ai = AIAnalyzer(api_key=api_key)  # Will try Dell first, then OpenAI
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
                dependency_files=dep_contents,
                docker_base_images=docker_images_info,
            )
            print(f"✅ AI generated {len(proposed_fixes)} fix proposals:")
            for fix in proposed_fixes:
                print(f"   - [{fix.action.value}] {fix.component} in {fix.file_path} ({fix.confidence.value} confidence)")
                print(f"     Explanation: {fix.explanation[:100]}...")

        # Step 5: Apply fixes and validate
        print("\n--- Step 5: Apply fixes ---")
        engine = RemediationEngine(repo_dir)
        if proposed_fixes:
            applied, failed = engine.apply_fixes(proposed_fixes)
            print(f"✅ Applied: {len(applied)}, Failed: {len(failed)}")

            for fix in applied:
                print(f"   ✅ {fix.vulnerability_id} → {fix.file_path}")
            for fix in failed:
                print(f"   ❌ {fix.vulnerability_id}: {fix.validation_error}")

            # Show the modified files
            print("\n   Modified package.json:")
            print("   " + (repo_dir / "package.json").read_text().replace("\n", "\n   "))
        else:
            applied, failed = [], []
            print("⏭️  No fixes to apply")

        # Step 6: Build report
        print("\n--- Step 6: Generate PR report ---")
        from security_remediation.models import ScannerSource
        report = RemediationReport(
            repo_url="https://github.com/test-org/my-vulnerable-app",
            branch="main",
            scanner_sources=[ScannerSource.TWISTLOCK],
            scan_dates={"twistlock": "2025-03-08"},
            total_vulnerabilities=len(vulns),
            filtered_vulnerabilities=len(filtered),
            fixes_applied=applied,
            fixes_failed=failed,
            manual_review=[v for v in filtered if v.id not in {f.vulnerability_id for f in applied}],
        )

        validation_results = ["✅ Dependency resolution passed (mock)"]
        comment = engine.build_pr_comment(report, validation_results)

        print("\n" + "=" * 60)
        print("GENERATED PR COMMENT (would be posted to PR):")
        print("=" * 60)
        print(comment)

    finally:
        # Cleanup
        shutil.rmtree(repo_dir, ignore_errors=True)
        print(f"\n🧹 Cleaned up test repo")

    print("\n" + "=" * 60)
    print("E2E TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
