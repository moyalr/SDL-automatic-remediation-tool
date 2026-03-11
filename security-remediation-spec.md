# Security Vulnerability Auto-Remediation Job

## Overview

An automated script/job that integrates with Dell's security scanning tools, retrieves the latest vulnerability scan results for a given repository, analyzes them using AI, and raises a Pull Request with the necessary fixes — fully documented.

---

## Trigger

The job is triggered **on-demand** for a specific repository. It accepts the following inputs:

| Input | Required | Description |
|---|---|---|
| `repo_url` | Yes | Git clone URL of the target repository (GitHub.com or Dell internal GitHub) |
| `repo_branch` | No | Branch to remediate (default: `main`) |
| `scanner` | No | Which scanner(s) to query: `blackduck`, `twistlock`, or `all` (default: `all`) |
| `severity_threshold` | No | Minimum severity to remediate: `critical`, `high`, `medium`, `low` (default: `high`) |
| `dry_run` | No | If `true`, generates the analysis report without raising a PR (default: `false`) |
| `ai_model` | No | AI model to use for analysis and fix generation (default: configurable) |

---

## Git Platforms

The job supports repositories hosted on **two Git platforms**. The platform is auto-detected from the `repo_url` input.

| Platform | URL | API | PR Mechanism |
|---|---|---|---|
| **GitHub.com** | `https://github.com/` | GitHub REST / GraphQL API | GitHub Pull Request |
| **Dell Internal GitHub (EOS2Git)** | `https://eos2git.cec.lab.emc.com/` | GitHub Enterprise REST API | GitHub Enterprise Pull Request |

- The job must detect which platform hosts the repo and use the corresponding API endpoint and authentication token.
- PR creation, branch push, and comment posting all go through the platform-specific API.
- Both platforms use Git-compatible protocols; cloning uses the appropriate credentials for each.

---

## Internal Artifactory (Docker Base Images)

Many Dockerfiles in Dell repos pull base images from Dell's internal Artifactory rather than public registries:

- **Registry URL:** `isgedge.artifactory.cec.lab.emc.com/isgedge-docker-virtual`
- **Example Dockerfile line:**
  ```dockerfile
  FROM isgedge.artifactory.cec.lab.emc.com/isgedge-docker-virtual/python:3.11-slim
  ```

### Implications for Remediation

- When a vulnerability is found in a **Docker base image**, the job must check whether the image is pulled from the internal Artifactory or a public registry.
- **Internal Artifactory images:** The job queries Artifactory's API to determine which tags/versions are available before suggesting an image version bump. The fix must reference a tag that **exists in the internal registry** — not just on Docker Hub.
- **Tag availability check:** Before proposing a base image update in a Dockerfile, verify the target tag exists in the Artifactory repository via the Artifactory AQL or REST API.
- If the patched image version is **not available** in the internal Artifactory, the vulnerability is flagged for manual review with a note explaining the missing tag.

---

## Security Scanners

### BlackDuck

- **URL:** https://blackduck.sro.cec.delllabs.net/
- **Purpose:** Software Composition Analysis (SCA) — identifies known vulnerabilities in open-source and third-party dependencies.
- **Integration:** REST API ([Black Duck API docs](https://blackduck.sro.cec.delllabs.net/api-doc/public.html))
- **Key data retrieved:**
  - Vulnerable component name and version
  - CVE identifiers
  - CVSS score and severity
  - Recommended fix version (if available)
  - License risk information

### Twistlock (Prisma Cloud)

- **Console URL:** https://us-west1.cloud.twistlock.com/us-3-159266859
- **Dashboard URL:** https://app3.prismacloud.io/
- **Purpose:** Container and image vulnerability scanning, IaC misconfigurations, and runtime protection.
- **Integration:** `twistcli` CLI + Prisma Cloud Compute API
- **Key data retrieved:**
  - Vulnerable packages in container images
  - CVE identifiers
  - CVSS score and severity
  - Fix status and fixed-in version
  - Compliance issues

#### Existing Scan Workflow Reference

The team already has a **reusable GitHub Actions workflow** for Twistlock scanning. Key details:

- **Scanner CLI:** `twistcli` — downloaded at runtime from the Prisma Cloud console:
  ```
  https://us-west1.cloud.twistlock.com/us-3-159266859/api/v1/util/twistcli
  ```
- **Scan command:**
  ```bash
  ./twistcli images scan \
    --address https://us-west1.cloud.twistlock.com/us-3-159266859 \
    --user "$TWISTLOCK_ACCESS_KEY" \
    --password "$TWISTLOCK_SECRET_KEY" \
    --output-file scan-results.json \
    --details \
    "$IMAGE"
  ```
- **Scan output:** Results are written to `scan-results.json` and also uploaded to the Prisma Cloud console.
- **Image source:** Docker images are pulled from **AWS ECR**. The workflow authenticates to ECR via AWS OIDC (`arn:aws:iam::702886132326:role/cfy-developers-github-actions-role`).
- **Runner requirements:** Self-hosted runners with labels `can-run-docker` and `can-access-aws-network`.
- **Auth:** Uses `twistlock-access-key` and `twistlock-secret-key` secrets.
- **Timeout:** Configurable (default `60s`).

> **For the remediation job:** Instead of re-scanning, the job can retrieve the latest scan results from the Prisma Cloud Compute API (`/api/v1/images` or `/api/v1/scans` endpoints), or alternatively parse a previously generated `scan-results.json` artifact from the existing scan workflow.

---

## Job Workflow

### Step 1 — Resolve Repository in Scanners

1. Accept the `repo_url` input.
2. Query each enabled scanner's API to locate the **project/image** corresponding to the repository.
   - **BlackDuck:** Search projects by name or repository URL mapping.
   - **Twistlock:** Search images via Prisma Cloud Compute API (`/api/v1/images`) by image name/tag, or retrieve the `scan-results.json` artifact from the most recent Twistlock scan workflow run.
3. If the repository is not found in a scanner, log a warning and continue with the remaining scanner(s). If not found in any scanner, fail with a clear error.

### Step 2 — Retrieve Latest Scan Results

1. For each matched scanner project/image:
   - Fetch the **most recent completed scan** (by timestamp).
   - Export the full vulnerability report via API.
2. Normalize results into a unified vulnerability schema (see [Unified Schema](#unified-vulnerability-schema) below).
3. Filter vulnerabilities by `severity_threshold`.
4. Deduplicate entries that appear in multiple scanners (match by CVE ID + component).

### Step 3 — Clone & Analyze Repository

1. Detect the Git platform from `repo_url` (GitHub.com vs. Dell Internal GitHub at `eos2git.cec.lab.emc.com`).
2. Clone the target repository at the specified `repo_branch` using the platform-appropriate credentials.
3. Detect the project's tech stack and dependency management files:
   - `package.json` / `package-lock.json` / `yarn.lock` (Node.js)
   - `requirements.txt` / `Pipfile` / `pyproject.toml` / `poetry.lock` (Python)
   - `pom.xml` / `build.gradle` (Java)
   - `go.mod` / `go.sum` (Go)
   - `Dockerfile` / `docker-compose.yml` (Container)
   - `.tf` files (Terraform / IaC)
   - `Gemfile` / `Gemfile.lock` (Ruby)
   - `*.csproj` / `packages.config` (C# / .NET)
4. For Dockerfiles, identify base image sources:
   - **Public registries** (Docker Hub, ghcr.io, etc.)
   - **Dell internal Artifactory** (`isgedge.artifactory.cec.lab.emc.com/isgedge-docker-virtual`)
5. Map each vulnerability to the specific file(s) and dependency declaration(s) in the repo.

### Step 4 — AI-Powered Fix Generation

1. Send the following context to the AI model:
   - The unified vulnerability list (filtered & deduplicated).
   - The relevant dependency/config files from the repo.
   - For each vulnerability: the CVE description, current version, and recommended fix version (if known).
2. The AI determines the remediation for each vulnerability:
   - **Dependency version bump** — update the dependency to the minimum patched version.
   - **Dependency replacement** — if the dependency is deprecated/unmaintained, suggest an alternative.
   - **Docker base image update** — update the base image tag in the Dockerfile to a patched version. For internal Artifactory images, verify tag availability before proposing.
   - **Configuration change** — fix IaC misconfigurations or Dockerfile best-practice issues.
   - **Code change** — if the vulnerability requires a code-level fix (e.g., insecure API usage).
   - **No fix available** — flag the vulnerability as requiring manual review (includes cases where a patched image is not yet in the internal Artifactory).
3. For each fix, the AI generates:
   - The exact file diff (what to change).
   - A human-readable explanation of the fix.
   - A confidence score (`high` / `medium` / `low`).
   - Any potential breaking-change warnings.
4. The AI validates that version bumps are compatible (no major version conflicts, peer dependency issues, etc.).

### Step 5 — Apply Changes & Run Validation

1. Create a new branch from the target branch: `security/auto-remediate-<timestamp>`.
2. Apply all generated fixes to the repository files.
3. Run validation checks:
   - **Dependency resolution:** Run the appropriate install/build command to verify no dependency conflicts.
   - **Lock file regeneration:** Regenerate lock files if dependency versions changed.
   - **Build check:** If a build script exists, run it to ensure the project still builds.
   - **Test suite:** If tests exist and are configured, run them to catch regressions.
4. If validation fails for a specific fix:
   - Roll back that individual fix.
   - Flag it in the report as "failed validation — manual review required."
   - Continue with remaining fixes.

### Step 6 — Raise Pull Request

1. Commit all successful changes with a structured commit message:
   ```
   fix(security): auto-remediate <N> vulnerabilities

   Scanner sources: BlackDuck, Twistlock
   Severities addressed: critical, high
   ```
2. Push the branch and create a Pull Request against the target branch using the appropriate platform API (GitHub.com or Dell Internal GitHub).
3. PR title format: `[Security Auto-Remediation] Fix <N> vulnerabilities (<date>)`
4. PR body contains:
   - Summary table of all addressed vulnerabilities.
   - Summary table of vulnerabilities that could **not** be fixed automatically.
   - Link to the scanner reports.

### Step 7 — Document Fixes in PR Comment

Post a detailed PR comment with the following structure:

```markdown
## Security Auto-Remediation Report

### Scanner Sources
- **BlackDuck:** <project_name> — scan date: <date>
- **Twistlock:** <image_name> — scan date: <date>

### Fixes Applied (<N> total)

| # | CVE | Component | Severity | Fix | Confidence | Breaking Risk |
|---|-----|-----------|----------|-----|------------|---------------|
| 1 | CVE-2025-XXXXX | lodash@4.17.20 | Critical | Bump to 4.17.21 | High | None |
| 2 | CVE-2025-YYYYY | express@4.17.1 | High | Bump to 4.18.2 | Medium | Minor API changes |

### Detailed Explanations

#### 1. CVE-2025-XXXXX — lodash@4.17.20
**Vulnerability:** Prototype pollution in `lodash.merge`
**Fix:** Updated `lodash` from `4.17.20` → `4.17.21` in `package.json`
**Explanation:** Version 4.17.21 patches the prototype pollution vector...

### Vulnerabilities Requiring Manual Review (<M> total)

| # | CVE | Component | Severity | Reason |
|---|-----|-----------|----------|--------|
| 1 | CVE-2025-ZZZZZ | internal-lib@1.0.0 | High | No patched version available |

### Validation Results
- ✅ Dependency resolution passed
- ✅ Build succeeded
- ✅ Test suite passed (142/142)
```

---

## Unified Vulnerability Schema

All scan results are normalized into the following structure before AI analysis:

```json
{
  "id": "unique-finding-id",
  "cve": "CVE-2025-XXXXX",
  "source": "blackduck | twistlock",
  "component": "package-name",
  "current_version": "1.2.3",
  "fixed_version": "1.2.4",
  "severity": "critical | high | medium | low",
  "cvss_score": 9.8,
  "description": "Short description of the vulnerability",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-XXXXX"],
  "file_path": "path/to/dependency/file",
  "scanner_metadata": {}
}
```

---

## Authentication & Secrets

| Secret | Purpose |
|---|---|
| `BLACKDUCK_API_TOKEN` | Authenticate against the BlackDuck REST API |
| `PRISMA_ACCESS_KEY` | Prisma Cloud access key ID |
| `PRISMA_SECRET_KEY` | Prisma Cloud secret key |
| `GITHUB_TOKEN` | GitHub.com personal access token (or service account) with repo write + PR creation permissions |
| `EOS2GIT_TOKEN` | Dell Internal GitHub (EOS2Git) token with repo write + PR creation permissions |
| `ARTIFACTORY_TOKEN` | Dell internal Artifactory token for querying available Docker image tags |
| `AI_API_KEY` | API key for the AI model service |

All secrets must be stored in a secure vault (e.g., Jenkins credentials, GitHub Actions secrets, HashiCorp Vault). **Never hardcode secrets.**

---

## Configuration File

The job can be configured via a `.security-remediation.yml` file at the repository root (optional overrides):

```yaml
git:
  platform: auto                       # auto | github | eos2git (auto-detected from repo_url)

artifactory:
  registry: "isgedge.artifactory.cec.lab.emc.com/isgedge-docker-virtual"
  verify_tags: true                    # Check tag availability before proposing Dockerfile fixes

scanners:
  blackduck:
    enabled: true
    project_name: "my-project"        # Override auto-detection
  twistlock:
    enabled: true
    image_name: "registry/my-image"   # Override auto-detection

remediation:
  severity_threshold: high             # Minimum severity to fix
  max_fixes_per_pr: 20                 # Limit fixes per PR to keep reviews manageable
  auto_merge: false                    # If true, auto-merge PR when all checks pass
  ignore_cves:                         # CVEs to skip (e.g., accepted risk)
    - CVE-2024-99999
  ignore_components:                   # Components to skip
    - legacy-internal-lib

validation:
  run_build: true
  run_tests: true
  timeout_minutes: 30

notifications:
  slack_channel: "#security-alerts"
  email: "team@dell.com"
```

---

## Error Handling & Logging

- **All API calls** include retry logic with exponential backoff (max 3 retries).
- **Scanner unreachable:** Log error, skip that scanner, continue with others if available.
- **No vulnerabilities found:** Exit successfully with a "clean" status message; no PR is created.
- **AI failure:** Log the error, output the raw vulnerability list for manual review, and exit with a non-zero code.
- **PR creation failure:** Log the error with the branch name so the changes can be recovered.
- Full structured logs (JSON) are emitted for integration with centralized logging (e.g., Splunk, ELK).

---

## Deployment Options

The job can be deployed as:

1. **Jenkins Pipeline** — triggered manually or via webhook.
2. **GitHub Actions Workflow** — triggered via `workflow_dispatch` or on a cron schedule.
3. **GitLab CI Job** — triggered manually or via API.
4. **Standalone CLI Script** — run from any CI/CD system or developer machine.

---

## Future Enhancements

- **Scheduled runs:** Cron-based trigger to remediate on a regular cadence (e.g., weekly).
- **Multi-repo batch mode:** Trigger remediation across multiple repositories in one run.
- **Auto-merge:** Automatically merge the PR if all CI checks pass and confidence is high.
- **JIRA integration:** Automatically create JIRA tickets for vulnerabilities requiring manual review.
- **Feedback loop:** Track which AI-generated fixes were accepted/rejected to improve future accuracy.
- **Additional scanners:** Support for Snyk, Checkmarx, SonarQube, etc.
- **SBOM generation:** Generate/update Software Bill of Materials alongside remediation.
