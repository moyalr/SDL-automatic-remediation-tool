# Security Vulnerability Auto-Remediation Tool

Automated tool that integrates with Dell's security scanners (BlackDuck & Twistlock/Prisma Cloud), retrieves vulnerability scan results, analyzes them with AI (OpenAI GPT-4o), and raises a Pull Request with fixes — fully documented.

## Quick Start

### 1. Install

```bash
pip install -r requirements.txt
```

### 2. Set Environment Variables

```bash
# Scanner credentials
export BLACKDUCK_API_TOKEN="your-blackduck-token"
export PRISMA_ACCESS_KEY="your-prisma-access-key"
export PRISMA_SECRET_KEY="your-prisma-secret-key"

# Git platform tokens (set the one matching your repo host)
export GITHUB_TOKEN="your-github-token"            # For github.com repos
export EOS2GIT_TOKEN="your-eos2git-token"          # For eos2git.cec.lab.emc.com repos

# Artifactory (for Docker base image tag verification)
export ARTIFACTORY_TOKEN="your-artifactory-token"

# AI
export OPENAI_API_KEY="your-openai-api-key"
```

### 3. Run

```bash
# Remediate a GitHub.com repo (all scanners, severity >= high)
python -m security_remediation.main --repo-url https://github.com/my-org/my-repo

# Remediate a Dell internal repo
python -m security_remediation.main --repo-url https://eos2git.cec.lab.emc.com/my-org/my-repo

# Only Twistlock, critical-only, dry run
python -m security_remediation.main \
  --repo-url https://github.com/my-org/my-repo \
  --scanner twistlock \
  --severity-threshold critical \
  --dry-run

# Use a local scan-results.json instead of querying Twistlock API
python -m security_remediation.main \
  --repo-url https://github.com/my-org/my-repo \
  --scanner twistlock \
  --scan-results-json ./scan-results.json

# Specify branch and AI model
python -m security_remediation.main \
  --repo-url https://github.com/my-org/my-repo \
  --repo-branch develop \
  --ai-model gpt-4o \
  --verbose
```

## CLI Options

| Option | Default | Description |
|---|---|---|
| `--repo-url` | *(required)* | Git clone URL (GitHub.com or EOS2Git) |
| `--repo-branch` | `main` | Branch to remediate |
| `--scanner` | `all` | `blackduck`, `twistlock`, or `all` |
| `--severity-threshold` | `high` | Minimum severity: `critical`, `high`, `medium`, `low` |
| `--dry-run` | `false` | Generate report without creating PR |
| `--ai-model` | `gpt-4o` | OpenAI model to use |
| `--scan-results-json` | — | Path to Twistlock scan-results.json (skip API) |
| `--verbose` | `false` | Enable debug logging |

## Repo-Level Config

Place a `.security-remediation.yml` in the repo root to override defaults:

```yaml
git:
  platform: auto                       # auto | github | eos2git

artifactory:
  registry: "isgedge.artifactory.cec.lab.emc.com/isgedge-docker-virtual"
  verify_tags: true

scanners:
  blackduck:
    enabled: true
    project_name: "my-project"
  twistlock:
    enabled: true
    image_name: "registry/my-image"

remediation:
  severity_threshold: high
  max_fixes_per_pr: 20
  auto_merge: false
  ignore_cves:
    - CVE-2024-99999
  ignore_components:
    - legacy-internal-lib

validation:
  run_build: true
  run_tests: true
  timeout_minutes: 30
```

## Architecture

```
security_remediation/
├── main.py                 # CLI entrypoint & orchestration
├── config.py               # Configuration (env vars, YAML, CLI args)
├── models.py               # Data models (Vulnerability, ProposedFix, etc.)
├── artifactory.py          # Dell Artifactory Docker tag verification
├── scanners/
│   ├── base.py             # Base scanner interface
│   ├── blackduck.py        # BlackDuck SCA client
│   └── twistlock.py        # Twistlock / Prisma Cloud client
├── git_platform/
│   └── github.py           # GitHub.com + EOS2Git (clone, branch, PR)
├── analyzers/
│   ├── repo_analyzer.py    # Tech stack & dependency file detection
│   └── ai_analyzer.py      # OpenAI-powered fix generation
└── remediation/
    └── engine.py           # Apply fixes, validate, build PR report
```

## Workflow

1. **Retrieve scan results** from BlackDuck and/or Twistlock
2. **Filter & deduplicate** by severity threshold and ignore lists
3. **Clone the repo**, detect tech stack and dependency files
4. **AI analysis** — OpenAI generates exact file diffs to fix each vulnerability
5. **Apply fixes** and run validation (build, tests)
6. **Create a PR** with all changes
7. **Post a detailed comment** documenting every fix with explanations

## Git Platforms

| Platform | Auto-detected by URL |
|---|---|
| GitHub.com | `github.com` in URL |
| Dell Internal GitHub (EOS2Git) | `eos2git.cec.lab.emc.com` in URL |

## Docker Base Image Handling

When a Dockerfile uses an image from Dell's internal Artifactory (`isgedge.artifactory.cec.lab.emc.com/isgedge-docker-virtual`), the tool:

1. Queries the Artifactory API for available tags
2. Only proposes base image updates to tags that **exist** in the internal registry
3. Flags the vulnerability for manual review if the patched tag is not available
