"""AI-powered vulnerability analysis and fix generation using Dell GenAI Gateway (OpenAI-compatible)."""

from __future__ import annotations

import json
import logging
import os
from typing import Optional

import httpx
import certifi
from openai import OpenAI

from security_remediation.models import (
    Confidence,
    FixAction,
    ProposedFix,
    Vulnerability,
)

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a security remediation assistant. You analyze software vulnerabilities found by \
security scanners (BlackDuck, Twistlock/Prisma Cloud) and generate precise fixes.

Your job:
1. Analyze each vulnerability against the repository's dependency and configuration files.
2. Determine the best remediation action for each vulnerability.
3. Generate exact file changes (old content → new content) to apply the fix.

Rules:
- For dependency version bumps, update to the MINIMUM version that fixes the vulnerability \
(prefer patch-level bumps over major version jumps).
- For Docker base image updates, propose the patched tag. If the image comes from an internal \
Artifactory registry, you MUST only propose tags confirmed to exist in that registry.
- Never remove a dependency unless it is clearly unused and deprecated.
- If no automated fix is possible, set action to "no_fix" and explain why.
- Be conservative: prefer high-confidence, low-risk fixes.
- Always explain the fix clearly for human reviewers.

Output format: Return a JSON array of fix objects. Each fix object has:
{
  "vulnerability_id": "string",
  "cve": "string or null",
  "component": "string",
  "action": "version_bump | dependency_replacement | docker_image_update | config_change | code_change | no_fix",
  "file_path": "relative path to file",
  "old_content": "exact text to find and replace",
  "new_content": "replacement text",
  "explanation": "human-readable explanation",
  "confidence": "high | medium | low",
  "breaking_risk": "description of potential breaking changes or 'None'"
}

Return ONLY the JSON array, no markdown fences, no extra text.
"""


class AIAnalyzer:
    """Uses Dell GenAI Gateway (OpenAI-compatible) or public OpenAI to analyze vulnerabilities and generate fix proposals."""

    def __init__(
        self,
        api_key: str = "",  # For public OpenAI fallback
        model: str = "gpt-oss-120b",
        base_url: str = "https://aia.gateway.dell.com/genai/dev/v1",
    ):
        self._model = model
        self._base_url = base_url

        # Try Dell GenAI Gateway first, fall back to public OpenAI
        try:
            self._client = self._create_dell_client()
            self._using_dell = True
            logger.info("Using Dell GenAI Gateway")
        except Exception as exc:
            logger.warning(f"Dell GenAI Gateway not available: {exc}")
            if not api_key:
                raise ValueError("OpenAI API key required when Dell GenAI Gateway is unavailable")
            self._client = OpenAI(api_key=api_key)
            self._using_dell = False
            self._model = "gpt-4o"  # Use public OpenAI model
            logger.info("Using public OpenAI API")

    def _create_dell_client(self) -> OpenAI:
        """Create OpenAI client pointed at Dell GenAI Gateway with Dell auth."""
        try:
            # Try to import from local authentication_provider first
            import sys
            import os
            auth_path = os.path.join(os.path.dirname(__file__), "..", "..", "authentication_provider.py")
            if os.path.exists(auth_path):
                sys.path.insert(0, os.path.dirname(auth_path))
                import authentication_provider
            else:
                # Fall back to installed package
                import authentication_provider
                
            import uuid
        except ImportError as exc:
            logger.error(f"Dell authentication package not available: {exc}")
            logger.error("Please install aia-auth-client from Dell Artifactory")
            raise

        # Add Dell certificates (same as notebook)
        self._update_certifi()

        # Set up HTTP client with Dell certificates
        timeout = httpx.Timeout(30.0, connect=10.0)
        http_client = httpx.Client(
            verify=certifi.where(),
            timeout=timeout,
        )

        # Set up headers with Dell auth
        auth = authentication_provider.AuthenticationProvider()
        headers = {
            "x-correlation-id": str(uuid.uuid4()),
            "accept": "*/*",
            "Content-Type": "application/json",
            "Authorization": "Bearer " + auth.generate_auth_token(),
        }

        return OpenAI(
            base_url=self._base_url,
            http_client=http_client,
            api_key="",  # Handled by authentication_provider
            default_headers=headers,
        )

    def _update_certifi(self):
        """Add Dell certificates to certifi bundle (same as notebook)."""
        import requests
        import zipfile
        import io
        
        try:
            # URL to download the Dell certificates zip file
            url = "https://pki.dell.com//Dell%20Technologies%20PKI%202018%20B64_PEM.zip"
            logger.info(f"Downloading Dell certificates zip from: {url}")
            response = requests.get(url)
            response.raise_for_status()
            logger.info(f"Downloaded certificate zip, size: {len(response.content)} bytes")

            # Determine the location of the certifi bundle
            cert_path = certifi.where()
            logger.info(f"Certifi bundle path: {cert_path}")

            # Define the names of the certificates within the zip file
            dell_root_cert_name = "Dell Technologies Root Certificate Authority 2018.pem"
            dell_issuing_cert_name = "Dell Technologies Issuing CA 101_new.pem"

            # Append the certificates directly from the zip archive in memory.
            logger.info("Appending Dell certificates to certifi bundle...")
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                # Read certificate contents directly from the zip file in memory
                root_cert_content = z.read(dell_root_cert_name).decode('utf-8')
                issuing_cert_content = z.read(dell_issuing_cert_name).decode('utf-8')

                # Append the certificates to the certifi bundle
                with open(cert_path, "a") as bundle:
                    bundle.write("\n")
                    bundle.write(root_cert_content)
                    bundle.write("\n")  # Ensure newline after first cert
                    bundle.write(issuing_cert_content)
                    bundle.write("\n")  # Ensure newline after second cert

            logger.info("Dell certificates successfully added to certifi bundle.")
        except Exception as e:
            logger.warning(f"Could not add Dell certificates: {e}")
            # Continue without Dell certs - might work if system already has them

    def generate_fixes(
        self,
        vulnerabilities: list[Vulnerability],
        dependency_files: dict[str, str],
        docker_base_images: Optional[list[dict]] = None,
        available_artifactory_tags: Optional[dict[str, list[str]]] = None,
    ) -> list[ProposedFix]:
        """
        Analyze vulnerabilities against repo files and generate fix proposals.

        Args:
            vulnerabilities: Normalized vulnerability list.
            dependency_files: Mapping of file_path → file_content for all dependency files.
            docker_base_images: List of parsed Dockerfile base image info.
            available_artifactory_tags: Mapping of image_name → [available_tags] from Artifactory.

        Returns:
            List of ProposedFix objects.
        """
        if not vulnerabilities:
            logger.info("No vulnerabilities to analyze")
            return []

        user_prompt = self._build_prompt(
            vulnerabilities, dependency_files, docker_base_images, available_artifactory_tags
        )

        logger.info(f"Sending {len(vulnerabilities)} vulnerabilities to AI for analysis...")

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=16000,
            )

            content = response.choices[0].message.content.strip()
            fixes = self._parse_response(content)
            logger.info(f"AI generated {len(fixes)} fix proposals")
            return fixes

        except Exception as exc:
            logger.error(f"AI analysis failed: {exc}")
            raise

    def _build_prompt(
        self,
        vulnerabilities: list[Vulnerability],
        dependency_files: dict[str, str],
        docker_base_images: Optional[list[dict]],
        available_artifactory_tags: Optional[dict[str, list[str]]],
    ) -> str:
        """Build the user prompt with all context for the AI."""
        sections = []

        # Vulnerabilities
        sections.append("## Vulnerabilities to Remediate\n")
        for v in vulnerabilities:
            sections.append(
                f"- **{v.id}** | CVE: {v.cve or 'N/A'} | Component: {v.component}@{v.current_version} "
                f"| Severity: {v.severity.value} | CVSS: {v.cvss_score or 'N/A'} "
                f"| Fixed in: {v.fixed_version or 'unknown'}\n"
                f"  Description: {v.description}\n"
            )

        # Dependency files
        sections.append("\n## Repository Dependency Files\n")
        for file_path, content in dependency_files.items():
            # Truncate very large files to avoid token limits
            truncated = content[:8000] if len(content) > 8000 else content
            sections.append(f"### File: `{file_path}`\n```\n{truncated}\n```\n")

        # Docker base images
        if docker_base_images:
            sections.append("\n## Dockerfile Base Images\n")
            for img in docker_base_images:
                sections.append(
                    f"- File: `{img['file_path']}` line {img['line_number']}: "
                    f"`{img['full_line']}` "
                    f"(internal_artifactory: {img['is_internal_artifactory']})\n"
                )

        # Available Artifactory tags
        if available_artifactory_tags:
            sections.append("\n## Available Tags in Internal Artifactory\n")
            for image_name, tags in available_artifactory_tags.items():
                tag_list = ", ".join(tags[:30])
                sections.append(f"- **{image_name}**: {tag_list}\n")

        return "\n".join(sections)

    def _parse_response(self, content: str) -> list[ProposedFix]:
        """Parse the AI response JSON into ProposedFix objects."""
        # Strip markdown fences if present
        if content.startswith("```"):
            lines = content.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            content = "\n".join(lines)

        try:
            raw_fixes = json.loads(content)
        except json.JSONDecodeError as exc:
            logger.error(f"Failed to parse AI response as JSON: {exc}")
            logger.debug(f"Raw response: {content[:2000]}")
            return []

        fixes = []
        for item in raw_fixes:
            try:
                fix = ProposedFix(
                    vulnerability_id=item["vulnerability_id"],
                    cve=item.get("cve"),
                    component=item["component"],
                    action=FixAction(item["action"]),
                    file_path=item["file_path"],
                    old_content=item.get("old_content", ""),
                    new_content=item.get("new_content", ""),
                    explanation=item["explanation"],
                    confidence=Confidence(item.get("confidence", "medium")),
                    breaking_risk=item.get("breaking_risk", "None"),
                )
                fixes.append(fix)
            except Exception as exc:
                logger.warning(f"Failed to parse fix proposal: {exc} — item: {item}")

        return fixes
