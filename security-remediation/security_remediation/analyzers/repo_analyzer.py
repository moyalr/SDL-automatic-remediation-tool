"""Repository analyzer — detects tech stack, dependency files, and Dockerfile base images."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEPENDENCY_FILE_PATTERNS = {
    # Node.js
    "package.json": "nodejs",
    "package-lock.json": "nodejs",
    "yarn.lock": "nodejs",
    "pnpm-lock.yaml": "nodejs",
    # Python
    "requirements.txt": "python",
    "Pipfile": "python",
    "Pipfile.lock": "python",
    "pyproject.toml": "python",
    "poetry.lock": "python",
    "setup.py": "python",
    "setup.cfg": "python",
    # Java / JVM
    "pom.xml": "java",
    "build.gradle": "java",
    "build.gradle.kts": "java",
    # Go
    "go.mod": "go",
    "go.sum": "go",
    # Ruby
    "Gemfile": "ruby",
    "Gemfile.lock": "ruby",
    # .NET / C#
    "*.csproj": "dotnet",
    "packages.config": "dotnet",
    "Directory.Packages.props": "dotnet",
    # Container
    "Dockerfile": "docker",
    "docker-compose.yml": "docker",
    "docker-compose.yaml": "docker",
    # IaC
    "*.tf": "terraform",
}


@dataclass
class DockerBaseImage:
    """Represents a FROM directive in a Dockerfile."""

    file_path: str
    line_number: int
    full_line: str
    registry: Optional[str]
    image_name: str
    tag: str
    is_internal_artifactory: bool = False


@dataclass
class RepoAnalysis:
    """Results of analyzing a repository."""

    tech_stacks: set[str] = field(default_factory=set)
    dependency_files: dict[str, list[str]] = field(default_factory=dict)  # stack → [file_paths]
    dockerfiles: list[str] = field(default_factory=list)
    docker_base_images: list[DockerBaseImage] = field(default_factory=list)


class RepoAnalyzer:
    """Analyzes a cloned repository to detect tech stack and dependency structure."""

    def __init__(self, repo_path: Path, internal_registry: str = "isgedge.artifactory.cec.lab.emc.com"):
        self._repo_path = repo_path
        self._internal_registry = internal_registry

    def analyze(self) -> RepoAnalysis:
        """Run the full analysis."""
        result = RepoAnalysis()

        self._find_dependency_files(result)
        self._find_dockerfiles(result)
        self._parse_docker_base_images(result)

        logger.info(f"Detected tech stacks: {result.tech_stacks}")
        logger.info(f"Found {len(result.dockerfiles)} Dockerfile(s)")
        logger.info(f"Found {sum(len(v) for v in result.dependency_files.values())} dependency file(s)")

        return result

    def _find_dependency_files(self, result: RepoAnalysis) -> None:
        """Walk the repo and find known dependency files."""
        for path in self._repo_path.rglob("*"):
            if not path.is_file():
                continue
            # Skip common non-project directories
            rel = path.relative_to(self._repo_path)
            parts = rel.parts
            if any(p in (".git", "node_modules", "vendor", ".venv", "venv", "__pycache__") for p in parts):
                continue

            name = path.name
            for pattern, stack in DEPENDENCY_FILE_PATTERNS.items():
                if pattern.startswith("*"):
                    # Glob-style match on extension
                    if name.endswith(pattern[1:]):
                        result.tech_stacks.add(stack)
                        result.dependency_files.setdefault(stack, []).append(str(rel))
                elif name == pattern:
                    result.tech_stacks.add(stack)
                    result.dependency_files.setdefault(stack, []).append(str(rel))

    def _find_dockerfiles(self, result: RepoAnalysis) -> None:
        """Find all Dockerfiles in the repo."""
        for path in self._repo_path.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(self._repo_path)
            if ".git" in rel.parts:
                continue
            name = path.name
            if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
                result.dockerfiles.append(str(rel))
                if "docker" not in result.tech_stacks:
                    result.tech_stacks.add("docker")

    def _parse_docker_base_images(self, result: RepoAnalysis) -> None:
        """Parse FROM directives from all Dockerfiles."""
        for dockerfile_rel in result.dockerfiles:
            dockerfile_path = self._repo_path / dockerfile_rel
            try:
                lines = dockerfile_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception as exc:
                logger.warning(f"Could not read {dockerfile_rel}: {exc}")
                continue

            for line_num, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped.upper().startswith("FROM "):
                    continue
                # Skip ARG-based dynamic images that can't be statically resolved
                if "${" in stripped:
                    logger.debug(f"Skipping dynamic FROM in {dockerfile_rel}:{line_num}: {stripped}")
                    continue

                base_image = self._parse_from_line(stripped, dockerfile_rel, line_num)
                if base_image:
                    result.docker_base_images.append(base_image)

    def _parse_from_line(self, line: str, file_path: str, line_number: int) -> Optional[DockerBaseImage]:
        """Parse a single FROM line into a DockerBaseImage."""
        # FROM [--platform=...] image[:tag] [AS alias]
        parts = line[5:].strip().split()
        image_ref = None
        for p in parts:
            if p.startswith("--"):
                continue
            if p.upper() == "AS":
                break
            if image_ref is None:
                image_ref = p

        if not image_ref:
            return None

        # Split tag
        if ":" in image_ref:
            image_path, tag = image_ref.rsplit(":", 1)
        else:
            image_path, tag = image_ref, "latest"

        # Split registry from image name
        segments = image_path.split("/")
        if len(segments) >= 3:
            registry = "/".join(segments[:-1])
            image_name = segments[-1]
        elif len(segments) == 2:
            # Could be registry/image or org/image
            if "." in segments[0]:
                registry = segments[0]
                image_name = segments[1]
            else:
                registry = None
                image_name = image_path
        else:
            registry = None
            image_name = segments[0]

        is_internal = registry is not None and self._internal_registry in registry

        return DockerBaseImage(
            file_path=file_path,
            line_number=line_number,
            full_line=line,
            registry=registry,
            image_name=image_name,
            tag=tag,
            is_internal_artifactory=is_internal,
        )

    def get_file_content(self, rel_path: str) -> Optional[str]:
        """Read and return the contents of a file relative to the repo root."""
        full_path = self._repo_path / rel_path
        if not full_path.is_file():
            return None
        try:
            return full_path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            logger.warning(f"Could not read {rel_path}: {exc}")
            return None
