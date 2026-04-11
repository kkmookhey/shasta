"""Main code scanning engine for AI security issues.

Scans GitHub repositories (cloned or local) for AI-specific security
vulnerabilities and returns compliance findings.

Requires Semgrep: ``pip install semgrep``
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from shasta.evidence.models import Finding
from whitney.code.checks import PYTHON_ONLY_CHECKS
from whitney.code.semgrep_runner import run_semgrep, semgrep_available

logger = logging.getLogger(__name__)


class SemgrepNotInstalledError(RuntimeError):
    """Raised when Semgrep is not installed."""


def scan_repository(
    repo_path: str | Path,
    *,
    github_token: str | None = None,
    github_repo: str | None = None,  # "owner/repo" — clones if repo_path doesn't exist
) -> list[Finding]:
    """Scan a code repository for AI security issues.

    Uses Semgrep AST-based rules (48 rules) plus Python-only checks
    for patterns that require file-level context analysis.

    Args:
        repo_path: Local path to the repository (or where it should be cloned).
        github_token: GitHub personal access token for cloning private repos.
        github_repo: ``owner/repo`` string. If provided and *repo_path* does
            not exist the repo is cloned automatically.

    Returns:
        A list of :class:`Finding` objects, one per detected issue.

    Raises:
        SemgrepNotInstalledError: If Semgrep is not installed.
        FileNotFoundError: If the repo path does not exist.
    """
    repo_path = Path(repo_path)

    # Clone if needed
    if not repo_path.exists() and github_repo:
        _clone_repo(github_repo, repo_path, token=github_token)
    elif not repo_path.exists():
        raise FileNotFoundError(
            f"Repository path {repo_path} does not exist "
            f"and no github_repo was provided for cloning."
        )

    if not repo_path.is_dir():
        raise NotADirectoryError(f"{repo_path} is not a directory.")

    if not semgrep_available():
        raise SemgrepNotInstalledError(
            "Semgrep is required for Whitney code scanning. Install it with: pip install semgrep"
        )

    logger.info("Scanning repository at %s", repo_path)
    findings: list[Finding] = []

    # Semgrep AST-based rules (48 rules across 16 files)
    logger.info("Running Semgrep AST scanner (48 rules)")
    semgrep_findings = run_semgrep(repo_path)
    findings.extend(semgrep_findings)
    logger.info("Semgrep engine: %d finding(s)", len(semgrep_findings))

    # Python-only checks — patterns requiring file-level context analysis
    # (rate limiting, outdated SDK, MCP/A2A protocol checks)
    for check_fn in PYTHON_ONLY_CHECKS:
        check_name = check_fn.__name__
        try:
            results = check_fn(repo_path)
            findings.extend(results)
            if results:
                logger.info(
                    "Python check %s: %d finding(s)",
                    check_name,
                    len(results),
                )
        except Exception:
            logger.exception("Check %s failed", check_name)

    logger.info("Scan complete: %d total finding(s)", len(findings))
    return findings


def _clone_repo(
    github_repo: str,
    dest: Path,
    *,
    token: str | None = None,
) -> None:
    """Clone a GitHub repository to *dest*.

    Uses ``git clone`` via subprocess. If a *token* is provided it is
    embedded in the HTTPS URL for private repos.
    """
    if token:
        clone_url = f"https://x-access-token:{token}@github.com/{github_repo}.git"
    else:
        clone_url = f"https://github.com/{github_repo}.git"

    dest.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Cloning %s to %s", github_repo, dest)
    result = subprocess.run(
        ["git", "clone", "--depth", "1", clone_url, str(dest)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        # Sanitise error output to avoid leaking tokens
        stderr = result.stderr.replace(token, "***") if token else result.stderr
        raise RuntimeError(f"Failed to clone {github_repo}: {stderr.strip()}")
    logger.info("Clone complete: %s", dest)
