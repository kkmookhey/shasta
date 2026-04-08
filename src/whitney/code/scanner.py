"""Main code scanning engine for AI security issues.

Scans GitHub repositories (cloned or local) for AI-specific security
vulnerabilities and returns compliance findings.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from shasta.evidence.models import Finding
from whitney.code.checks import ALL_CHECKS, PYTHON_ONLY_CHECKS
from whitney.code.semgrep_runner import run_semgrep, semgrep_available

logger = logging.getLogger(__name__)


def scan_repository(
    repo_path: str | Path,
    *,
    github_token: str | None = None,
    github_repo: str | None = None,  # "owner/repo" — clones if repo_path doesn't exist
) -> list[Finding]:
    """Scan a code repository for AI security issues.

    Args:
        repo_path: Local path to the repository (or where it should be cloned).
        github_token: GitHub personal access token for cloning private repos.
        github_repo: ``owner/repo`` string. If provided and *repo_path* does
            not exist the repo is cloned automatically.

    Returns:
        A list of :class:`Finding` objects, one per detected issue.
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

    logger.info("Scanning repository at %s", repo_path)

    findings: list[Finding] = []

    if semgrep_available():
        # Dual-engine mode: Semgrep for 13 checks + Python for 2
        logger.info("Semgrep available — using AST-based scanning engine")
        semgrep_findings = run_semgrep(repo_path)
        findings.extend(semgrep_findings)
        logger.info("Semgrep engine: %d finding(s)", len(semgrep_findings))

        # Run the 2 Python-only checks (rate limiting + outdated SDK)
        for check_fn in PYTHON_ONLY_CHECKS:
            check_name = check_fn.__name__
            try:
                results = check_fn(repo_path)
                findings.extend(results)
                logger.info("Python check %s: %d finding(s)", check_name, len(results))
            except Exception:
                logger.exception("Check %s failed", check_name)
    else:
        # Fallback: all 15 regex-based checks
        logger.info("Semgrep not available — falling back to regex engine")
        for check_fn in ALL_CHECKS:
            check_name = check_fn.__name__
            try:
                logger.debug("Running check: %s", check_name)
                results = check_fn(repo_path)
                findings.extend(results)
                logger.info("Check %s completed: %d finding(s)", check_name, len(results))
            except Exception:
                logger.exception("Check %s failed with an unexpected error", check_name)

    logger.info(
        "Scan complete: %d total finding(s)",
        len(findings),
    )
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
