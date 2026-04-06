"""AI governance compliance scoring engine for ISO 42001 and EU AI Act."""

from __future__ import annotations

from dataclasses import dataclass

from shasta.evidence.models import Finding
from whitney.compliance.mapper import (
    get_eu_ai_act_obligation_summary,
    get_iso42001_control_summary,
)


@dataclass
class AIGovernanceScore:
    """Overall AI governance compliance score."""

    # ISO 42001
    total_controls: int
    passing: int
    failing: int
    partial: int
    not_assessed: int
    requires_policy: int
    score_percentage: float  # 0-100, based on assessed controls only
    grade: str  # A, B, C, D, F

    # EU AI Act
    eu_total_obligations: int
    eu_passing: int
    eu_failing: int
    eu_partial: int
    eu_not_assessed: int
    eu_requires_policy: int
    eu_score_percentage: float
    eu_grade: str

    # Combined
    combined_score: float
    combined_grade: str


def calculate_ai_governance_score(findings: list[Finding]) -> AIGovernanceScore:
    """Calculate AI governance compliance score from findings.

    Scores findings against both ISO 42001 controls and EU AI Act obligations
    using the same algorithm as Shasta's SOC 2 scorer:
    (passing + partial * 0.5) / assessed * 100, with the zero-findings fix.
    """
    # ISO 42001 scoring
    iso_summary = get_iso42001_control_summary(findings)
    iso_total = len(iso_summary)
    iso_passing = sum(1 for c in iso_summary.values() if c["overall_status"] == "pass")
    iso_failing = sum(1 for c in iso_summary.values() if c["overall_status"] == "fail")
    iso_partial = sum(1 for c in iso_summary.values() if c["overall_status"] == "partial")
    iso_not_assessed = sum(1 for c in iso_summary.values() if c["overall_status"] == "not_assessed")
    iso_requires_policy = sum(
        1 for c in iso_summary.values() if c["overall_status"] == "requires_policy"
    )

    iso_assessed = iso_passing + iso_failing + iso_partial
    if iso_assessed > 0:
        iso_score = (iso_passing + iso_partial * 0.5) / iso_assessed * 100
    elif iso_not_assessed > 0 or iso_requires_policy > 0:
        iso_score = 100.0
    else:
        iso_score = 0.0
    iso_grade = _score_to_grade(iso_score)

    # EU AI Act scoring
    eu_summary = get_eu_ai_act_obligation_summary(findings)
    eu_total = len(eu_summary)
    eu_passing = sum(1 for o in eu_summary.values() if o["overall_status"] == "pass")
    eu_failing = sum(1 for o in eu_summary.values() if o["overall_status"] == "fail")
    eu_partial = sum(1 for o in eu_summary.values() if o["overall_status"] == "partial")
    eu_not_assessed = sum(1 for o in eu_summary.values() if o["overall_status"] == "not_assessed")
    eu_requires_policy = sum(
        1 for o in eu_summary.values() if o["overall_status"] == "requires_policy"
    )

    eu_assessed = eu_passing + eu_failing + eu_partial
    if eu_assessed > 0:
        eu_score = (eu_passing + eu_partial * 0.5) / eu_assessed * 100
    elif eu_not_assessed > 0 or eu_requires_policy > 0:
        eu_score = 100.0
    else:
        eu_score = 0.0
    eu_grade = _score_to_grade(eu_score)

    # Combined score (weighted average of both frameworks)
    total_assessed = iso_assessed + eu_assessed
    if total_assessed > 0:
        combined_passing = iso_passing + eu_passing
        combined_partial = iso_partial + eu_partial
        combined_score = (combined_passing + combined_partial * 0.5) / total_assessed * 100
    elif (iso_not_assessed + eu_not_assessed) > 0 or (iso_requires_policy + eu_requires_policy) > 0:
        combined_score = 100.0
    else:
        combined_score = 0.0
    combined_grade = _score_to_grade(combined_score)

    return AIGovernanceScore(
        total_controls=iso_total,
        passing=iso_passing,
        failing=iso_failing,
        partial=iso_partial,
        not_assessed=iso_not_assessed,
        requires_policy=iso_requires_policy,
        score_percentage=round(iso_score, 1),
        grade=iso_grade,
        eu_total_obligations=eu_total,
        eu_passing=eu_passing,
        eu_failing=eu_failing,
        eu_partial=eu_partial,
        eu_not_assessed=eu_not_assessed,
        eu_requires_policy=eu_requires_policy,
        eu_score_percentage=round(eu_score, 1),
        eu_grade=eu_grade,
        combined_score=round(combined_score, 1),
        combined_grade=combined_grade,
    )


def _score_to_grade(score: float) -> str:
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"
