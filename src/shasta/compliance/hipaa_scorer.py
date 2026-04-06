"""HIPAA Security Rule compliance scoring engine."""

from __future__ import annotations

from dataclasses import dataclass

from shasta.compliance.hipaa_mapper import get_hipaa_control_summary
from shasta.evidence.models import Finding


@dataclass
class HIPAAScore:
    """Overall HIPAA Security Rule compliance score.

    Provides aggregate metrics and per-safeguard breakdowns for
    Administrative, Physical, and Technical safeguard categories.
    """

    total_controls: int
    passing: int
    failing: int
    partial: int
    not_assessed: int
    requires_policy: int
    score_percentage: float
    grade: str
    # By safeguard
    administrative_pass: int = 0
    administrative_fail: int = 0
    physical_pass: int = 0
    physical_fail: int = 0
    technical_pass: int = 0
    technical_fail: int = 0


def calculate_hipaa_score(findings: list[Finding]) -> HIPAAScore:
    """Calculate HIPAA compliance score from findings.

    Uses the same scoring formula as ISO 27001: assessed controls only,
    partial controls count as 0.5. When no controls are assessed but
    policy-only or not-assessed controls exist, defaults to 100%.
    """
    control_summary = get_hipaa_control_summary(findings)

    total = len(control_summary)
    passing = sum(1 for c in control_summary.values() if c["overall_status"] == "pass")
    failing = sum(1 for c in control_summary.values() if c["overall_status"] == "fail")
    partial = sum(1 for c in control_summary.values() if c["overall_status"] == "partial")
    not_assessed = sum(1 for c in control_summary.values() if c["overall_status"] == "not_assessed")
    requires_policy = sum(
        1 for c in control_summary.values() if c["overall_status"] == "requires_policy"
    )

    assessed = passing + failing + partial
    if assessed > 0:
        score = (passing + partial * 0.5) / assessed * 100
    elif not_assessed > 0 or requires_policy > 0:
        score = 100.0
    else:
        score = 0.0
    grade = _score_to_grade(score)

    # By safeguard
    admin_pass = sum(
        1
        for c in control_summary.values()
        if c["safeguard"] == "Administrative" and c["overall_status"] == "pass"
    )
    admin_fail = sum(
        1
        for c in control_summary.values()
        if c["safeguard"] == "Administrative" and c["overall_status"] == "fail"
    )
    phys_pass = sum(
        1
        for c in control_summary.values()
        if c["safeguard"] == "Physical" and c["overall_status"] == "pass"
    )
    phys_fail = sum(
        1
        for c in control_summary.values()
        if c["safeguard"] == "Physical" and c["overall_status"] == "fail"
    )
    tech_pass = sum(
        1
        for c in control_summary.values()
        if c["safeguard"] == "Technical" and c["overall_status"] == "pass"
    )
    tech_fail = sum(
        1
        for c in control_summary.values()
        if c["safeguard"] == "Technical" and c["overall_status"] == "fail"
    )

    return HIPAAScore(
        total_controls=total,
        passing=passing,
        failing=failing,
        partial=partial,
        not_assessed=not_assessed,
        requires_policy=requires_policy,
        score_percentage=round(score, 1),
        grade=grade,
        administrative_pass=admin_pass,
        administrative_fail=admin_fail,
        physical_pass=phys_pass,
        physical_fail=phys_fail,
        technical_pass=tech_pass,
        technical_fail=tech_fail,
    )


def _score_to_grade(score: float) -> str:
    """Convert numeric score to letter grade."""
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
