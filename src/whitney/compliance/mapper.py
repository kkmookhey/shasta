"""Maps findings to ISO 42001 and EU AI Act controls and enriches findings with control context."""

from __future__ import annotations

from shasta.evidence.models import Finding
from whitney.compliance.eu_ai_act import (
    EU_AI_ACT_OBLIGATIONS,
    get_eu_ai_act_obligations_for_check,
)
from whitney.compliance.iso42001 import (
    ISO42001_CONTROLS,
    get_iso42001_controls_for_check,
)


def enrich_findings_with_ai_controls(findings: list[Finding]) -> list[Finding]:
    """Add iso42001_controls and eu_ai_act fields to findings based on check_id mapping.

    Stores control IDs in finding.details since the Finding model uses
    soc2_controls for SOC 2. This mirrors the ISO 27001 mapper pattern.
    """
    for finding in findings:
        # ISO 42001
        iso42001_controls = get_iso42001_controls_for_check(finding.check_id)
        finding.details["iso42001_controls"] = [c.id for c in iso42001_controls]

        # EU AI Act
        eu_ai_act_obligations = get_eu_ai_act_obligations_for_check(finding.check_id)
        finding.details["eu_ai_act"] = [o.id for o in eu_ai_act_obligations]

    return findings


def get_iso42001_control_summary(findings: list[Finding]) -> dict[str, dict]:
    """Aggregate findings by ISO 42001 control (mirrors Shasta's get_control_summary)."""
    summary: dict[str, dict] = {}

    # Initialize all known controls
    for ctrl_id, ctrl in ISO42001_CONTROLS.items():
        summary[ctrl_id] = {
            "id": ctrl_id,
            "title": ctrl.title,
            "clause": ctrl.clause,
            "guidance": ctrl.guidance,
            "requires_policy": ctrl.requires_policy,
            "has_automated_checks": bool(ctrl.check_ids),
            "findings": [],
            "pass_count": 0,
            "fail_count": 0,
            "partial_count": 0,
            "overall_status": "not_assessed",
        }

    # Map findings to controls via check_id
    for finding in findings:
        controls = get_iso42001_controls_for_check(finding.check_id)
        for ctrl in controls:
            if ctrl.id in summary:
                summary[ctrl.id]["findings"].append(finding)
                match finding.status.value:
                    case "pass":
                        summary[ctrl.id]["pass_count"] += 1
                    case "fail":
                        summary[ctrl.id]["fail_count"] += 1
                    case "partial":
                        summary[ctrl.id]["partial_count"] += 1

    # Determine overall status
    for ctrl_id, data in summary.items():
        if data["fail_count"] > 0:
            data["overall_status"] = "fail"
        elif data["partial_count"] > 0:
            data["overall_status"] = "partial"
        elif data["pass_count"] > 0:
            data["overall_status"] = "pass"
        elif data["requires_policy"] and not data["has_automated_checks"]:
            data["overall_status"] = "requires_policy"
        else:
            data["overall_status"] = "not_assessed"

    return summary


def get_eu_ai_act_obligation_summary(findings: list[Finding]) -> dict[str, dict]:
    """Aggregate findings by EU AI Act obligation (mirrors Shasta's get_control_summary)."""
    summary: dict[str, dict] = {}

    # Initialize all known obligations
    for obl_id, obl in EU_AI_ACT_OBLIGATIONS.items():
        summary[obl_id] = {
            "id": obl_id,
            "article": obl.article,
            "title": obl.title,
            "risk_level": obl.risk_level,
            "guidance": obl.guidance,
            "requires_policy": obl.requires_policy,
            "has_automated_checks": bool(obl.check_ids),
            "findings": [],
            "pass_count": 0,
            "fail_count": 0,
            "partial_count": 0,
            "overall_status": "not_assessed",
        }

    # Map findings to obligations via check_id
    for finding in findings:
        obligations = get_eu_ai_act_obligations_for_check(finding.check_id)
        for obl in obligations:
            if obl.id in summary:
                summary[obl.id]["findings"].append(finding)
                match finding.status.value:
                    case "pass":
                        summary[obl.id]["pass_count"] += 1
                    case "fail":
                        summary[obl.id]["fail_count"] += 1
                    case "partial":
                        summary[obl.id]["partial_count"] += 1

    # Determine overall status
    for obl_id, data in summary.items():
        if data["fail_count"] > 0:
            data["overall_status"] = "fail"
        elif data["partial_count"] > 0:
            data["overall_status"] = "partial"
        elif data["pass_count"] > 0:
            data["overall_status"] = "pass"
        elif data["requires_policy"] and not data["has_automated_checks"]:
            data["overall_status"] = "requires_policy"
        else:
            data["overall_status"] = "not_assessed"

    return summary
