"""Regression test for Bug #2 from bugs1104.md.

`run_full_scan(framework=...)` must always enrich findings with SOC 2,
ISO 27001, AND HIPAA mappings regardless of the `framework` parameter.
Otherwise sequential scans with different framework flags produce
inconsistent finding shapes and downstream consumers (dashboard, scorers,
reports) see empty control lists.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)


def _fake_finding(check_id: str) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"fake {check_id}",
        description="fake",
        severity=Severity.HIGH,
        status=ComplianceStatus.FAIL,
        domain=CheckDomain.IAM,
        resource_type="AWS::IAM::User",
        resource_id="arn:aws:iam::123456789012:user/test",
        region="us-east-1",
        account_id="123456789012",
        cloud_provider=CloudProvider.AWS,
    )


class _FakeAccountInfo:
    account_id = "123456789012"
    region = "us-east-1"


class _FakeClient:
    account_info = _FakeAccountInfo()


@pytest.mark.parametrize("framework", ["soc2", "iso27001", "hipaa", "both", "all"])
def test_run_full_scan_enriches_all_frameworks_regardless_of_flag(framework):
    """All three framework mappers must run for every framework value."""
    from shasta import scanner

    fake_findings = [_fake_finding("iam-password-policy")]

    with (
        patch.object(scanner, "_run_aws_checks", return_value=list(fake_findings)),
        patch(
            "shasta.aws.vulnerabilities.run_all_vulnerability_checks",
            return_value=[],
        ),
        patch(
            "shasta.compliance.mapper.enrich_findings_with_controls",
            wraps=__import__(
                "shasta.compliance.mapper", fromlist=["enrich_findings_with_controls"]
            ).enrich_findings_with_controls,
        ) as mock_soc2,
        patch(
            "shasta.compliance.iso27001_mapper.enrich_findings_with_iso27001",
            wraps=__import__(
                "shasta.compliance.iso27001_mapper",
                fromlist=["enrich_findings_with_iso27001"],
            ).enrich_findings_with_iso27001,
        ) as mock_iso,
        patch(
            "shasta.compliance.hipaa_mapper.enrich_findings_with_hipaa",
            wraps=__import__(
                "shasta.compliance.hipaa_mapper", fromlist=["enrich_findings_with_hipaa"]
            ).enrich_findings_with_hipaa,
        ) as mock_hipaa,
    ):
        result = scanner.run_full_scan(client=_FakeClient(), framework=framework)

    assert mock_soc2.called, f"SOC 2 enrichment skipped for framework={framework}"
    assert mock_iso.called, f"ISO 27001 enrichment skipped for framework={framework}"
    assert mock_hipaa.called, f"HIPAA enrichment skipped for framework={framework}"
    assert len(result.findings) >= 1
