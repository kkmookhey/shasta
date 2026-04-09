"""Smoke tests for the Stage 1-3 AWS parity sweep.

Verifies that the new AWS modules import cleanly, expose the expected
public runners, that the Finding model carries the new cis_aws_controls
field, and that the new AWS Terraform templates render to non-empty
azurerm-style snippets when fed a synthetic Finding.
"""

from __future__ import annotations

import importlib
import inspect

import pytest

from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    Finding,
    Severity,
)


NEW_AWS_MODULES = [
    "shasta.aws.databases",
    "shasta.aws.serverless",
    "shasta.aws.backup",
    "shasta.aws.vpc_endpoints",
    "shasta.aws.cloudwatch_logs",
    "shasta.aws.organizations",
]

EXPECTED_RUNNERS = {
    "shasta.aws.databases": "run_all_aws_database_checks",
    "shasta.aws.serverless": "run_all_aws_serverless_checks",
    "shasta.aws.backup": "run_all_aws_backup_checks",
    "shasta.aws.vpc_endpoints": "run_all_aws_vpc_endpoint_checks",
    "shasta.aws.cloudwatch_logs": "run_all_aws_cloudwatch_log_checks",
    "shasta.aws.organizations": "run_all_aws_organizations_checks",
}


@pytest.mark.parametrize("mod_name", NEW_AWS_MODULES)
def test_module_imports(mod_name: str) -> None:
    importlib.import_module(mod_name)


@pytest.mark.parametrize("mod_name,runner_name", list(EXPECTED_RUNNERS.items()))
def test_runner_exists_and_takes_client(mod_name: str, runner_name: str) -> None:
    mod = importlib.import_module(mod_name)
    runner = getattr(mod, runner_name)
    sig = inspect.signature(runner)
    params = list(sig.parameters)
    assert params, f"{runner_name} should accept at least one positional argument (client)"
    assert params[0] == "client"


def test_finding_model_has_cis_aws_field() -> None:
    f = Finding(
        check_id="x",
        title="t",
        description="d",
        severity=Severity.INFO,
        status="pass",
        domain=CheckDomain.IAM,
        resource_type="X",
        resource_id="r",
        region="us-east-1",
        account_id="123456789012",
        cloud_provider=CloudProvider.AWS,
        cis_aws_controls=["1.20", "3.5"],
    )
    assert f.cis_aws_controls == ["1.20", "3.5"]


def test_lambda_eol_runtimes_table_is_current() -> None:
    """The deprecated runtimes table should include known-EOL runtimes for 2026."""
    from shasta.aws.serverless import DEPRECATED_LAMBDA_RUNTIMES

    for r in ("python3.7", "python3.8", "nodejs14.x", "nodejs16.x", "go1.x"):
        assert r in DEPRECATED_LAMBDA_RUNTIMES, f"{r} should be flagged as deprecated"


def test_vpc_endpoint_expectations_table() -> None:
    """The VPC endpoint walker must cover the high-leverage services."""
    from shasta.aws.vpc_endpoints import EXPECTED_VPC_ENDPOINTS

    for svc in ("s3", "dynamodb", "kms", "secretsmanager"):
        assert svc in EXPECTED_VPC_ENDPOINTS, f"{svc} should be in the expected endpoints table"


def test_aws_terraform_templates_registered() -> None:
    from shasta.remediation.engine import EXPLANATIONS, TERRAFORM_TEMPLATES

    aws_tf = [k for k in TERRAFORM_TEMPLATES if not k.startswith("azure-")]
    assert len(aws_tf) >= 30, f"Expected ≥30 AWS Terraform templates, found {len(aws_tf)}"

    missing_exp = [k for k in aws_tf if k not in EXPLANATIONS]
    assert not missing_exp, f"AWS TF templates missing EXPLANATIONS: {missing_exp}"


@pytest.mark.parametrize(
    "check_id",
    [
        "cloudtrail-kms-encryption",
        "cloudtrail-log-validation",
        "cloudtrail-s3-object-lock",
        "security-hub-enabled",
        "iam-access-analyzer",
        "efs-encryption",
        "sns-encryption",
        "sqs-encryption",
        "secrets-manager-rotation",
        "elb-listener-tls",
        "elb-access-logs",
        "elb-drop-invalid-headers",
        "rds-iam-auth",
        "rds-deletion-protection",
        "dynamodb-pitr",
        "dynamodb-kms",
        "lambda-runtime-eol",
        "lambda-dlq",
        "apigw-waf",
        "aws-backup-vault-lock",
        "aws-vpc-endpoints",
        "cwl-kms-encryption",
        "aws-org-scps",
    ],
)
def test_aws_terraform_template_renders(check_id: str) -> None:
    from shasta.remediation.engine import TERRAFORM_TEMPLATES

    fn = TERRAFORM_TEMPLATES[check_id]
    f = Finding(
        check_id=check_id,
        title="t",
        description="d",
        severity=Severity.HIGH,
        status="fail",
        domain=CheckDomain.MONITORING,
        resource_type="X",
        resource_id="r",
        region="us-east-1",
        account_id="123456789012",
        cloud_provider=CloudProvider.AWS,
        details={
            "trail": "main",
            "bucket": "cloudtrail-logs",
            "vault": "primary",
            "db": "mydb",
            "file_system_id": "fs-abc",
            "deprecated": [{"name": "fn1", "runtime": "python3.7"}],
        },
    )
    out = fn(f)
    assert isinstance(out, str)
    assert out.strip(), f"{check_id} produced empty output"
    assert "aws_" in out or "resource" in out, f"{check_id} doesn't look like aws Terraform"
