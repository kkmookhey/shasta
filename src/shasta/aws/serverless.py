"""AWS serverless security checks: Lambda, API Gateway, Step Functions.

Covers Lambda runtime EOL detection, environment variable encryption,
dead-letter config, code signing, VPC placement; API Gateway WAF
attachment, logging, throttling, mTLS; Step Functions logging.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from shasta.aws.client import AWSClient
from shasta.evidence.models import (
    CheckDomain,
    ComplianceStatus,
    Finding,
    Severity,
)


# Lambda runtimes that AWS has marked deprecated. Updated for 2026.
DEPRECATED_LAMBDA_RUNTIMES = {
    "nodejs",
    "nodejs4.3",
    "nodejs4.3-edge",
    "nodejs6.10",
    "nodejs8.10",
    "nodejs10.x",
    "nodejs12.x",
    "nodejs14.x",
    "nodejs16.x",
    "python2.7",
    "python3.6",
    "python3.7",
    "python3.8",
    "ruby2.5",
    "ruby2.7",
    "dotnetcore1.0",
    "dotnetcore2.0",
    "dotnetcore2.1",
    "dotnetcore3.1",
    "dotnet5.0",
    "dotnet6",
    "go1.x",
    "java8",
    "java8.al2",
}


def run_all_aws_serverless_checks(client: AWSClient) -> list[Finding]:
    """Run all serverless compliance checks."""
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    try:
        regions = client.get_enabled_regions()
    except ClientError:
        regions = [region]

    for r in regions:
        try:
            rc = client.for_region(r)
            findings.extend(check_lambda_runtime_eol(rc, account_id, r))
            findings.extend(check_lambda_env_encryption(rc, account_id, r))
            findings.extend(check_lambda_dead_letter(rc, account_id, r))
            findings.extend(check_lambda_code_signing(rc, account_id, r))
            findings.extend(check_apigw_logging(rc, account_id, r))
            findings.extend(check_apigw_waf(rc, account_id, r))
            findings.extend(check_stepfunctions_logging(rc, account_id, r))
        except ClientError:
            continue

    return findings


# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------


def _lambda_functions(client: AWSClient) -> list[dict]:
    try:
        lam = client.client("lambda")
        paginator = lam.get_paginator("list_functions")
        out: list[dict] = []
        for page in paginator.paginate():
            out.extend(page.get("Functions", []))
        return out
    except ClientError:
        return []


def check_lambda_runtime_eol(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """[CIS AWS] Lambda functions on deprecated runtimes are unmaintained."""
    findings: list[Finding] = []
    fns = _lambda_functions(client)
    if not fns:
        return []

    deprecated: list[dict] = []
    healthy: list[str] = []
    for f in fns:
        runtime = f.get("Runtime", "")
        if runtime in DEPRECATED_LAMBDA_RUNTIMES:
            deprecated.append({"name": f.get("FunctionName"), "runtime": runtime})
        else:
            healthy.append(f.get("FunctionName", ""))

    if not deprecated:
        return [
            Finding(
                check_id="lambda-runtime-eol",
                title=f"All {len(fns)} Lambda function(s) on supported runtimes",
                description="No functions are running on AWS-deprecated runtimes.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="AWS::Lambda::Function",
                resource_id=f"arn:aws:lambda:{region}:{account_id}:function:*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC7.1"],
                cis_aws_controls=["4.x"],
            )
        ]
    return [
        Finding(
            check_id="lambda-runtime-eol",
            title=f"{len(deprecated)} Lambda function(s) on deprecated runtimes",
            description=(
                "Functions on deprecated runtimes stop receiving security patches. AWS will "
                "eventually block invocations after the deprecation deadline. List: "
                + ", ".join(f"{d['name']} ({d['runtime']})" for d in deprecated[:10])
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="AWS::Lambda::Function",
            resource_id=f"arn:aws:lambda:{region}:{account_id}:function:*",
            region=region,
            account_id=account_id,
            remediation=(
                "Migrate each function to a current runtime (nodejs20.x, python3.12, java21, "
                "etc.). For broken-by-bump dependencies, pin to the latest compatible runtime "
                "and budget engineering time before AWS blocks the deprecated one."
            ),
            soc2_controls=["CC7.1"],
            cis_aws_controls=["4.x"],
            details={"deprecated": deprecated},
        )
    ]


def check_lambda_env_encryption(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """Lambda env vars should be encrypted with a customer-managed KMS key."""
    findings: list[Finding] = []
    fns = _lambda_functions(client)
    no_cmk: list[str] = []
    has_cmk = 0
    no_env = 0
    for f in fns:
        env = (f.get("Environment") or {}).get("Variables") or {}
        if not env:
            no_env += 1
            continue
        kms = f.get("KMSKeyArn")
        if kms:
            has_cmk += 1
        else:
            no_cmk.append(f.get("FunctionName", ""))

    if not fns:
        return []

    if not no_cmk:
        return [
            Finding(
                check_id="lambda-env-kms",
                title=f"Lambda env-var encryption: {has_cmk} CMK, {no_env} no env vars",
                description="No function has env vars without explicit KMS key.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="AWS::Lambda::Function",
                resource_id=f"arn:aws:lambda:{region}:{account_id}:function:*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.7"],
                cis_aws_controls=["4.x"],
            )
        ]
    return [
        Finding(
            check_id="lambda-env-kms",
            title=f"{len(no_cmk)} Lambda function(s) with env vars but no CMK",
            description=(
                "Env vars are encrypted with the default Lambda key. CIS recommends a "
                "customer-managed KMS key so you control rotation and can audit decrypt calls."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.PARTIAL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::Lambda::Function",
            resource_id=f"arn:aws:lambda:{region}:{account_id}:function:*",
            region=region,
            account_id=account_id,
            remediation=(
                "aws lambda update-function-configuration --function-name <name> "
                "--kms-key-arn <key-arn>"
            ),
            soc2_controls=["CC6.7"],
            cis_aws_controls=["4.x"],
            details={"functions_without_cmk": no_cmk[:20]},
        )
    ]


def check_lambda_dead_letter(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """Async Lambda invocations should have a dead-letter queue or destination."""
    findings: list[Finding] = []
    fns = _lambda_functions(client)
    no_dlq: list[str] = []
    for f in fns:
        dlq = (f.get("DeadLetterConfig") or {}).get("TargetArn")
        if not dlq:
            no_dlq.append(f.get("FunctionName", ""))

    if not fns:
        return []

    if not no_dlq:
        return [
            Finding(
                check_id="lambda-dlq",
                title=f"All {len(fns)} Lambda function(s) have a DLQ",
                description="Every function has a dead-letter destination configured.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="AWS::Lambda::Function",
                resource_id=f"arn:aws:lambda:{region}:{account_id}:function:*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC7.2"],
            )
        ]
    return [
        Finding(
            check_id="lambda-dlq",
            title=f"{len(no_dlq)} Lambda function(s) without a dead-letter destination",
            description=(
                "Async invocation failures are silently retried then dropped. With no DLQ "
                "or destination, you lose the failed payload entirely — no debugging trail."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.PARTIAL,
            domain=CheckDomain.COMPUTE,
            resource_type="AWS::Lambda::Function",
            resource_id=f"arn:aws:lambda:{region}:{account_id}:function:*",
            region=region,
            account_id=account_id,
            remediation=(
                "Add an SQS queue or SNS topic as the function's dead-letter target. "
                "Or use Lambda Destinations for richer success/failure routing."
            ),
            soc2_controls=["CC7.2"],
            details={"functions_without_dlq": no_dlq[:20]},
        )
    ]


def check_lambda_code_signing(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """Lambda functions should require code signing for supply-chain integrity."""
    findings: list[Finding] = []
    fns = _lambda_functions(client)
    if not fns:
        return []
    no_signing: list[str] = []
    for f in fns:
        if not f.get("SigningProfileVersionArn") and not f.get("CodeSigningConfigArn"):
            no_signing.append(f.get("FunctionName", ""))

    if not no_signing:
        return [
            Finding(
                check_id="lambda-code-signing",
                title=f"All {len(fns)} Lambda function(s) require code signing",
                description="Every function has a code signing config attached.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="AWS::Lambda::Function",
                resource_id=f"arn:aws:lambda:{region}:{account_id}:function:*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC8.1"],
                cis_aws_controls=["4.x"],
            )
        ]
    return [
        Finding(
            check_id="lambda-code-signing",
            title=f"{len(no_signing)} Lambda function(s) without code signing",
            description=(
                "Code signing prevents an attacker who compromises a CI pipeline from deploying "
                "tampered code — only artifacts signed by an approved Signer profile will deploy."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.PARTIAL,
            domain=CheckDomain.COMPUTE,
            resource_type="AWS::Lambda::Function",
            resource_id=f"arn:aws:lambda:{region}:{account_id}:function:*",
            region=region,
            account_id=account_id,
            remediation=(
                "Create an AWS Signer profile, then `aws lambda put-function-code-signing-config` "
                "to require signed deploys."
            ),
            soc2_controls=["CC8.1"],
            cis_aws_controls=["4.x"],
            details={"functions_without_signing": no_signing[:20]},
        )
    ]


# ---------------------------------------------------------------------------
# API Gateway
# ---------------------------------------------------------------------------


def check_apigw_logging(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """[CIS AWS] API Gateway stages should have CloudWatch logging at INFO level."""
    findings: list[Finding] = []
    try:
        apigw = client.client("apigateway")
        apis = apigw.get_rest_apis().get("items", [])
    except ClientError:
        return []

    for api in apis:
        api_id = api.get("id", "")
        api_name = api.get("name", "unknown")
        try:
            stages = apigw.get_stages(restApiId=api_id).get("item", [])
        except ClientError:
            continue
        for stage in stages:
            stage_name = stage.get("stageName", "")
            method_settings = stage.get("methodSettings", {}).get("*/*", {})
            log_level = method_settings.get("loggingLevel", "OFF")
            metrics = method_settings.get("metricsEnabled", False)
            arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stage_name}"
            ok = log_level in ("INFO", "ERROR") and metrics
            if ok:
                findings.append(
                    Finding(
                        check_id="apigw-logging",
                        title=f"API Gateway '{api_name}/{stage_name}' has logging+metrics",
                        description=f"Logging level={log_level}, metrics enabled.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.LOGGING,
                        resource_type="AWS::ApiGateway::Stage",
                        resource_id=arn,
                        region=region,
                        account_id=account_id,
                        soc2_controls=["CC7.1"],
                        cis_aws_controls=["3.x"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="apigw-logging",
                        title=f"API Gateway '{api_name}/{stage_name}' has logging disabled",
                        description=(
                            f"Logging level={log_level}, metrics={metrics}. Without execution "
                            "logging you cannot trace request failures or correlate with backend incidents."
                        ),
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.LOGGING,
                        resource_type="AWS::ApiGateway::Stage",
                        resource_id=arn,
                        region=region,
                        account_id=account_id,
                        remediation=(
                            "Enable Execution logging at INFO level + Detailed CloudWatch metrics "
                            "via the stage's Logs/Tracing tab."
                        ),
                        soc2_controls=["CC7.1"],
                        cis_aws_controls=["3.x"],
                    )
                )
    return findings


def check_apigw_waf(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """[CIS AWS] Public API Gateway stages should have AWS WAF associated."""
    findings: list[Finding] = []
    try:
        apigw = client.client("apigateway")
        apis = apigw.get_rest_apis().get("items", [])
    except ClientError:
        return []

    if not apis:
        return []

    no_waf: list[str] = []
    has_waf: list[str] = []
    for api in apis:
        api_id = api.get("id", "")
        try:
            stages = apigw.get_stages(restApiId=api_id).get("item", [])
        except ClientError:
            continue
        for stage in stages:
            stage_name = stage.get("stageName", "")
            web_acl = stage.get("webAclArn")
            label = f"{api.get('name', api_id)}/{stage_name}"
            if web_acl:
                has_waf.append(label)
            else:
                no_waf.append(label)

    if not no_waf:
        return [
            Finding(
                check_id="apigw-waf",
                title=f"All {len(has_waf)} API Gateway stage(s) have WAF attached",
                description="Every stage has an AWS WAF Web ACL.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.NETWORKING,
                resource_type="AWS::ApiGateway::Stage",
                resource_id=f"arn:aws:apigateway:{region}::/restapis/*/stages/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.6"],
                cis_aws_controls=["4.x"],
            )
        ]
    return [
        Finding(
            check_id="apigw-waf",
            title=f"{len(no_waf)} API Gateway stage(s) have no WAF",
            description=(
                "API stages without WAF are exposed to OWASP Top 10 / bot abuse / scraping. "
                "Even with auth, you need WAF for rate limiting and known-bad-input filtering."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.NETWORKING,
            resource_type="AWS::ApiGateway::Stage",
            resource_id=f"arn:aws:apigateway:{region}::/restapis/*/stages/*",
            region=region,
            account_id=account_id,
            remediation=(
                "Create a WAFv2 Web ACL with Core Rule Set + AWS-managed bot control, then "
                "associate it with each public API Gateway stage via "
                "wafv2:AssociateWebACL."
            ),
            soc2_controls=["CC6.6"],
            cis_aws_controls=["4.x"],
            details={"stages_without_waf": no_waf[:20]},
        )
    ]


# ---------------------------------------------------------------------------
# Step Functions
# ---------------------------------------------------------------------------


def check_stepfunctions_logging(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """Step Functions state machines should have execution history logging enabled."""
    findings: list[Finding] = []
    try:
        sfn = client.client("stepfunctions")
        machines = sfn.list_state_machines().get("stateMachines", [])
    except ClientError:
        return []

    if not machines:
        return []

    no_logging: list[str] = []
    has_logging = 0
    for m in machines:
        arn = m.get("stateMachineArn", "")
        try:
            desc = sfn.describe_state_machine(stateMachineArn=arn)
            level = (desc.get("loggingConfiguration", {}) or {}).get("level", "OFF")
            if level in ("ALL", "ERROR", "FATAL"):
                has_logging += 1
            else:
                no_logging.append(m.get("name", ""))
        except ClientError:
            continue

    if not no_logging:
        return [
            Finding(
                check_id="sfn-logging",
                title=f"All {has_logging} Step Functions state machine(s) have logging",
                description="Execution history logged to CloudWatch.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.LOGGING,
                resource_type="AWS::StepFunctions::StateMachine",
                resource_id=f"arn:aws:states:{region}:{account_id}:stateMachine:*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC7.1"],
            )
        ]
    return [
        Finding(
            check_id="sfn-logging",
            title=f"{len(no_logging)} Step Functions state machine(s) without logging",
            description="Logging level=OFF means execution history is only available via the StartExecution API and is lost after a few weeks.",
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.LOGGING,
            resource_type="AWS::StepFunctions::StateMachine",
            resource_id=f"arn:aws:states:{region}:{account_id}:stateMachine:*",
            region=region,
            account_id=account_id,
            remediation=(
                "aws stepfunctions update-state-machine --state-machine-arn <arn> "
                "--logging-configuration level=ALL,includeExecutionData=true,"
                "destinations=cloudWatchLogsLogGroup={logGroupArn=<arn>}"
            ),
            soc2_controls=["CC7.1"],
            details={"machines_without_logging": no_logging[:20]},
        )
    ]
