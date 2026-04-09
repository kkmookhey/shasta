"""Remediation engine — generates prioritized fix recommendations and Terraform code.

For each failing finding, produces:
  1. Plain-English explanation of what's wrong and why it matters
  2. Step-by-step remediation instructions
  3. Terraform code to fix the issue (where applicable)
  4. Priority score for ordering the remediation roadmap
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from shasta.evidence.models import ComplianceStatus, Finding, Severity

SEVERITY_PRIORITY = {
    Severity.CRITICAL: 1,
    Severity.HIGH: 2,
    Severity.MEDIUM: 3,
    Severity.LOW: 4,
    Severity.INFO: 5,
}


@dataclass
class Remediation:
    """A remediation recommendation for a finding."""

    finding: Finding
    priority: int
    explanation: str  # Why this matters (founder-friendly)
    steps: list[str]  # Step-by-step instructions
    terraform: str = ""  # Terraform code to fix, if applicable
    effort: str = ""  # "quick" (<30min), "moderate" (1-4hrs), "significant" (>4hrs)
    category: str = ""  # "iam", "networking", "storage", "monitoring"


# ---------------------------------------------------------------------------
# Terraform template registry — maps check_id to a Terraform generator
# ---------------------------------------------------------------------------

TERRAFORM_TEMPLATES: dict[str, callable] = {}


def _tf(check_id: str):
    """Decorator to register a Terraform template generator."""

    def decorator(fn):
        TERRAFORM_TEMPLATES[check_id] = fn
        return fn

    return decorator


@_tf("iam-password-policy")
def _tf_password_policy(f: Finding) -> str:
    return """\
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 12
  hard_expiry                    = false
}"""


@_tf("iam-user-mfa")
def _tf_user_mfa(f: Finding) -> str:
    username = f.details.get("username", "USERNAME")
    return f"""\
# MFA must be enabled manually or via CLI — Terraform cannot create virtual MFA devices.
# Run the following AWS CLI commands:

# 1. Create a virtual MFA device:
#    aws iam create-virtual-mfa-device --virtual-mfa-device-name {username}-mfa \\
#        --outfile /tmp/{username}-qr.png --bootstrap-method QRCodePNG

# 2. Scan the QR code with an authenticator app (Google Authenticator, Authy, etc.)

# 3. Enable MFA for the user (replace CODE1 and CODE2 with two consecutive codes):
#    aws iam enable-mfa-device --user-name {username} \\
#        --serial-number arn:aws:iam::ACCOUNT_ID:mfa/{username}-mfa \\
#        --authentication-code1 CODE1 --authentication-code2 CODE2"""


@_tf("iam-no-direct-policies")
def _tf_no_direct_policies(f: Finding) -> str:
    username = f.details.get("username", "USERNAME")
    attached = f.details.get("attached_policies", [])
    policies_block = "\n".join(f"  # - {p}" for p in attached)
    return f'''\
# Move direct policies from user '{username}' to a group.
# Currently attached directly:
{policies_block}

resource "aws_iam_group" "{username}_group" {{
  name = "{username}-role-group"
}}

resource "aws_iam_group_membership" "{username}_membership" {{
  name  = "{username}-membership"
  users = ["{username}"]
  group = aws_iam_group.{username}_group.name
}}

# Attach the policies to the group instead of the user.
# Then remove direct user policy attachments.'''


@_tf("iam-overprivileged-user")
def _tf_overprivileged(f: Finding) -> str:
    username = f.details.get("username", "USERNAME")
    return f'''\
# Replace AdministratorAccess for user '{username}' with scoped policies.
# Step 1: Identify what the user actually needs access to.
# Step 2: Create a custom policy with minimum required permissions.
# Step 3: Remove the admin policy and attach the scoped one.

# Example: If the user only needs S3 and EC2 read access:
resource "aws_iam_policy" "{username}_scoped" {{
  name        = "{username}-scoped-access"
  description = "Scoped permissions for {username} — replaces AdministratorAccess"

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect   = "Allow"
        Action   = [
          "s3:Get*",
          "s3:List*",
          "ec2:Describe*",
        ]
        Resource = "*"
      }}
    ]
  }})
}}

# IMPORTANT: Customize the actions and resources above based on
# what '{username}' actually needs to do.'''


@_tf("sg-no-unrestricted-ingress")
def _tf_restrict_sg(f: Finding) -> str:
    sg_name = f.details.get("sg_name", "SECURITY_GROUP")
    sg_id = f.resource_id
    rules = f.details.get("unrestricted_rules", [])

    rules_desc = []
    for r in rules:
        if r.get("protocol") == "-1":
            rules_desc.append("all traffic")
        else:
            rules_desc.append(f"port {r.get('from_port')}-{r.get('to_port')}")

    return f'''\
# Security group '{sg_name}' ({sg_id}) currently allows unrestricted
# ingress for: {", ".join(rules_desc)}
#
# Replace 0.0.0.0/0 with your specific IP ranges:

# Option 1: Restrict to your office/VPN IP
# Find your IP: curl -s ifconfig.me
resource "aws_vpc_security_group_ingress_rule" "{sg_name}_restricted" {{
  security_group_id = "{sg_id}"
  from_port         = 443  # Adjust port as needed
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "YOUR_OFFICE_IP/32"  # Replace with your actual IP
  description       = "HTTPS from office"
}}

# Option 2: If this SG is no longer needed, delete it:
# aws ec2 delete-security-group --group-id {sg_id}
#
# First check nothing is using it:
# aws ec2 describe-network-interfaces --filters Name=group-id,Values={sg_id}'''


@_tf("vpc-flow-logs-enabled")
def _tf_vpc_flow_logs(f: Finding) -> str:
    vpc_id = f.resource_id
    vpc_name = f.details.get("vpc_name", "")
    safe_name = (vpc_name or vpc_id).replace("-", "_").replace(" ", "_")
    return f'''\
resource "aws_flow_log" "{safe_name}_flow_log" {{
  vpc_id          = "{vpc_id}"
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.{safe_name}_flow.arn
  iam_role_arn    = aws_iam_role.flow_log_role.arn
}}

resource "aws_cloudwatch_log_group" "{safe_name}_flow" {{
  name              = "/aws/vpc/flow-logs/{vpc_id}"
  retention_in_days = 90
}}

resource "aws_iam_role" "flow_log_role" {{
  name = "vpc-flow-log-role"
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect    = "Allow"
      Principal = {{ Service = "vpc-flow-logs.amazonaws.com" }}
      Action    = "sts:AssumeRole"
    }}]
  }})
}}

resource "aws_iam_role_policy" "flow_log_policy" {{
  name = "vpc-flow-log-policy"
  role = aws_iam_role.flow_log_role.id
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }}]
  }})
}}'''


@_tf("s3-versioning")
def _tf_s3_versioning(f: Finding) -> str:
    bucket = f.details.get("bucket", "BUCKET_NAME")
    return f'''\
resource "aws_s3_bucket_versioning" "{bucket.replace("-", "_")}" {{
  bucket = "{bucket}"
  versioning_configuration {{
    status = "Enabled"
  }}
}}'''


@_tf("s3-ssl-only")
def _tf_s3_ssl(f: Finding) -> str:
    bucket = f.details.get("bucket", "BUCKET_NAME")
    safe = bucket.replace("-", "_")
    return f'''\
resource "aws_s3_bucket_policy" "{safe}_ssl_only" {{
  bucket = "{bucket}"
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [
        "arn:aws:s3:::{bucket}",
        "arn:aws:s3:::{bucket}/*"
      ]
      Condition = {{
        Bool = {{ "aws:SecureTransport" = "false" }}
      }}
    }}]
  }})
}}'''


@_tf("s3-public-access-block")
def _tf_s3_public_block(f: Finding) -> str:
    bucket = f.details.get("bucket", "BUCKET_NAME")
    safe = bucket.replace("-", "_")
    return f'''\
resource "aws_s3_bucket_public_access_block" "{safe}" {{
  bucket                  = "{bucket}"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}'''


@_tf("s3-encryption-at-rest")
def _tf_s3_encryption(f: Finding) -> str:
    bucket = f.details.get("bucket", "BUCKET_NAME")
    safe = bucket.replace("-", "_")
    return f'''\
resource "aws_s3_bucket_server_side_encryption_configuration" "{safe}" {{
  bucket = "{bucket}"
  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "aws:kms"
    }}
    bucket_key_enabled = true
  }}
}}'''


# ---------------------------------------------------------------------------
# AWS — Stage 1/2/3 CIS AWS v3.0 sweep templates
# ---------------------------------------------------------------------------


def _aws_safe(name: str) -> str:
    """Sanitize an AWS resource name for use as a Terraform identifier."""
    return (name or "RESOURCE").replace("-", "_").replace(".", "_").replace("/", "_")


# ----- CloudTrail -----


@_tf("cloudtrail-kms-encryption")
def _tf_aws_ct_kms(f: Finding) -> str:
    name = f.details.get("trail", "main")
    return f'''\
resource "aws_kms_key" "cloudtrail" {{
  description             = "CloudTrail log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "AllowCloudTrail"
        Effect = "Allow"
        Principal = {{ Service = "cloudtrail.amazonaws.com" }}
        Action = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource = "*"
      }},
      {{
        Sid    = "AllowAccountFullAccess"
        Effect = "Allow"
        Principal = {{ AWS = "arn:aws:iam::ACCOUNT_ID:root" }}
        Action = "kms:*"
        Resource = "*"
      }}
    ]
  }})
}}

resource "aws_cloudtrail" "{_aws_safe(name)}" {{
  name           = "{name}"
  # ... existing config ...
  kms_key_id     = aws_kms_key.cloudtrail.arn
}}'''


@_tf("cloudtrail-log-validation")
def _tf_aws_ct_validation(f: Finding) -> str:
    name = f.details.get("trail", "main")
    return f'''\
resource "aws_cloudtrail" "{_aws_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  enable_log_file_validation = true  # CIS AWS 3.2
}}'''


@_tf("cloudtrail-s3-object-lock")
def _tf_aws_ct_object_lock(f: Finding) -> str:
    bucket = f.details.get("bucket", "cloudtrail-logs")
    safe = _aws_safe(bucket)
    return f'''\
# Object Lock can only be enabled at bucket creation. Migrate logs to a new
# bucket created with object_lock_enabled = true, then update the trail.

resource "aws_s3_bucket" "{safe}_v2" {{
  bucket              = "{bucket}-v2"
  object_lock_enabled = true
}}

resource "aws_s3_bucket_object_lock_configuration" "{safe}_v2" {{
  bucket = aws_s3_bucket.{safe}_v2.id

  rule {{
    default_retention {{
      mode = "COMPLIANCE"
      days = 365
    }}
  }}
}}

resource "aws_s3_bucket_versioning" "{safe}_v2" {{
  bucket = aws_s3_bucket.{safe}_v2.id
  versioning_configuration {{
    status = "Enabled"
  }}
}}'''


@_tf("security-hub-enabled")
def _tf_aws_security_hub(f: Finding) -> str:
    return '''\
resource "aws_securityhub_account" "main" {
  enable_default_standards = true
}

resource "aws_securityhub_standards_subscription" "cis_aws" {
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/3.0.0"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}'''


@_tf("iam-access-analyzer")
def _tf_aws_access_analyzer(f: Finding) -> str:
    return '''\
resource "aws_accessanalyzer_analyzer" "default" {
  analyzer_name = "default"
  type          = "ACCOUNT"  # Use ORGANIZATION if AWS Organizations is in use
}'''


# ----- Encryption: EFS / SNS / SQS / Secrets Manager / ACM -----


@_tf("efs-encryption")
def _tf_aws_efs_encryption(f: Finding) -> str:
    fs_id = f.details.get("file_system_id", "fs")
    return f'''\
# EFS encryption can only be enabled at creation. Recreate the file system:
resource "aws_efs_file_system" "{_aws_safe(fs_id)}_encrypted" {{
  creation_token = "{fs_id}-encrypted"
  encrypted      = true
  kms_key_id     = aws_kms_key.efs.arn
}}

resource "aws_kms_key" "efs" {{
  description         = "EFS encryption key"
  enable_key_rotation = true
}}'''


@_tf("sns-encryption")
def _tf_aws_sns_encryption(f: Finding) -> str:
    return '''\
resource "aws_sns_topic" "encrypted_topic" {
  name              = "TOPIC_NAME"
  kms_master_key_id = "alias/aws/sns"  # or a customer-managed key alias
}'''


@_tf("sqs-encryption")
def _tf_aws_sqs_encryption(f: Finding) -> str:
    return '''\
resource "aws_sqs_queue" "encrypted_queue" {
  name                              = "QUEUE_NAME"
  sqs_managed_sse_enabled           = true  # SQS-managed SSE (no KMS cost)
  # OR for KMS:
  # kms_master_key_id                 = "alias/aws/sqs"
  # kms_data_key_reuse_period_seconds = 300
}'''


@_tf("secrets-manager-rotation")
def _tf_aws_sm_rotation(f: Finding) -> str:
    return '''\
resource "aws_secretsmanager_secret" "db_password" {
  name = "db_password"
}

resource "aws_secretsmanager_secret_rotation" "db_password" {
  secret_id           = aws_secretsmanager_secret.db_password.id
  rotation_lambda_arn = aws_lambda_function.rotator.arn

  rotation_rules {
    automatically_after_days = 30
  }
}'''


@_tf("acm-expiring-certs")
def _tf_aws_acm_renewal(f: Finding) -> str:
    return '''\
# Use DNS validation so ACM auto-renews ~60 days before expiry.
# For email-validated or imported certs, switch to DNS-validated:
resource "aws_acm_certificate" "main" {
  domain_name       = "example.com"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for d in aws_acm_certificate.main.domain_validation_options : d.domain_name => {
      name   = d.resource_record_name
      record = d.resource_record_value
      type   = d.resource_record_type
    }
  }
  zone_id = "ZONE_ID"
  name    = each.value.name
  records = [each.value.record]
  type    = each.value.type
  ttl     = 60
}'''


# ----- Networking: ELB v2 -----


@_tf("elb-listener-tls")
def _tf_aws_elb_tls(f: Finding) -> str:
    return '''\
# Use a modern TLS policy and redirect HTTP -> HTTPS
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"  # CIS AWS
  certificate_arn   = aws_acm_certificate.main.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}'''


@_tf("elb-access-logs")
def _tf_aws_elb_access_logs(f: Finding) -> str:
    return '''\
resource "aws_lb" "main" {
  name = "main"
  # ... existing config ...

  access_logs {
    bucket  = aws_s3_bucket.elb_logs.id
    prefix  = "alb-logs"
    enabled = true
  }
}'''


@_tf("elb-drop-invalid-headers")
def _tf_aws_elb_drop_headers(f: Finding) -> str:
    return '''\
resource "aws_lb" "main" {
  name = "main"
  # ... existing config ...

  drop_invalid_header_fields = true  # CIS AWS
}'''


# ----- Stage 2: Databases -----


@_tf("rds-iam-auth")
def _tf_aws_rds_iam_auth(f: Finding) -> str:
    db_id = f.details.get("db", "main")
    return f'''\
resource "aws_db_instance" "{_aws_safe(db_id)}" {{
  identifier = "{db_id}"
  # ... existing config ...

  iam_database_authentication_enabled = true  # CIS AWS 2.3.x
}}'''


@_tf("rds-deletion-protection")
def _tf_aws_rds_deletion_protect(f: Finding) -> str:
    db_id = f.details.get("db", "main")
    return f'''\
resource "aws_db_instance" "{_aws_safe(db_id)}" {{
  identifier          = "{db_id}"
  # ... existing config ...
  deletion_protection = true
}}'''


@_tf("rds-pi-kms")
def _tf_aws_rds_pi(f: Finding) -> str:
    db_id = f.details.get("db", "main")
    return f'''\
resource "aws_db_instance" "{_aws_safe(db_id)}" {{
  identifier = "{db_id}"
  # ... existing config ...

  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.rds_pi.arn
}}

resource "aws_kms_key" "rds_pi" {{
  description         = "RDS Performance Insights"
  enable_key_rotation = true
}}'''


@_tf("rds-auto-minor-upgrade")
def _tf_aws_rds_minor(f: Finding) -> str:
    db_id = f.details.get("db", "main")
    return f'''\
resource "aws_db_instance" "{_aws_safe(db_id)}" {{
  identifier                  = "{db_id}"
  # ... existing config ...
  auto_minor_version_upgrade  = true
}}'''


@_tf("dynamodb-pitr")
def _tf_aws_ddb_pitr(f: Finding) -> str:
    return '''\
resource "aws_dynamodb_table" "main" {
  name = "TABLE_NAME"
  # ... existing config ...

  point_in_time_recovery {
    enabled = true
  }
}'''


@_tf("dynamodb-kms")
def _tf_aws_ddb_kms(f: Finding) -> str:
    return '''\
resource "aws_dynamodb_table" "main" {
  name = "TABLE_NAME"
  # ... existing config ...

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamodb.arn  # Customer-managed
  }
}

resource "aws_kms_key" "dynamodb" {
  description         = "DynamoDB CMK"
  enable_key_rotation = true
}'''


# ----- Stage 2: Serverless -----


@_tf("lambda-runtime-eol")
def _tf_aws_lambda_runtime(f: Finding) -> str:
    deprecated = f.details.get("deprecated", [])
    examples = ", ".join(d.get("name", "") if isinstance(d, dict) else str(d) for d in deprecated[:3])
    return f'''\
# Bump deprecated Lambda runtimes ({examples}) to a current version.
resource "aws_lambda_function" "example" {{
  function_name = "FUNCTION_NAME"
  runtime       = "python3.12"  # or nodejs20.x / java21 / dotnet8
  # ... existing config ...
}}'''


@_tf("lambda-env-kms")
def _tf_aws_lambda_env_kms(f: Finding) -> str:
    return '''\
resource "aws_kms_key" "lambda_env" {
  description         = "Lambda environment variable encryption"
  enable_key_rotation = true
}

resource "aws_lambda_function" "example" {
  function_name = "FUNCTION_NAME"
  kms_key_arn   = aws_kms_key.lambda_env.arn
  # ... existing config ...
}'''


@_tf("lambda-dlq")
def _tf_aws_lambda_dlq(f: Finding) -> str:
    return '''\
resource "aws_sqs_queue" "lambda_dlq" {
  name                       = "lambda-dlq"
  message_retention_seconds  = 1209600  # 14 days
}

resource "aws_lambda_function" "example" {
  function_name = "FUNCTION_NAME"
  # ... existing config ...

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }
}'''


@_tf("apigw-logging")
def _tf_aws_apigw_logging(f: Finding) -> str:
    return '''\
resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  stage_name  = aws_api_gateway_stage.prod.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled = true
    logging_level   = "INFO"
  }
}'''


@_tf("apigw-waf")
def _tf_aws_apigw_waf(f: Finding) -> str:
    return '''\
resource "aws_wafv2_web_acl" "apigw" {
  name        = "apigw-waf"
  scope       = "REGIONAL"
  default_action { allow {} }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "apigw-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "apigw" {
  resource_arn = aws_api_gateway_stage.prod.arn
  web_acl_arn  = aws_wafv2_web_acl.apigw.arn
}'''


@_tf("sfn-logging")
def _tf_aws_sfn_logging(f: Finding) -> str:
    return '''\
resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/states/STATE_MACHINE_NAME"
  retention_in_days = 90
}

resource "aws_sfn_state_machine" "main" {
  name     = "STATE_MACHINE_NAME"
  # ... existing config ...

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }
}'''


# ----- Stage 2: Backup -----


@_tf("aws-backup-vault-lock")
def _tf_aws_backup_vault_lock(f: Finding) -> str:
    name = f.details.get("vault", "primary")
    return f'''\
resource "aws_backup_vault" "{_aws_safe(name)}" {{
  name        = "{name}"
  kms_key_arn = aws_kms_key.backup.arn
}}

resource "aws_backup_vault_lock_configuration" "{_aws_safe(name)}" {{
  backup_vault_name   = aws_backup_vault.{_aws_safe(name)}.name
  changeable_for_days = 3       # Compliance mode after 3 days
  min_retention_days  = 30
  max_retention_days  = 365
}}

resource "aws_kms_key" "backup" {{
  description         = "AWS Backup vault encryption"
  enable_key_rotation = true
}}'''


@_tf("aws-backup-plans")
def _tf_aws_backup_plans(f: Finding) -> str:
    return '''\
resource "aws_backup_plan" "daily_35day" {
  name = "daily-35day"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.primary.name
    schedule          = "cron(0 5 ? * * *)"

    lifecycle {
      delete_after = 35
    }
  }
}

resource "aws_backup_selection" "all_resources" {
  iam_role_arn = aws_iam_role.backup.arn
  name         = "all-resources"
  plan_id      = aws_backup_plan.daily_35day.id

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "backup"
    value = "true"
  }
}'''


# ----- Stage 3: Cross-cutting -----


@_tf("aws-vpc-endpoints")
def _tf_aws_vpc_endpoints(f: Finding) -> str:
    return '''\
# Gateway endpoints (free)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.private[*].id
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.private[*].id
}

# Interface endpoints (priced per AZ + per GB)
locals {
  interface_endpoints = [
    "kms", "secretsmanager", "ssm", "ssmmessages", "ec2messages",
    "ecr.api", "ecr.dkr", "logs", "sts"
  ]
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(local.interface_endpoints)
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
}'''


@_tf("cwl-kms-encryption")
def _tf_aws_cwl_kms(f: Finding) -> str:
    return '''\
resource "aws_kms_key" "logs" {
  description         = "CloudWatch Logs encryption"
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowLogs"
      Effect = "Allow"
      Principal = { Service = "logs.${var.region}.amazonaws.com" }
      Action = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*",
                "kms:GenerateDataKey*", "kms:Describe*"]
      Resource = "*"
    }]
  })
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/app/main"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.logs.arn
}'''


@_tf("cwl-retention")
def _tf_aws_cwl_retention(f: Finding) -> str:
    return '''\
# Apply a retention policy to existing log groups via for_each
data "aws_cloudwatch_log_groups" "all" {}

resource "aws_cloudwatch_log_group" "retention_patch" {
  for_each          = toset(data.aws_cloudwatch_log_groups.all.log_group_names)
  name              = each.value
  retention_in_days = 90  # or 180/365 for compliance-critical
}'''


@_tf("aws-org-scps")
def _tf_aws_scps(f: Finding) -> str:
    return '''\
# Deny CloudTrail disable / delete across all member accounts
resource "aws_organizations_policy" "deny_cloudtrail_disable" {
  name = "deny-cloudtrail-disable"
  type = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyCloudTrailDisable"
      Effect = "Deny"
      Action = [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors",
      ]
      Resource = "*"
    }]
  })
}

resource "aws_organizations_policy_attachment" "deny_ct" {
  policy_id = aws_organizations_policy.deny_cloudtrail_disable.id
  target_id = "ou-XXXX-XXXXXXXX"  # OU or account ID
}'''


@_tf("aws-tag-policy")
def _tf_aws_tag_policy(f: Finding) -> str:
    return '''\
resource "aws_organizations_policy" "require_owner_tag" {
  name = "require-owner-tag"
  type = "TAG_POLICY"

  content = jsonencode({
    tags = {
      owner = {
        tag_key = { "@@assign" = "owner" }
        enforced_for = { "@@assign" = ["ec2:instance", "rds:db", "s3:bucket"] }
      }
      environment = {
        tag_key = { "@@assign" = "environment" }
        tag_value = { "@@assign" = ["production", "staging", "dev"] }
        enforced_for = { "@@assign" = ["ec2:instance", "rds:db", "s3:bucket"] }
      }
    }
  })
}'''


# ---------------------------------------------------------------------------
# Azure (azurerm) Terraform templates — covers the Stage 1/2/3 CIS Azure
# v3.0 checks. Each template is a focused snippet that the operator drops
# into the matching resource block; full resource definitions are intentionally
# avoided so we don't overwrite unrelated configuration.
# ---------------------------------------------------------------------------


def _safe(name: str) -> str:
    """Sanitize a resource name for use as a Terraform identifier."""
    return (name or "RESOURCE").replace("-", "_").replace(".", "_").replace("/", "_")


# ----- Storage Account checks -----


@_tf("azure-storage-shared-key-access")
def _tf_az_storage_shared_key(f: Finding) -> str:
    name = f.details.get("storage_account", "STORAGE_ACCOUNT")
    rg = f.details.get("resource_group", "RESOURCE_GROUP")
    return f'''\
resource "azurerm_storage_account" "{_safe(name)}" {{
  name                = "{name}"
  resource_group_name = "{rg}"
  # ... existing config ...

  # Disable account-key auth — force Entra ID-only access (CIS 3.3)
  shared_access_key_enabled = false
}}'''


@_tf("azure-storage-cross-tenant-replication")
def _tf_az_storage_cross_tenant(f: Finding) -> str:
    name = f.details.get("storage_account", "STORAGE_ACCOUNT")
    rg = f.details.get("resource_group", "RESOURCE_GROUP")
    return f'''\
resource "azurerm_storage_account" "{_safe(name)}" {{
  name                = "{name}"
  resource_group_name = "{rg}"
  # ... existing config ...

  # Block cross-tenant object replication (CIS 3.15)
  cross_tenant_replication_enabled = false
}}'''


@_tf("azure-storage-network-default-deny")
def _tf_az_storage_default_deny(f: Finding) -> str:
    name = f.details.get("storage_account", "STORAGE_ACCOUNT")
    rg = f.details.get("resource_group", "RESOURCE_GROUP")
    return f'''\
resource "azurerm_storage_account" "{_safe(name)}" {{
  name                = "{name}"
  resource_group_name = "{rg}"
  # ... existing config ...

  # Network default-Deny with explicit allowlist (CIS 3.8)
  network_rules {{
    default_action             = "Deny"
    bypass                     = ["AzureServices", "Logging", "Metrics"]
    ip_rules                   = []  # Add trusted IPs here
    virtual_network_subnet_ids = []  # Add trusted subnet IDs here
  }}
}}'''


# ----- Key Vault checks -----


@_tf("azure-keyvault-rbac-mode")
def _tf_az_kv_rbac(f: Finding) -> str:
    name = f.details.get("vault", "KEY_VAULT")
    return f'''\
resource "azurerm_key_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Use Azure RBAC instead of legacy access policies (CIS 8.5)
  enable_rbac_authorization = true
}}

# Re-grant access via RBAC role assignments after switching modes:
resource "azurerm_role_assignment" "{_safe(name)}_admin" {{
  scope                = azurerm_key_vault.{_safe(name)}.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = "PRINCIPAL_OBJECT_ID"
}}'''


@_tf("azure-keyvault-public-access")
def _tf_az_kv_public_access(f: Finding) -> str:
    name = f.details.get("vault", "KEY_VAULT")
    return f'''\
resource "azurerm_key_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Disable public network access (CIS 8.7)
  public_network_access_enabled = false

  # Default-Deny network ACLs (CIS 8.6)
  network_acls {{
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = []
  }}
}}

# Pair with a Private Endpoint:
resource "azurerm_private_endpoint" "{_safe(name)}_pe" {{
  name                = "{name}-pe"
  location            = "LOCATION"
  resource_group_name = "RESOURCE_GROUP"
  subnet_id           = "SUBNET_ID"

  private_service_connection {{
    name                           = "{name}-psc"
    private_connection_resource_id = azurerm_key_vault.{_safe(name)}.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }}
}}'''


# ----- SQL Server checks -----


@_tf("azure-sql-min-tls")
def _tf_az_sql_min_tls(f: Finding) -> str:
    server = f.details.get("server", "SQL_SERVER")
    return f'''\
resource "azurerm_mssql_server" "{_safe(server)}" {{
  name = "{server}"
  # ... existing config ...

  # Enforce TLS 1.2 (CIS 4.1.7)
  minimum_tls_version = "1.2"
}}'''


@_tf("azure-sql-auditing")
def _tf_az_sql_auditing(f: Finding) -> str:
    server = f.details.get("server", "SQL_SERVER")
    return f'''\
# Server-level auditing with ≥90-day retention (CIS 4.1.1, 4.1.6)
resource "azurerm_mssql_server_extended_auditing_policy" "{_safe(server)}" {{
  server_id                               = azurerm_mssql_server.{_safe(server)}.id
  storage_endpoint                        = "https://AUDITSTORAGE.blob.core.windows.net/"
  storage_account_access_key              = ""  # Use managed identity instead
  storage_account_access_key_is_secondary = false
  retention_in_days                       = 90
  log_monitoring_enabled                  = true
}}

# Also send to Log Analytics for query + alerting:
resource "azurerm_monitor_diagnostic_setting" "{_safe(server)}_audit" {{
  name                       = "{server}-audit"
  target_resource_id         = "${{azurerm_mssql_server.{_safe(server)}.id}}/databases/master"
  log_analytics_workspace_id = "LOG_ANALYTICS_WORKSPACE_ID"

  enabled_log {{ category = "SQLSecurityAuditEvents" }}
  enabled_log {{ category = "DevOpsOperationsAudit" }}
}}'''


@_tf("azure-sql-entra-admin")
def _tf_az_sql_entra_admin(f: Finding) -> str:
    server = f.details.get("server", "SQL_SERVER")
    return f'''\
resource "azurerm_mssql_server" "{_safe(server)}" {{
  name = "{server}"
  # ... existing config ...

  # Entra ID admin (CIS 4.1.3) — prefer an Entra group for break-glass
  azuread_administrator {{
    login_username              = "sql-admins"
    object_id                   = "ENTRA_GROUP_OBJECT_ID"
    azuread_authentication_only = true
  }}
}}'''


# ----- PostgreSQL Flexible Server -----


@_tf("azure-postgres-secure-transport")
def _tf_az_pg_secure_transport(f: Finding) -> str:
    server = f.details.get("server", "PG_SERVER")
    return f'''\
# Force TLS-only connections (CIS 4.3.1)
resource "azurerm_postgresql_flexible_server_configuration" "{_safe(server)}_secure_transport" {{
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.{_safe(server)}.id
  value     = "ON"
}}'''


@_tf("azure-postgres-log-settings")
def _tf_az_pg_log_settings(f: Finding) -> str:
    server = f.details.get("server", "PG_SERVER")
    safe = _safe(server)
    return f'''\
# Connection logging (CIS 4.3.2 - 4.3.4)
resource "azurerm_postgresql_flexible_server_configuration" "{safe}_log_connections" {{
  name      = "log_connections"
  server_id = azurerm_postgresql_flexible_server.{safe}.id
  value     = "ON"
}}

resource "azurerm_postgresql_flexible_server_configuration" "{safe}_log_disconnections" {{
  name      = "log_disconnections"
  server_id = azurerm_postgresql_flexible_server.{safe}.id
  value     = "ON"
}}

resource "azurerm_postgresql_flexible_server_configuration" "{safe}_log_checkpoints" {{
  name      = "log_checkpoints"
  server_id = azurerm_postgresql_flexible_server.{safe}.id
  value     = "ON"
}}'''


# ----- MySQL Flexible Server -----


@_tf("azure-mysql-secure-transport")
def _tf_az_mysql_secure_transport(f: Finding) -> str:
    server = f.details.get("server", "MYSQL_SERVER")
    return f'''\
# Force TLS-only connections (CIS 4.4.1)
resource "azurerm_mysql_flexible_server_configuration" "{_safe(server)}_secure_transport" {{
  name                = "require_secure_transport"
  resource_group_name = "RESOURCE_GROUP"
  server_name         = azurerm_mysql_flexible_server.{_safe(server)}.name
  value               = "ON"
}}'''


@_tf("azure-mysql-tls-version")
def _tf_az_mysql_tls_version(f: Finding) -> str:
    server = f.details.get("server", "MYSQL_SERVER")
    return f'''\
# Restrict to TLS 1.2 / 1.3 (CIS 4.4.2)
resource "azurerm_mysql_flexible_server_configuration" "{_safe(server)}_tls_version" {{
  name                = "tls_version"
  resource_group_name = "RESOURCE_GROUP"
  server_name         = azurerm_mysql_flexible_server.{_safe(server)}.name
  value               = "TLSv1.2,TLSv1.3"
}}'''


@_tf("azure-mysql-audit-log")
def _tf_az_mysql_audit_log(f: Finding) -> str:
    server = f.details.get("server", "MYSQL_SERVER")
    return f'''\
# Enable audit logging (CIS 4.4.3)
resource "azurerm_mysql_flexible_server_configuration" "{_safe(server)}_audit" {{
  name                = "audit_log_enabled"
  resource_group_name = "RESOURCE_GROUP"
  server_name         = azurerm_mysql_flexible_server.{_safe(server)}.name
  value               = "ON"
}}'''


# ----- Cosmos DB -----


@_tf("azure-cosmos-disable-local-auth")
def _tf_az_cosmos_local_auth(f: Finding) -> str:
    name = f.details.get("account", "COSMOS_ACCOUNT")
    return f'''\
resource "azurerm_cosmosdb_account" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Force Entra ID-only access (CIS 4.5.1)
  local_authentication_disabled = true
}}'''


@_tf("azure-cosmos-public-access")
def _tf_az_cosmos_public(f: Finding) -> str:
    name = f.details.get("account", "COSMOS_ACCOUNT")
    return f'''\
resource "azurerm_cosmosdb_account" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Disable public network access (CIS 4.5.2)
  public_network_access_enabled = false
  is_virtual_network_filter_enabled = true
}}'''


@_tf("azure-cosmos-firewall")
def _tf_az_cosmos_firewall(f: Finding) -> str:
    name = f.details.get("account", "COSMOS_ACCOUNT")
    return f'''\
resource "azurerm_cosmosdb_account" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Restrict network access — explicit IP / VNet rules (CIS 4.5.3)
  is_virtual_network_filter_enabled = true
  ip_range_filter                   = ["198.51.100.0/24"]  # replace with trusted CIDRs

  virtual_network_rule {{
    id                                   = "SUBNET_ID"
    ignore_missing_vnet_service_endpoint = false
  }}
}}'''


# ----- App Service -----


@_tf("azure-appservice-https-only")
def _tf_az_appsvc_https(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Enforce HTTPS-only (CIS 9.2)
  https_only = true
}}'''


@_tf("azure-appservice-min-tls")
def _tf_az_appsvc_min_tls(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  site_config {{
    # Enforce TLS 1.2+ (CIS 9.3)
    minimum_tls_version     = "1.2"
    scm_minimum_tls_version = "1.2"
  }}
}}'''


@_tf("azure-appservice-ftps")
def _tf_az_appsvc_ftps(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  site_config {{
    # Block plain FTP (CIS 9.10)
    ftps_state = "Disabled"  # or "FtpsOnly" if FTPS uploads are required
  }}
}}'''


@_tf("azure-appservice-remote-debug")
def _tf_az_appsvc_remote_debug(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  site_config {{
    # Disable remote debugging in production (CIS 9.5)
    remote_debugging_enabled = false
  }}
}}'''


@_tf("azure-appservice-managed-identity")
def _tf_az_appsvc_msi(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Use managed identity instead of stored credentials (CIS 9.11)
  identity {{
    type = "SystemAssigned"
  }}
}}

# Then grant the identity access to the resources it needs:
resource "azurerm_role_assignment" "{_safe(name)}_kv_access" {{
  scope                = "KEY_VAULT_ID"
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_web_app.{_safe(name)}.identity[0].principal_id
}}'''


# ----- Recovery Services Vault -----


@_tf("azure-rsv-soft-delete")
def _tf_az_rsv_soft_delete(f: Finding) -> str:
    name = f.details.get("vault", "RSV")
    return f'''\
resource "azurerm_recovery_services_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Enable irreversible soft delete (MCSB BR-2)
  soft_delete_enabled = true
}}'''


@_tf("azure-rsv-immutability")
def _tf_az_rsv_immutability(f: Finding) -> str:
    name = f.details.get("vault", "RSV")
    return f'''\
resource "azurerm_recovery_services_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Enable immutability and lock it (MCSB BR-2.3)
  immutability = "Locked"  # WARNING: irreversible once Locked
}}'''


@_tf("azure-rsv-redundancy")
def _tf_az_rsv_redundancy(f: Finding) -> str:
    name = f.details.get("vault", "RSV")
    return f'''\
resource "azurerm_recovery_services_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Geo-redundant storage (MCSB BR-2)
  storage_mode_type            = "GeoRedundant"
  cross_region_restore_enabled = true
}}'''


# ----- Networking / Monitoring -----


@_tf("azure-vnet-flow-logs-modern")
def _tf_az_vnet_flow_logs(f: Finding) -> str:
    return '''\
# VNet flow logs — successor to NSG flow logs (CIS 6.4)
resource "azurerm_network_watcher_flow_log" "vnet_flow" {
  network_watcher_name = "NetworkWatcher_LOCATION"
  resource_group_name  = "NetworkWatcherRG"
  name                 = "vnet-flow-log"

  target_resource_id = azurerm_virtual_network.main.id
  storage_account_id = azurerm_storage_account.flowlogs.id
  enabled            = true

  retention_policy {
    enabled = true
    days    = 90
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.main.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.main.location
    workspace_resource_id = azurerm_log_analytics_workspace.main.id
    interval_in_minutes   = 10
  }
}'''


@_tf("azure-network-watcher-coverage")
def _tf_az_network_watcher(f: Finding) -> str:
    missing = f.details.get("missing_regions", ["LOCATION"])
    blocks = []
    for r in missing[:5]:
        safe = _safe(r)
        blocks.append(
            f'''resource "azurerm_network_watcher" "{safe}" {{
  name                = "NetworkWatcher_{r}"
  location            = "{r}"
  resource_group_name = "NetworkWatcherRG"
}}'''
        )
    return "\n\n".join(blocks)


@_tf("azure-defender-per-plan")
def _tf_az_defender_per_plan(f: Finding) -> str:
    disabled = f.details.get("disabled", [])
    plans = [d.get("plan") if isinstance(d, dict) else d for d in disabled[:8]]
    if not plans:
        plans = ["VirtualMachines", "StorageAccounts", "KeyVaults", "Containers", "Arm"]
    blocks = []
    for plan in plans:
        blocks.append(
            f'''resource "azurerm_security_center_subscription_pricing" "{_safe(plan).lower()}" {{
  tier          = "Standard"
  resource_type = "{plan}"
}}'''
        )
    return "\n\n".join(blocks)


@_tf("azure-activity-log-alerts")
def _tf_az_activity_alerts(f: Finding) -> str:
    return '''\
# CIS 5.2.x — alert on critical control-plane changes
locals {
  critical_operations = [
    "Microsoft.Network/networkSecurityGroups/write",
    "Microsoft.Network/networkSecurityGroups/delete",
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.Network/networkSecurityGroups/securityRules/delete",
    "Microsoft.Sql/servers/firewallRules/write",
    "Microsoft.Authorization/policyAssignments/write",
    "Microsoft.Authorization/policyAssignments/delete",
    "Microsoft.KeyVault/vaults/write",
    "Microsoft.KeyVault/vaults/delete",
  ]
}

resource "azurerm_monitor_action_group" "secops" {
  name                = "secops-page"
  resource_group_name = "monitoring"
  short_name          = "secops"

  email_receiver {
    name          = "secops"
    email_address = "secops@example.com"
  }
}

resource "azurerm_monitor_activity_log_alert" "critical_changes" {
  for_each            = toset(local.critical_operations)
  name                = "alert-${replace(each.key, "/", "-")}"
  resource_group_name = "monitoring"
  scopes              = [data.azurerm_subscription.current.id]
  description         = "CIS 5.2.x — control-plane change alert"

  criteria {
    category       = "Administrative"
    operation_name = each.key
  }

  action {
    action_group_id = azurerm_monitor_action_group.secops.id
  }
}'''


# ----- Governance -----


@_tf("azure-resource-locks")
def _tf_az_resource_locks(f: Finding) -> str:
    rg = f.details.get("resource_group", "RESOURCE_GROUP")
    return f'''\
resource "azurerm_management_lock" "{_safe(rg)}_protect" {{
  name       = "protect-{rg}"
  scope      = "/subscriptions/SUBSCRIPTION_ID/resourceGroups/{rg}"
  lock_level = "CanNotDelete"
  notes      = "Protects sensitive resources (Key Vault / RSV / Log Analytics) from accidental deletion."
}}'''


@_tf("azure-required-tags")
def _tf_az_required_tags(f: Finding) -> str:
    return '''\
# Built-in policy: 'Require a tag and its value on resource groups'
data "azurerm_policy_definition" "require_tag" {
  display_name = "Require a tag and its value on resource groups"
}

resource "azurerm_subscription_policy_assignment" "require_owner_tag" {
  name                 = "require-owner-tag"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = data.azurerm_policy_definition.require_tag.id

  parameters = jsonencode({
    tagName  = { value = "owner" }
    tagValue = { value = "REQUIRED_VALUE" }
  })
}

resource "azurerm_subscription_policy_assignment" "require_env_tag" {
  name                 = "require-environment-tag"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = data.azurerm_policy_definition.require_tag.id

  parameters = jsonencode({
    tagName  = { value = "environment" }
    tagValue = { value = "production" }
  })
}'''


@_tf("azure-security-initiative")
def _tf_az_security_initiative(f: Finding) -> str:
    return '''\
# Assign the Microsoft Cloud Security Benchmark initiative (CIS 2.x)
data "azurerm_policy_set_definition" "mcsb" {
  display_name = "Microsoft cloud security benchmark"
}

resource "azurerm_subscription_policy_assignment" "mcsb" {
  name                 = "mcsb-baseline"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = data.azurerm_policy_set_definition.mcsb.id
  display_name         = "Microsoft Cloud Security Benchmark"
  description          = "Continuous compliance against the MCSB."
}'''


# ---------------------------------------------------------------------------
# Explanation and steps registry
# ---------------------------------------------------------------------------

EXPLANATIONS: dict[str, dict] = {
    "iam-password-policy": {
        "explanation": "Your AWS password policy is like the rules for building keys to your office. Right now, the rules are too lax — allowing short, simple passwords that are easy to guess. An attacker who cracks one password gets into your AWS console.",
        "steps": [
            "Go to IAM > Account settings > Password policy in the AWS Console",
            "Set minimum length to 14 characters",
            "Require uppercase, lowercase, numbers, AND symbols",
            "Set password expiration to 90 days",
            "Set password reuse prevention to 12",
            "Or apply the Terraform template below",
        ],
        "effort": "quick",
    },
    "iam-user-mfa": {
        "explanation": "Multi-factor authentication (MFA) is a second lock on the door. Even if someone steals a password, they can't get in without the second factor (usually a phone app). Without MFA, a single leaked password means full account access.",
        "steps": [
            "Log into the AWS Console as the user (or an admin)",
            "Go to IAM > Users > select the user > Security credentials",
            "Click 'Assign MFA device'",
            "Choose 'Authenticator app' and scan the QR code",
            "Enter two consecutive codes to activate",
        ],
        "effort": "quick",
    },
    "iam-root-mfa": {
        "explanation": "The root account is the master key to your entire AWS account. If compromised without MFA, an attacker has unrestricted access to everything — they could delete all your data, spin up expensive resources, or lock you out entirely.",
        "steps": [
            "Sign in as root (email + password) at https://console.aws.amazon.com/",
            "Go to Security credentials in the top-right dropdown",
            "Assign an MFA device — hardware key is ideal, authenticator app is acceptable",
            "Store backup codes securely",
        ],
        "effort": "quick",
    },
    "iam-no-direct-policies": {
        "explanation": "Attaching policies directly to users is like giving each employee a unique set of keys instead of a role-based keycard. It becomes unmanageable — when someone changes roles, you have to update each user individually. Groups make access easy to audit and update.",
        "steps": [
            "Create an IAM group for the user's role (e.g., 'developers', 'ops')",
            "Attach the necessary policies to the group",
            "Add the user to the group",
            "Remove the direct policy attachments from the user",
        ],
        "effort": "quick",
    },
    "iam-overprivileged-user": {
        "explanation": "Giving a user AdministratorAccess is like giving an intern the CEO's master key. If their credentials are compromised, the attacker gets unlimited access. The principle of least privilege means each person gets only the access they actually need.",
        "steps": [
            "Identify what the user actually needs to do (which services, which actions)",
            "Create a scoped IAM policy with only those permissions",
            "Attach the scoped policy to a group",
            "Remove AdministratorAccess",
            "Test that the user can still do their work",
        ],
        "effort": "moderate",
    },
    "sg-no-unrestricted-ingress": {
        "explanation": "A security group open to 0.0.0.0/0 means anyone on the internet can reach that port. For SSH or RDP, this means anyone can try to brute-force their way in. For databases, it means your data could be directly exposed.",
        "steps": [
            "Identify who actually needs access to this resource",
            "Find your office/VPN IP address (curl ifconfig.me)",
            "Update the security group to only allow that IP range",
            "If the SG is unused, check for attached resources and delete it",
        ],
        "effort": "quick",
    },
    "vpc-flow-logs-enabled": {
        "explanation": "VPC flow logs are like security cameras for your network. Without them, if someone breaks in, you have no way to see what traffic came and went. They're essential for incident investigation and audit trail.",
        "steps": [
            "Go to VPC > Your VPCs in the AWS Console",
            "Select the VPC and click 'Flow logs' tab",
            "Create flow log: ALL traffic, send to CloudWatch Logs",
            "Set retention to 90 days minimum",
            "Or apply the Terraform template below",
        ],
        "effort": "quick",
    },
    "s3-versioning": {
        "explanation": "Without versioning, if someone accidentally deletes a file or overwrites it with bad data, it's gone forever. Versioning keeps a history of every change, letting you recover from accidents or ransomware.",
        "steps": [
            "Go to S3 > select the bucket > Properties tab",
            "Under Bucket Versioning, click Edit and enable it",
            "Consider adding a lifecycle rule to expire old versions after 90 days to control costs",
        ],
        "effort": "quick",
    },
    "s3-ssl-only": {
        "explanation": "Without an SSL-only policy, data can be sent to or from your S3 bucket over unencrypted HTTP. This means anyone monitoring the network could read your data in transit — like sending a postcard instead of a sealed envelope.",
        "steps": [
            "Go to S3 > select the bucket > Permissions > Bucket policy",
            "Add a policy that denies all requests where aws:SecureTransport is false",
            "Or apply the Terraform template below",
        ],
        "effort": "quick",
    },
    "s3-encryption-at-rest": {
        "explanation": "Encryption at rest means your data is scrambled on disk. If someone steals the physical drive or gets unauthorized access to the storage layer, they can't read anything without the encryption key.",
        "steps": [
            "Go to S3 > select the bucket > Properties tab",
            "Under Default encryption, enable SSE-KMS (preferred) or SSE-S3",
            "This only affects new objects — existing objects keep their current encryption",
        ],
        "effort": "quick",
    },
    "s3-public-access-block": {
        "explanation": "The public access block is a safety net that prevents anyone from accidentally making your bucket or objects public. Without it, a single misconfigured policy or ACL could expose your data to the entire internet.",
        "steps": [
            "Go to S3 > select the bucket > Permissions",
            "Under 'Block public access', click Edit",
            "Enable all four settings",
            "Click Save changes",
        ],
        "effort": "quick",
    },
    "sg-default-restricted": {
        "explanation": "Default security groups often have permissive rules left over from initial setup. Any resource that doesn't explicitly specify a security group will use the default — meaning those leftover rules apply unexpectedly.",
        "steps": [
            "Go to VPC > Security Groups in the AWS Console",
            "Find the default security group for each VPC",
            "Remove all inbound rules (leave outbound as-is if needed)",
            "Ensure all resources use custom security groups instead",
        ],
        "effort": "quick",
    },
    "iam-access-key-rotation": {
        "explanation": "Access keys are like passwords for programmatic access. The longer they exist, the more likely they've been accidentally committed to a repo, shared in a message, or logged somewhere insecure. Regular rotation limits the damage window.",
        "steps": [
            "Create a new access key for the user",
            "Update all applications using the old key",
            "Verify everything works with the new key",
            "Deactivate the old key, wait a few days, then delete it",
        ],
        "effort": "moderate",
    },
    "iam-inactive-user": {
        "explanation": "Unused accounts are a risk because they can be compromised without anyone noticing. If an ex-employee's credentials are leaked or brute-forced, there's no active user to notice the suspicious activity.",
        "steps": [
            "Review whether the user still needs access",
            "If not: disable their console password and deactivate access keys",
            "After confirming no automated processes depend on the user, delete the account",
        ],
        "effort": "quick",
    },
    "guardduty-no-active-findings": {
        "explanation": "GuardDuty has found potential security threats in your environment. These could range from unusual API calls to possible credential compromise. Each finding needs to be investigated — some may be false positives, but some could be real attacks.",
        "steps": [
            "Go to GuardDuty > Findings in the AWS Console",
            "Review each active finding",
            "For each: determine if it's a real threat or expected behavior",
            "Archive false positives, remediate real threats",
            "Set up SNS notifications for future findings",
        ],
        "effort": "moderate",
    },
    # ----- CIS AWS v3.0 Stage 1-3 explanations -----
    "cloudtrail-kms-encryption": {
        "explanation": "CloudTrail logs are stored in S3 with default SSE-S3 encryption. Adding a customer-managed KMS key gives you key-level audit (every decrypt is logged), independent rotation, and the ability to revoke access without touching the bucket itself.",
        "steps": [
            "Create a KMS key with a policy allowing cloudtrail.amazonaws.com to encrypt",
            "Update the trail with --kms-key-id <key-arn>",
            "Verify CloudTrail can still write log files",
        ],
        "effort": "moderate",
    },
    "cloudtrail-log-validation": {
        "explanation": "Without log file validation, an attacker who gains write access to the log bucket can modify or delete CloudTrail logs without detection. Log validation creates a hash chain of digest files signed by AWS — tampering breaks the chain in a way that's verifiable.",
        "steps": [
            "aws cloudtrail update-trail --name <name> --enable-log-file-validation",
            "Use `aws cloudtrail validate-logs` periodically to verify the hash chain",
        ],
        "effort": "quick",
    },
    "cloudtrail-s3-object-lock": {
        "explanation": "Object Lock with COMPLIANCE mode prevents anyone — including the root user — from deleting CloudTrail log objects before retention expires. It's the only AWS-side control that defeats a malicious admin or compromised root credential trying to wipe audit evidence.",
        "steps": [
            "Object Lock can only be enabled at bucket creation",
            "Create a new bucket with object_lock_enabled + versioning",
            "Migrate logs and update the trail to point at the new bucket",
        ],
        "effort": "significant",
    },
    "security-hub-enabled": {
        "explanation": "Security Hub aggregates findings from GuardDuty, Inspector, Macie, Access Analyzer, Config, and the AWS Foundational + CIS standards into one console. Without it, security findings are scattered across per-service consoles with no unified prioritization or auto-remediation hook.",
        "steps": [
            "Enable Security Hub in your primary operating region",
            "Subscribe to AWS Foundational Security Best Practices and CIS AWS Foundations Benchmark v3.0.0",
            "Configure SNS or EventBridge for high-severity findings",
        ],
        "effort": "moderate",
    },
    "iam-access-analyzer": {
        "explanation": "IAM Access Analyzer continuously monitors IAM resource policies (S3 buckets, KMS keys, IAM roles, Lambda, Secrets Manager) for unintended external access. It catches S3 buckets shared publicly, KMS keys assumable cross-account, and roles trusting unknown principals.",
        "steps": [
            "aws accessanalyzer create-analyzer --analyzer-name default --type ACCOUNT",
            "Or use --type ORGANIZATION from the management account for org-wide coverage",
            "Review findings in the IAM > Access analyzer console",
        ],
        "effort": "quick",
    },
    "efs-encryption": {
        "explanation": "EFS encryption can only be enabled at creation. An unencrypted EFS file system stores data in clear on AWS disks — which means a snapshot leak, account compromise, or misconfigured backup gives an attacker the raw bytes.",
        "steps": [
            "Create a new encrypted EFS file system",
            "Use AWS DataSync or a temporary EC2 instance with rsync to copy data",
            "Cut over consumers (Lambda, ECS, EC2) and delete the old file system",
        ],
        "effort": "significant",
    },
    "sns-encryption": {
        "explanation": "SNS messages may carry sensitive payloads (alerts, notifications, webhook payloads). Without KMS encryption, the message body sits in unencrypted SNS storage between publish and delivery.",
        "steps": [
            "aws sns set-topic-attributes --topic-arn <arn> --attribute-name KmsMasterKeyId --attribute-value alias/aws/sns",
        ],
        "effort": "quick",
    },
    "sqs-encryption": {
        "explanation": "SQS messages sit in queue storage between enqueue and consume. Without encryption, that storage is unencrypted disk on AWS infrastructure. SqsManagedSseEnabled adds encryption with no KMS cost.",
        "steps": [
            "aws sqs set-queue-attributes --queue-url <url> --attributes SqsManagedSseEnabled=true",
        ],
        "effort": "quick",
    },
    "secrets-manager-rotation": {
        "explanation": "Secrets without automatic rotation accumulate risk — credentials cycle outside any policy, stale secrets persist after staff turnover, and a leaked secret stays valid until someone notices. Lambda-backed rotation lets you set a 30-90 day schedule.",
        "steps": [
            "Pick or write a Lambda rotation function (AWS provides templates for RDS, Redshift, DocumentDB)",
            "Attach it to each secret with a 30-day rotation schedule",
            "Monitor CloudWatch alarms for rotation failures",
        ],
        "effort": "moderate",
    },
    "acm-expiring-certs": {
        "explanation": "Expired certificates break TLS for whatever they're attached to (CloudFront, ALB, API Gateway). DNS-validated public certs in ACM auto-renew ~60 days before expiry; imported and email-validated certs do not.",
        "steps": [
            "Switch any email-validated certs to DNS validation",
            "For imported certs, replace them or migrate to ACM-issued",
            "Set up CloudWatch alarms on AWS/CertificateManager > DaysToExpiry < 30",
        ],
        "effort": "moderate",
    },
    "elb-listener-tls": {
        "explanation": "HTTP listeners send credentials and session cookies in clear text. ELBSecurityPolicy-TLS-1-0/1.1 allows protocols vulnerable to BEAST/POODLE. Modern policies pin TLS 1.2+ with strong ciphers only.",
        "steps": [
            "Add HTTPS listeners with ELBSecurityPolicy-TLS13-1-2-2021-06",
            "Convert HTTP listeners to redirect-to-HTTPS",
        ],
        "effort": "quick",
    },
    "elb-access-logs": {
        "explanation": "Without access logs, you can't reconstruct request patterns during an incident — no source IPs, no paths, no user agents. SOC 2 expects request-level audit trail for production HTTP services.",
        "steps": [
            "Create an S3 bucket with the AWS-managed bucket policy for ELB log delivery",
            "Enable access_logs.s3.enabled and point at the bucket",
        ],
        "effort": "quick",
    },
    "elb-drop-invalid-headers": {
        "explanation": "Headers with invalid characters can be used for HTTP request smuggling and header-injection attacks against the backend. ALB has a one-flag fix to drop them at the edge.",
        "steps": [
            "Set routing.http.drop_invalid_header_fields.enabled = true on the ALB attributes",
        ],
        "effort": "quick",
    },
    "rds-iam-auth": {
        "explanation": "Static DB passwords need rotation, vaulting, and access reviews. IAM database authentication uses short-lived tokens tied to an IAM identity that's already governed by your IAM controls — no password to leak.",
        "steps": [
            "Enable iam_database_authentication on the instance",
            "Create a DB user mapped to an IAM role",
            "Update apps to call rds.generate-db-auth-token instead of passing a password",
        ],
        "effort": "moderate",
    },
    "rds-deletion-protection": {
        "explanation": "DeletionProtection prevents accidental DELETE — a misclick, a careless terraform destroy, or a compromised admin can otherwise wipe the database in seconds. Final snapshots help but add recovery time.",
        "steps": [
            "aws rds modify-db-instance --db-instance-identifier <id> --deletion-protection --apply-immediately",
        ],
        "effort": "quick",
    },
    "rds-pi-kms": {
        "explanation": "Performance Insights captures query text including bind values. If queries contain PII or credentials (which they often do), PI data needs the same protection as the underlying database.",
        "steps": [
            "Create a CMK for PI",
            "aws rds modify-db-instance --performance-insights-kms-key-id <key-arn>",
        ],
        "effort": "quick",
    },
    "rds-auto-minor-upgrade": {
        "explanation": "Without auto minor upgrades, the instance won't receive security patches without a manual operation — and CVEs in DB engines are common. Auto upgrades happen during the maintenance window with zero data risk.",
        "steps": [
            "aws rds modify-db-instance --db-instance-identifier <id> --auto-minor-version-upgrade --apply-immediately",
        ],
        "effort": "quick",
    },
    "dynamodb-pitr": {
        "explanation": "Point-in-Time Recovery lets you restore a DynamoDB table to any second within the last 35 days. Without it, accidental deletes/overwrites are unrecoverable — and there's no CLI command for 'undo'.",
        "steps": [
            "aws dynamodb update-continuous-backups --table-name <name> --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true",
        ],
        "effort": "quick",
    },
    "dynamodb-kms": {
        "explanation": "DynamoDB tables are encrypted by default with an AWS-owned key — you can't audit decrypt calls and you can't revoke access independently. A customer-managed KMS key gives you key-level audit and rotation.",
        "steps": [
            "Create a CMK with rotation enabled",
            "aws dynamodb update-table --table-name <name> --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=<key-arn>",
        ],
        "effort": "quick",
    },
    "lambda-runtime-eol": {
        "explanation": "Functions on deprecated Lambda runtimes stop receiving security patches. AWS eventually blocks invocations after the deprecation deadline — so a function on python3.8 won't just be insecure, it'll stop running.",
        "steps": [
            "Identify each function on a deprecated runtime",
            "Bump to a current runtime (python3.12, nodejs20.x, java21, dotnet8)",
            "Test for breaking changes in dependencies, then redeploy",
        ],
        "effort": "moderate",
    },
    "lambda-env-kms": {
        "explanation": "Lambda environment variables are encrypted by default with the Lambda service key. A customer-managed KMS key gives you key-level audit and the ability to rotate the encryption key independently.",
        "steps": [
            "Create a CMK",
            "aws lambda update-function-configuration --function-name <name> --kms-key-arn <key-arn>",
        ],
        "effort": "quick",
    },
    "lambda-dlq": {
        "explanation": "Async Lambda invocation failures are silently retried then dropped. With no DLQ or destination, you lose the failed payload entirely — no debugging trail, no replay capability.",
        "steps": [
            "Create an SQS queue or SNS topic to act as the DLQ",
            "Attach via DeadLetterConfig.TargetArn or use Lambda Destinations for richer routing",
        ],
        "effort": "quick",
    },
    "lambda-code-signing": {
        "explanation": "Code signing prevents an attacker who compromises a CI pipeline from deploying tampered code — only artifacts signed by an approved Signer profile will deploy. It's the supply-chain control AWS-native equivalent of cosign.",
        "steps": [
            "Create an AWS Signer profile",
            "Define a code signing config that requires signed deployments",
            "Attach the config to each function via PutFunctionCodeSigningConfig",
        ],
        "effort": "moderate",
    },
    "apigw-logging": {
        "explanation": "Without execution logging, you cannot trace API request failures or correlate them with backend incidents. INFO level captures request/response metadata; ERROR level captures only failures.",
        "steps": [
            "Enable Execution logging at INFO level on each stage",
            "Enable Detailed CloudWatch metrics for the stage",
        ],
        "effort": "quick",
    },
    "apigw-waf": {
        "explanation": "API stages without WAF are exposed to OWASP Top 10, bot abuse, and credential stuffing. Even with auth, you need WAF for rate limiting and known-bad-input filtering.",
        "steps": [
            "Create a WAFv2 Web ACL with the AWS Managed Rules Common Rule Set",
            "Add the AWS Managed Rules Bot Control rule group",
            "wafv2:AssociateWebACL with each public API Gateway stage",
        ],
        "effort": "moderate",
    },
    "sfn-logging": {
        "explanation": "Step Functions logging level OFF means execution history is only available via the StartExecution API and is lost after a few weeks. ALL level + includeExecutionData captures every state transition for incident investigation.",
        "steps": [
            "Create a CloudWatch Log Group for Step Functions",
            "Update each state machine with logging configuration level=ALL",
        ],
        "effort": "quick",
    },
    "aws-backup-vault-lock": {
        "explanation": "Without Vault Lock in COMPLIANCE mode, an attacker (or compromised admin) with backup:DeleteRecoveryPoint can wipe every backup in the vault — defeating your entire DR plan. Vault Lock COMPLIANCE makes recovery points immutable until retention expires, even for the root user.",
        "steps": [
            "aws backup put-backup-vault-lock-configuration with --changeable-for-days 3 (after 3 days the lock is irreversible)",
            "Test that recovery points cannot be deleted before retention expires",
        ],
        "effort": "moderate",
    },
    "aws-backup-plans": {
        "explanation": "Backup vaults exist but no Backup plan schedules recovery points — meaning nothing is being backed up automatically. The vault is just an empty container.",
        "steps": [
            "Create a backup plan via the Backup console or CLI",
            "Use AWS-managed plans (Daily-35day, Monthly-1year) as a starting point",
            "Add a backup selection that targets resources with tag backup=true",
        ],
        "effort": "moderate",
    },
    "aws-vpc-endpoints": {
        "explanation": "Without VPC endpoints, EC2/ECS/EKS traffic to AWS services (S3, DynamoDB, KMS, Secrets Manager, ECR) traverses the public internet via NAT — adding NAT cost, latency, and exposure to internet-facing controls. Gateway endpoints (S3, DynamoDB) are free; interface endpoints are priced per AZ + per GB.",
        "steps": [
            "Create gateway endpoints for S3 and DynamoDB (free, no infra change)",
            "Create interface endpoints for KMS, Secrets Manager, SSM, ECR, Logs, STS",
            "Add SG rules allowing the VPC CIDR to reach the interface endpoint ENIs",
        ],
        "effort": "moderate",
    },
    "cwl-kms-encryption": {
        "explanation": "Application logs frequently contain credentials, PII, or session tokens. Log groups encrypted with the AWS-owned default key give you no key-level audit and no way to revoke decrypt access independently.",
        "steps": [
            "Create a KMS key with a policy allowing logs.<region>.amazonaws.com to encrypt",
            "aws logs associate-kms-key --log-group-name <name> --kms-key-id <key-arn>",
        ],
        "effort": "quick",
    },
    "cwl-retention": {
        "explanation": "Log groups with infinite retention accumulate cost indefinitely. Log groups with retention < 90 days lose audit evidence too fast for SOC 2 — you need at least 90 days to investigate incidents reported by customers.",
        "steps": [
            "aws logs put-retention-policy --log-group-name <name> --retention-in-days 90",
            "Use 180 / 365 days for compliance-critical groups (CloudTrail, Audit, Auth)",
        ],
        "effort": "quick",
    },
    "aws-org-scps": {
        "explanation": "Service Control Policies are the only AWS-side control that can prevent member accounts from disabling CloudTrail, leaving regions, or assuming risky roles. Without custom SCPs you have no org-wide guardrails.",
        "steps": [
            "Author SCPs that deny CloudTrail disable/delete, root account use, and resource creation outside approved regions",
            "Apply at OU level (test on a sandbox OU first)",
        ],
        "effort": "moderate",
    },
    "aws-tag-policy": {
        "explanation": "Without tag policies, resources are tagged inconsistently — making cost allocation, ownership tracking, and policy-based access control unreliable.",
        "steps": [
            "Define a tag policy enforcing 'owner' and 'environment' keys at the org root",
            "Attach to OUs and configure 'enforced for' on the resource types you care about",
        ],
        "effort": "moderate",
    },
    "aws-org-enabled": {
        "explanation": "Without AWS Organizations, you can't apply SCPs, enforce centralized logging, share resources via RAM, or use Backup / Tag policies that need org-level scope. Single-account setups don't scale beyond a small team.",
        "steps": [
            "Create an Organization from a dedicated management account",
            "Invite this account into it",
            "Enable ALL features (not just consolidated billing)",
        ],
        "effort": "moderate",
    },
    "aws-delegated-admin": {
        "explanation": "Security services should be delegated to a dedicated security account so the management account stays minimal-privilege and is rarely accessed. This is the AWS-recommended landing zone pattern.",
        "steps": [
            "Create a dedicated security/audit account",
            "register-delegated-administrator for securityhub, guardduty, config, backup, access-analyzer",
        ],
        "effort": "moderate",
    },
    "aws-backup-policy": {
        "explanation": "Without an org-level Backup policy, every member account needs its own backup plan defined manually — which scales badly and creates drift. Org policies enforce a baseline across every account automatically.",
        "steps": [
            "Define a backup policy via aws organizations create-policy --type BACKUP_POLICY",
            "Attach to OUs",
        ],
        "effort": "moderate",
    },
    "aws-backup-vault-cmk": {
        "explanation": "AWS Backup vaults encrypted with the AWS-managed key give you no key-level audit and no way to revoke decrypt independently. A customer-managed KMS key with rotation closes both gaps.",
        "steps": [
            "Recreate the vault with --encryption-key-arn pointing to a customer-managed KMS key",
        ],
        "effort": "moderate",
    },
    "aws-backup-vault-exists": {
        "explanation": "Without an AWS Backup vault, you have no centralized place to manage recovery points across services. Each service's native backups (RDS snapshots, EBS snapshots, EFS recovery points) live independently with separate retention.",
        "steps": [
            "Create a Backup vault with KMS encryption",
            "Create a Backup plan",
            "Add resource selections via tags",
        ],
        "effort": "moderate",
    },
    "docdb-encryption": {
        "explanation": "DocumentDB encryption can only be enabled at cluster creation. An unencrypted cluster means data is stored in clear on AWS disks.",
        "steps": [
            "Snapshot the cluster",
            "Restore the snapshot with --storage-encrypted",
            "Cut over and delete the old cluster",
        ],
        "effort": "significant",
    },
    "docdb-audit-logs": {
        "explanation": "DocumentDB audit logs capture authentication, DDL, and DML events. Without audit log export, anomalous queries leave no trace.",
        "steps": [
            "aws docdb modify-db-cluster --cloudwatch-logs-export-configuration EnableLogTypes=audit",
        ],
        "effort": "quick",
    },
    # ----- Azure CIS v3.0 explanations -----
    "azure-storage-shared-key-access": {
        "explanation": "Storage account keys are like a master password — anyone holding the key bypasses Entra ID identity, RBAC, Conditional Access, and audit attribution. Disable shared-key access so every read/write must come through an authenticated Entra ID identity.",
        "steps": [
            "Audit which apps still use the storage account key (search app settings, env vars, secrets)",
            "Migrate each consumer to managed identity + Entra ID auth",
            "Set allowSharedKeyAccess = false on the storage account",
            "Confirm via the audit logs that no SharedKey requests remain",
        ],
        "effort": "moderate",
    },
    "azure-storage-cross-tenant-replication": {
        "explanation": "Object replication across tenants is a stealth exfiltration channel — a user with replication permissions can configure your storage to mirror blobs into a foreign Entra ID tenant, and the data leaves without triggering normal data-movement alerts.",
        "steps": [
            "Set allowCrossTenantReplication = false on every production storage account",
            "Audit existing object replication policies for foreign-tenant targets",
        ],
        "effort": "quick",
    },
    "azure-storage-network-default-deny": {
        "explanation": "By default, a storage account is reachable from anywhere on the internet — a leaked SAS or stolen identity becomes immediately exploitable. Default-Deny + explicit allowlist limits the blast radius to known networks.",
        "steps": [
            "Set network rules default action to Deny",
            "Add explicit IP rules for trusted office/VPN ranges",
            "Add VNet subnet rules for internal apps",
            "Allow only AzureServices, Logging, Metrics in the bypass list",
        ],
        "effort": "quick",
    },
    "azure-keyvault-rbac-mode": {
        "explanation": "Legacy Key Vault access policies are a parallel permission system that doesn't integrate with PIM, Conditional Access, or central access reviews. Switching to RBAC mode makes Key Vault permissions visible alongside every other Azure resource and lets you use Key Vault Administrator / Secrets User / Crypto User roles.",
        "steps": [
            "Document who currently has access via the access policy list",
            "Set enable_rbac_authorization = true on the vault",
            "Create RBAC role assignments mirroring the previous access policy grants",
            "Remove the legacy access_policy blocks",
        ],
        "effort": "moderate",
    },
    "azure-keyvault-public-access": {
        "explanation": "A Key Vault reachable from the public internet means a stolen workload identity can be used from anywhere — there's no network boundary on top of the identity check. Combined with token theft, this is the shortest path from compromised credential to leaked secrets.",
        "steps": [
            "Set publicNetworkAccess = Disabled on the vault",
            "Set network ACL default action to Deny",
            "Create a Private Endpoint in the VNet that needs vault access",
            "Add a Private DNS zone (privatelink.vaultcore.azure.net) linked to the VNet",
        ],
        "effort": "moderate",
    },
    "azure-sql-min-tls": {
        "explanation": "TLS 1.0 and 1.1 have known cryptographic weaknesses (BEAST, POODLE) and are deprecated by every major security framework. SQL Server's minimal_tls_version controls what the server will accept on the wire.",
        "steps": [
            "Set minimal_tls_version = '1.2' on every SQL server",
            "Verify clients are using a recent driver that supports TLS 1.2+",
        ],
        "effort": "quick",
    },
    "azure-sql-auditing": {
        "explanation": "Server-level auditing captures every login, query, and DDL change. Without it, anomalous queries and brute-force attempts leave no record — you have no incident-response trail and no detection signal for SQL injection or data exfil.",
        "steps": [
            "Create or pick a Log Analytics workspace for security data",
            "Enable extended auditing on each SQL server pointing at the workspace",
            "Set retention to ≥ 90 days (365 ideal)",
        ],
        "effort": "moderate",
    },
    "azure-sql-entra-admin": {
        "explanation": "Without an Entra ID admin, the only way to manage SQL Server is SQL authentication — meaning no MFA, no Conditional Access, and credentials cycling outside identity governance. An Entra group as admin lets you use PIM for break-glass.",
        "steps": [
            "Create an Entra group like 'sql-admins' with one or two members",
            "Set the group as the SQL server's Entra admin",
            "Enable azuread_authentication_only = true to disable mixed-mode",
        ],
        "effort": "quick",
    },
    "azure-postgres-secure-transport": {
        "explanation": "PostgreSQL Flexible Server lets clients connect over plaintext unless require_secure_transport is ON. Plaintext means anyone on the network path can read every query and credential.",
        "steps": [
            "Set require_secure_transport = ON via az postgres flexible-server parameter set",
            "Verify clients use SSL connection strings",
        ],
        "effort": "quick",
    },
    "azure-postgres-log-settings": {
        "explanation": "Connection logging is the audit trail for every authentication attempt and session. Without log_connections / log_disconnections / log_checkpoints, brute-force attempts and anomalous session patterns are invisible.",
        "steps": [
            "Set each parameter to ON via az postgres flexible-server parameter set",
            "Forward server logs to Log Analytics via diagnostic settings",
        ],
        "effort": "quick",
    },
    "azure-mysql-secure-transport": {
        "explanation": "Same as PostgreSQL: MySQL Flexible Server can accept plaintext connections unless require_secure_transport = ON. Force TLS server-side so a misconfigured client can't downgrade.",
        "steps": [
            "az mysql flexible-server parameter set --name require_secure_transport --value ON",
        ],
        "effort": "quick",
    },
    "azure-mysql-tls-version": {
        "explanation": "MySQL accepts older TLS versions by default. Restrict to TLS 1.2 / 1.3 only.",
        "steps": [
            "az mysql flexible-server parameter set --name tls_version --value 'TLSv1.2,TLSv1.3'",
        ],
        "effort": "quick",
    },
    "azure-mysql-audit-log": {
        "explanation": "MySQL audit log captures connection events and DDL/DML statements for incident investigation. It's disabled by default.",
        "steps": [
            "Enable audit_log_enabled = ON",
            "Configure audit_log_events to include CONNECTION, ADMIN, DDL at minimum",
        ],
        "effort": "quick",
    },
    "azure-cosmos-disable-local-auth": {
        "explanation": "Cosmos DB account keys are full-access bearer tokens that bypass Entra ID, RBAC, and audit attribution. Disabling local auth forces every operation through Entra ID identity, which is logged and CA-controlled.",
        "steps": [
            "Migrate apps to use DefaultAzureCredential / managed identity",
            "Grant the identity Cosmos DB Built-in Data Reader/Contributor RBAC roles",
            "Set disableLocalAuth = true on the account",
        ],
        "effort": "moderate",
    },
    "azure-cosmos-public-access": {
        "explanation": "A Cosmos account with public network access enabled is reachable from anywhere on the internet, so any leaked identity becomes immediately exploitable.",
        "steps": [
            "Set publicNetworkAccess = Disabled",
            "Create Private Endpoint for the SQL/Mongo/Cassandra subresource the app uses",
        ],
        "effort": "moderate",
    },
    "azure-cosmos-firewall": {
        "explanation": "An empty IP firewall with public access enabled means any IP can attempt to authenticate — combined with shared keys this is a direct exfiltration path.",
        "steps": [
            "Add explicit IP rules for trusted ranges, or",
            "Add VNet rules for internal apps, or",
            "Disable public network access entirely and use Private Endpoints",
        ],
        "effort": "quick",
    },
    "azure-appservice-https-only": {
        "explanation": "An App Service that accepts HTTP serves credentials and session cookies in plaintext over the wire — anyone on the network path can capture them.",
        "steps": [
            "az webapp update --https-only true -g <rg> -n <app>",
        ],
        "effort": "quick",
    },
    "azure-appservice-min-tls": {
        "explanation": "App Service defaults to TLS 1.0 in older deployments. Force TLS 1.2+ both for the app endpoint and the Kudu (SCM) deployment endpoint.",
        "steps": [
            "az webapp config set --min-tls-version 1.2 -g <rg> -n <app>",
            "Also update scm_minimum_tls_version via ARM/Terraform",
        ],
        "effort": "quick",
    },
    "azure-appservice-ftps": {
        "explanation": "Plain FTP transmits the deployment credential in clear text. Disable it entirely, or restrict to FTPS-only if FTPS uploads are required.",
        "steps": [
            "az webapp config set --ftps-state Disabled -g <rg> -n <app>",
        ],
        "effort": "quick",
    },
    "azure-appservice-remote-debug": {
        "explanation": "Remote debugging exposes a debug endpoint that lets developers attach Visual Studio to a running production process. It should only be on briefly during a debug session, never permanently.",
        "steps": [
            "az webapp config set --remote-debugging-enabled false -g <rg> -n <app>",
        ],
        "effort": "quick",
    },
    "azure-appservice-managed-identity": {
        "explanation": "Without a managed identity, the app must store credentials in app settings or config files — which then need rotation, vaulting, and access reviews. A managed identity is identity-bound to the app instance, with no secrets to leak.",
        "steps": [
            "az webapp identity assign -g <rg> -n <app>",
            "Grant the identity RBAC on the resources it needs (Key Vault, Storage, SQL, etc.)",
            "Remove static credentials from app settings",
        ],
        "effort": "moderate",
    },
    "azure-rsv-soft-delete": {
        "explanation": "Without soft delete, an attacker (or careless admin) with vault access can delete recovery points and there's no recovery — your backups are gone. Soft delete keeps them in a recoverable state for 14 days, AlwaysON makes the protection irreversible.",
        "steps": [
            "Set soft_delete_enabled = true on every Recovery Services Vault",
            "Set the soft delete state to AlwaysON via the portal for irreversibility",
        ],
        "effort": "quick",
    },
    "azure-rsv-immutability": {
        "explanation": "Immutable vaults prevent recovery points from being deleted before their retention expires — the only true protection against ransomware that targets backups. Locking the immutability setting makes the protection irreversible.",
        "steps": [
            "Enable immutability on the vault (Properties > Immutability)",
            "Test recovery on a non-production vault first",
            "Lock the setting once you're confident — this cannot be undone",
        ],
        "effort": "moderate",
    },
    "azure-rsv-redundancy": {
        "explanation": "Locally-redundant storage (LRS) means a regional outage destroys your backups along with your primary data. GRS / GZRS replicates backup data to a paired Azure region.",
        "steps": [
            "Set storage_mode_type = 'GeoRedundant' on the vault",
            "Note: redundancy can only be changed before any backup item is registered",
            "Enable cross_region_restore = true",
        ],
        "effort": "quick",
    },
    "azure-vnet-flow-logs-modern": {
        "explanation": "NSG flow logs are deprecated — no new ones can be created after June 2025, and all existing ones retire September 2027. VNet flow logs are the post-2025 successor and capture richer data including encrypted traffic patterns.",
        "steps": [
            "Create a Storage account in the same region as the VNet for flow log storage",
            "Configure VNet flow logs in Network Watcher targeting the VNet",
            "Set retention to ≥ 90 days",
            "Enable Traffic Analytics linked to a Log Analytics workspace",
        ],
        "effort": "moderate",
    },
    "azure-network-watcher-coverage": {
        "explanation": "Network Watcher is the per-region service that powers VNet flow logs, connection troubleshooter, and Traffic Analytics. Without it in a region, you can't capture flow logs for VNets in that region.",
        "steps": [
            "Create a Network Watcher resource in each region that hosts a VNet",
            "Network Watcher is normally auto-created — manual creation is only needed if it was deleted",
        ],
        "effort": "quick",
    },
    "azure-defender-per-plan": {
        "explanation": "Defender for Cloud charges per resource type ('plan'), and each plan covers a different attack surface — Defender for Servers detects malware on VMs, Defender for SQL detects SQL injection, Defender for Containers scans images, etc. Enabling only some plans leaves blind spots.",
        "steps": [
            "Identify which Defender plans are missing",
            "Enable each one via Defender for Cloud > Environment settings > Defender plans",
            "Set up email notifications for new alerts",
        ],
        "effort": "moderate",
    },
    "azure-activity-log-alerts": {
        "explanation": "CIS Azure 5.2.x requires real-time alerts on critical control-plane changes — NSG rule edits, SQL firewall changes, Policy assignment changes, Key Vault create/delete. Without these, security-relevant changes happen silently and only show up in retrospective audits.",
        "steps": [
            "Create an Action Group with email + SMS for SecOps",
            "Create one Activity Log alert per CIS-required operation",
            "Verify alerts trigger by making a test change",
        ],
        "effort": "moderate",
    },
    "azure-resource-locks": {
        "explanation": "A misclick in the Portal or a compromised admin can wipe an entire resource group containing your Key Vault, Recovery Services Vault, or log storage. CanNotDelete locks block deletion until the lock is explicitly removed — a small speed bump that prevents catastrophic mistakes.",
        "steps": [
            "Identify resource groups containing sensitive resources (KV, RSV, log Storage, Log Analytics)",
            "Apply a CanNotDelete lock to each",
            "Document the lock removal procedure for change windows",
        ],
        "effort": "quick",
    },
    "azure-required-tags": {
        "explanation": "Without owner / environment tags, incident response and access reviews are guesswork — you don't know who owns a resource or whether it's production. Azure Policy with deny effect prevents new resources from being created without the required tags.",
        "steps": [
            "Backfill missing tags on existing resource groups",
            "Assign the built-in 'Require a tag and its value on resource groups' policy",
            "Set the deny effect to enforce going forward",
        ],
        "effort": "moderate",
    },
    "azure-security-initiative": {
        "explanation": "The Microsoft Cloud Security Benchmark initiative is a pre-built bundle of security policies that maps to CIS, NIST, ISO, and PCI. Assigning it gives you a continuous compliance score in Defender for Cloud's Regulatory Compliance dashboard without writing a single policy.",
        "steps": [
            "Find the 'Microsoft cloud security benchmark' built-in initiative",
            "Assign it at the tenant root management group (or top-level MG)",
            "Review the compliance score in Defender for Cloud",
        ],
        "effort": "quick",
    },
}


def generate_remediation(finding: Finding) -> Remediation:
    """Generate a full remediation recommendation for a finding."""
    check_id = finding.check_id
    info = EXPLANATIONS.get(check_id, {})

    # Generate Terraform if available
    tf_generator = TERRAFORM_TEMPLATES.get(check_id)
    terraform = tf_generator(finding) if tf_generator else ""

    return Remediation(
        finding=finding,
        priority=SEVERITY_PRIORITY.get(finding.severity, 5),
        explanation=info.get("explanation", finding.description),
        steps=info.get("steps", [finding.remediation] if finding.remediation else []),
        terraform=terraform,
        effort=info.get("effort", "moderate"),
        category=finding.domain.value,
    )


def generate_all_remediations(findings: list[Finding]) -> list[Remediation]:
    """Generate remediations for all failing findings, sorted by priority."""
    failing = [f for f in findings if f.status in (ComplianceStatus.FAIL, ComplianceStatus.PARTIAL)]
    remediations = [generate_remediation(f) for f in failing]
    remediations.sort(key=lambda r: (r.priority, r.category))
    return remediations


def save_terraform_bundle(
    remediations: list[Remediation],
    output_path: Path | str = "data/remediation",
) -> Path:
    """Save all Terraform remediations as a single .tf file."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / "remediation.tf"

    blocks = []
    blocks.append("# Shasta Auto-Generated Remediation Terraform")
    blocks.append("# Review each resource before applying!\n")

    seen_check_ids = set()
    for r in remediations:
        if r.terraform and r.finding.check_id not in seen_check_ids:
            blocks.append(f"# --- {r.finding.title} ---")
            blocks.append(f"# SOC 2: {', '.join(r.finding.soc2_controls)}")
            blocks.append(f"# Severity: {r.finding.severity.value}")
            blocks.append(r.terraform)
            blocks.append("")
            seen_check_ids.add(r.finding.check_id)

    filepath.write_text("\n".join(blocks), encoding="utf-8")
    return filepath
