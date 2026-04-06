"""ISO 42001 (AI Management Systems) control framework definitions.

Maps Whitney AI checks to ISO/IEC 42001:2023 controls for AI management.
ISO 42001 provides requirements for establishing, implementing, maintaining,
and continually improving an AI management system (AIMS).

The standard covers:
  - Clauses 4-10: Management system requirements
  - Annex A: Reference control objectives and controls

For organizations deploying AI systems, Clauses 5-8 and Annex A are the focus.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ISO42001Control:
    """A single ISO 42001 control point."""

    id: str  # e.g., "AI-5.2"
    title: str
    description: str
    clause: str  # e.g., "5.2", "8.3", "A.5"
    check_ids: list[str] = field(default_factory=list)
    requires_policy: bool = False
    guidance: str = ""


# ---------------------------------------------------------------------------
# ISO 42001 Controls — AI Management System
# ---------------------------------------------------------------------------

ISO42001_CONTROLS: dict[str, ISO42001Control] = {
    # =========================================================================
    # Clauses 5-8 — Management System Requirements
    # =========================================================================
    "AI-5.2": ISO42001Control(
        id="AI-5.2",
        title="AI Policy",
        description=(
            "Top management shall establish an AI policy that is appropriate "
            "to the purpose of the organization, provides a framework for "
            "setting AI objectives, and includes a commitment to applicable "
            "requirements and continual improvement."
        ),
        clause="5.2",
        requires_policy=True,
        guidance=(
            "Requires a documented AI policy approved by leadership covering "
            "responsible AI use, ethical principles, and accountability. "
            "Generate with /policy-gen."
        ),
    ),
    "AI-6.1": ISO42001Control(
        id="AI-6.1",
        title="AI Risk Assessment",
        description=(
            "The organization shall define and apply an AI risk assessment "
            "process that identifies risks associated with AI systems, "
            "analyzes and evaluates those risks, and determines risk "
            "treatment."
        ),
        clause="6.1",
        requires_policy=True,
        guidance=(
            "Requires a risk classification engine and documented AI risk "
            "assessment process. Use the risk register workflow to classify "
            "AI systems by risk level and track treatment decisions."
        ),
    ),
    "AI-8.2": ISO42001Control(
        id="AI-8.2",
        title="AI System Impact Assessment",
        description=(
            "The organization shall conduct an AI system impact assessment "
            "to determine the potential impacts of AI systems on "
            "individuals, groups, and societies."
        ),
        clause="8.2",
        requires_policy=True,
        guidance=(
            "Requires architecture review documentation assessing societal, "
            "ethical, and individual impacts of AI systems. Document bias "
            "risks, fairness considerations, and affected stakeholders."
        ),
    ),
    "AI-8.3": ISO42001Control(
        id="AI-8.3",
        title="AI System Lifecycle",
        description=(
            "The organization shall manage the AI system lifecycle including "
            "design, development, deployment, operation, and "
            "decommissioning with appropriate controls at each stage."
        ),
        clause="8.3",
        check_ids=[
            "sagemaker-model-registry-access",
            "sagemaker-model-approval",
            "azure-ml-model-registration",
            "code-no-model-versioning",
        ],
        guidance=(
            "Models must be versioned, registered, and require approval "
            "before deployment. Use SageMaker Model Registry or Azure ML "
            "model registration with access controls."
        ),
    ),
    "AI-8.4": ISO42001Control(
        id="AI-8.4",
        title="Data for AI Systems",
        description=(
            "The organization shall determine data requirements for AI "
            "systems and ensure data quality, provenance, and protection "
            "throughout the data lifecycle."
        ),
        clause="8.4",
        check_ids=[
            "code-pii-in-prompts",
            "code-training-data-unencrypted",
            "s3-training-data-encrypted",
            "s3-training-data-versioned",
        ],
        guidance=(
            "Training data must be encrypted, versioned, and free of "
            "unprotected PII. S3 buckets holding training data need "
            "server-side encryption and versioning enabled."
        ),
    ),
    "AI-8.5": ISO42001Control(
        id="AI-8.5",
        title="AI System Monitoring",
        description=(
            "The organization shall monitor AI systems in operation to "
            "detect deviations from expected behavior, data drift, model "
            "degradation, and emerging risks."
        ),
        clause="8.5",
        check_ids=[
            "sagemaker-data-capture",
            "azure-ml-data-drift-monitor",
            "code-ai-logging-insufficient",
            "bedrock-model-invocation-logging",
        ],
        guidance=(
            "Enable data capture on SageMaker endpoints, configure drift "
            "monitors in Azure ML, and ensure all AI invocations are "
            "logged for observability and audit."
        ),
    ),
    # =========================================================================
    # Annex A — Reference Controls
    # =========================================================================
    "AI-A.2": ISO42001Control(
        id="AI-A.2",
        title="Policies for AI",
        description=(
            "Policies specific to the development, provision, and use of "
            "AI systems shall be defined, approved, published, "
            "communicated, and reviewed."
        ),
        clause="A.2",
        requires_policy=True,
        guidance=(
            "Requires AI-specific policies covering acceptable use of AI, "
            "model governance, data handling for AI, and third-party AI "
            "service usage. Supplement your information security policy "
            "with AI addenda."
        ),
    ),
    "AI-A.5": ISO42001Control(
        id="AI-A.5",
        title="Data Management",
        description=(
            "Data used by AI systems shall be managed to ensure quality, "
            "relevance, representativeness, and freedom from prohibited "
            "bias, with appropriate privacy protections."
        ),
        clause="A.5",
        check_ids=[
            "code-pii-in-prompts",
            "code-training-data-unencrypted",
            "azure-openai-diagnostic-logging",
        ],
        guidance=(
            "Ensure PII is not leaked in prompts, training data is "
            "encrypted, and AI service interactions are logged for data "
            "governance auditing."
        ),
    ),
    "AI-A.6": ISO42001Control(
        id="AI-A.6",
        title="Computing Resources",
        description=(
            "Computing resources for AI systems shall be provisioned with "
            "appropriate security controls including network isolation, "
            "encryption, and access management."
        ),
        clause="A.6",
        check_ids=[
            "sagemaker-training-vpc",
            "sagemaker-endpoint-encryption",
            "azure-ml-workspace-encryption",
            "azure-ml-compute-rbac",
        ],
        guidance=(
            "AI training jobs should run in private VPCs, endpoints must "
            "use encryption, ML workspaces need encryption at rest, and "
            "compute access should be restricted via RBAC."
        ),
    ),
    "AI-A.8": ISO42001Control(
        id="AI-A.8",
        title="AI System Security",
        description=(
            "AI systems shall be protected against adversarial attacks, "
            "prompt injection, unauthorized access, and misuse through "
            "appropriate technical and organizational measures."
        ),
        clause="A.8",
        check_ids=[
            "code-prompt-injection-risk",
            "code-ai-api-key-exposed",
            "bedrock-guardrails-configured",
            "azure-openai-content-filter",
            "code-agent-unrestricted-tools",
        ],
        guidance=(
            "Protect against prompt injection, never expose API keys in "
            "code, configure guardrails and content filters on AI "
            "services, and restrict tool access for AI agents."
        ),
    ),
    "AI-A.9": ISO42001Control(
        id="AI-A.9",
        title="Third-Party and Customer Relationships",
        description=(
            "The organization shall manage risks from third-party AI "
            "components, APIs, and services, ensuring secure integration "
            "and ongoing vendor assessment."
        ),
        clause="A.9",
        check_ids=[
            "lambda-ai-api-keys-not-hardcoded",
            "azure-openai-managed-identity",
            "code-outdated-ai-sdk",
        ],
        guidance=(
            "Use managed identities instead of API keys for AI services, "
            "never hardcode keys in Lambda functions, and keep AI SDKs "
            "up to date to avoid known vulnerabilities."
        ),
    ),
}


# ---------------------------------------------------------------------------
# Helper functions (mirror framework.py pattern)
# ---------------------------------------------------------------------------


def get_iso42001_control(control_id: str) -> ISO42001Control | None:
    """Look up an ISO 42001 control by ID."""
    return ISO42001_CONTROLS.get(control_id)


def get_iso42001_controls_for_check(check_id: str) -> list[ISO42001Control]:
    """Find all ISO 42001 controls that a given check maps to."""
    return [ctrl for ctrl in ISO42001_CONTROLS.values() if check_id in ctrl.check_ids]


def get_automated_iso42001_controls() -> list[ISO42001Control]:
    """Get all controls that have automated checks."""
    return [ctrl for ctrl in ISO42001_CONTROLS.values() if ctrl.check_ids]


def get_policy_required_iso42001_controls() -> list[ISO42001Control]:
    """Get all controls that require policy documents."""
    return [ctrl for ctrl in ISO42001_CONTROLS.values() if ctrl.requires_policy]
