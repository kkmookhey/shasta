"""MITRE ATLAS (Adversarial Threat Landscape for AI Systems) framework.

Maps Whitney AI checks to MITRE ATLAS tactics and techniques for
adversarial ML threats.

Reference: https://atlas.mitre.org/
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ATLASTechnique:
    """A single MITRE ATLAS technique."""

    id: str  # e.g., "AML.T0051"
    tactic: str  # e.g., "Initial Access"
    title: str
    description: str
    check_ids: list[str] = field(default_factory=list)
    soc2_equivalent: list[str] = field(default_factory=list)
    guidance: str = ""


# ---------------------------------------------------------------------------
# MITRE ATLAS Techniques
# ---------------------------------------------------------------------------

ATLAS_TECHNIQUES: dict[str, ATLASTechnique] = {
    # =========================================================================
    # Reconnaissance
    # =========================================================================
    "AML.T0000": ATLASTechnique(
        id="AML.T0000",
        tactic="Reconnaissance",
        title="Search for Victim's AI Capabilities",
        description=(
            "Adversary searches for information about a victim's AI "
            "capabilities, deployed models, and AI infrastructure."
        ),
        check_ids=[
            "code-meta-prompt-exposed",
            "code-ai-api-key-exposed",
        ],
        soc2_equivalent=["CC6.1"],
        guidance=(
            "Do not expose system prompts or API keys in source code. "
            "Restrict AI service metadata from public access."
        ),
    ),
    "AML.T0001": ATLASTechnique(
        id="AML.T0001",
        tactic="Reconnaissance",
        title="Search for AI-Related Publications",
        description=(
            "Adversary searches for publications about a victim's AI "
            "systems including model architectures, training data, and "
            "performance characteristics."
        ),
        check_ids=[],
        soc2_equivalent=["CC6.1"],
        guidance=(
            "Limit public disclosure of model architectures and training "
            "methodologies. Review publications for operational security."
        ),
    ),
    # =========================================================================
    # Resource Development
    # =========================================================================
    "AML.T0003": ATLASTechnique(
        id="AML.T0003",
        tactic="Resource Development",
        title="Acquire Adversarial ML Attack Tools",
        description=(
            "Adversary acquires or develops tools for adversarial ML "
            "attacks including prompt injection frameworks and model "
            "extraction tools."
        ),
        check_ids=[],
        soc2_equivalent=["CC7.1"],
        guidance=(
            "Monitor for known attack toolkits in threat intelligence. "
            "Test AI systems against known adversarial techniques."
        ),
    ),
    "AML.T0004": ATLASTechnique(
        id="AML.T0004",
        tactic="Resource Development",
        title="Develop Adversarial ML Capabilities",
        description=(
            "Adversary develops custom adversarial inputs, poisoned "
            "training data, or model extraction queries."
        ),
        check_ids=[
            "code-training-data-unencrypted",
            "s3-training-data-encrypted",
        ],
        soc2_equivalent=["CC6.1", "CC6.7"],
        guidance=(
            "Encrypt and version training data. Validate data integrity. "
            "Monitor for data poisoning indicators."
        ),
    ),
    # =========================================================================
    # Initial Access
    # =========================================================================
    "AML.T0051": ATLASTechnique(
        id="AML.T0051",
        tactic="Initial Access",
        title="LLM Prompt Injection",
        description=(
            "Adversary crafts inputs to manipulate LLM behaviour, "
            "bypassing safety controls or extracting sensitive information "
            "through direct or indirect prompt injection."
        ),
        check_ids=[
            "code-prompt-injection-risk",
            "bedrock-guardrails-configured",
            "bedrock-content-filter",
            "azure-openai-content-filter",
        ],
        soc2_equivalent=["CC6.1", "CC7.2"],
        guidance=(
            "Sanitise user inputs. Deploy guardrails and content filters. "
            "Separate user input from system instructions. Validate outputs."
        ),
    ),
    "AML.T0052": ATLASTechnique(
        id="AML.T0052",
        tactic="Initial Access",
        title="Phishing via AI",
        description=(
            "Adversary uses AI-generated content for social engineering "
            "or phishing attacks targeting AI system operators."
        ),
        check_ids=[],
        soc2_equivalent=["CC6.1"],
        guidance=(
            "Train staff on AI-generated phishing. Implement email "
            "security controls. Verify identity for AI system access."
        ),
    ),
    # =========================================================================
    # ML Attack Staging
    # =========================================================================
    "AML.T0010": ATLASTechnique(
        id="AML.T0010",
        tactic="ML Attack Staging",
        title="Poison Training Data",
        description=(
            "Adversary contaminates training data to introduce backdoors "
            "or biases into the model during training or fine-tuning."
        ),
        check_ids=[
            "code-training-data-unencrypted",
            "code-unsafe-deserialization",
            "s3-training-data-encrypted",
            "s3-training-data-versioned",
        ],
        soc2_equivalent=["CC6.1", "CC6.7"],
        guidance=(
            "Encrypt and version training data. Validate data provenance. "
            "Use checksums to detect tampering. Never load untrusted "
            "pickle/torch model files — use safetensors format."
        ),
    ),
    "AML.T0011": ATLASTechnique(
        id="AML.T0011",
        tactic="ML Attack Staging",
        title="Backdoor ML Model",
        description=(
            "Adversary introduces a backdoor into the model during "
            "training that activates on specific trigger inputs."
        ),
        check_ids=[
            "sagemaker-model-approval",
            "sagemaker-model-registry-access",
        ],
        soc2_equivalent=["CC6.1", "CC8.1"],
        guidance=(
            "Require model approval before deployment. Restrict model "
            "registry access. Scan models for anomalous behaviour."
        ),
    ),
    "AML.T0012": ATLASTechnique(
        id="AML.T0012",
        tactic="ML Attack Staging",
        title="Supply Chain Compromise",
        description=(
            "Adversary compromises AI supply chain components including "
            "SDKs, model registries, or training pipelines."
        ),
        check_ids=[
            "code-outdated-ai-sdk",
            "lambda-ai-api-keys-not-hardcoded",
        ],
        soc2_equivalent=["CC7.1", "CC9.1"],
        guidance=(
            "Keep AI SDKs updated. Use AI SBOM for dependency tracking. "
            "Verify model integrity from registries."
        ),
    ),
    # =========================================================================
    # Exfiltration
    # =========================================================================
    "AML.T0024": ATLASTechnique(
        id="AML.T0024",
        tactic="Exfiltration",
        title="Exfiltration via AI API",
        description=(
            "Adversary extracts sensitive data through AI model APIs "
            "including training data extraction, membership inference, "
            "or model inversion attacks."
        ),
        check_ids=[
            "code-pii-in-prompts",
            "code-ai-api-key-exposed",
            "sagemaker-endpoint-encryption",
            "azure-openai-private-endpoint",
            "bedrock-vpc-endpoint",
        ],
        soc2_equivalent=["CC6.1", "CC6.7"],
        guidance=(
            "Remove PII from prompts. Encrypt endpoints. Use private "
            "endpoints. Monitor for extraction query patterns."
        ),
    ),
    "AML.T0025": ATLASTechnique(
        id="AML.T0025",
        tactic="Exfiltration",
        title="Model Theft",
        description=(
            "Adversary steals model weights, parameters, or intellectual "
            "property through API queries or direct access."
        ),
        check_ids=[
            "code-ai-api-key-exposed",
            "sagemaker-endpoint-encryption",
            "azure-openai-private-endpoint",
            "bedrock-vpc-endpoint",
        ],
        soc2_equivalent=["CC6.1", "CC6.7"],
        guidance=(
            "Protect API credentials. Use VPC endpoints. Rate-limit "
            "inference APIs. Monitor for model extraction patterns."
        ),
    ),
    # =========================================================================
    # Impact
    # =========================================================================
    "AML.T0029": ATLASTechnique(
        id="AML.T0029",
        tactic="Impact",
        title="Denial of AI Service",
        description=(
            "Adversary disrupts AI service availability through resource "
            "exhaustion, model corruption, or infrastructure attacks."
        ),
        check_ids=[
            "code-no-rate-limiting",
            "code-no-fallback-handler",
        ],
        soc2_equivalent=["CC6.1", "CC7.5"],
        guidance=(
            "Implement rate limiting. Add fallback handlers. Set "
            "resource budgets and circuit breakers."
        ),
    ),
    "AML.T0031": ATLASTechnique(
        id="AML.T0031",
        tactic="Impact",
        title="Erode AI Integrity",
        description=(
            "Adversary degrades the integrity of AI system outputs "
            "through adversarial inputs, data drift, or model "
            "manipulation."
        ),
        check_ids=[
            "sagemaker-data-capture",
            "azure-ml-data-drift-monitor",
            "code-no-output-validation",
        ],
        soc2_equivalent=["CC7.2"],
        guidance=(
            "Enable data capture and drift monitoring. Validate AI "
            "outputs. Monitor for performance degradation."
        ),
    ),
    # =========================================================================
    # Evasion
    # =========================================================================
    "AML.T0015": ATLASTechnique(
        id="AML.T0015",
        tactic="Evasion",
        title="Evade ML Model",
        description=(
            "Adversary crafts inputs designed to cause the ML model "
            "to produce incorrect outputs while appearing normal to "
            "human observers."
        ),
        check_ids=[
            "bedrock-guardrails-configured",
            "azure-openai-content-filter",
        ],
        soc2_equivalent=["CC7.2"],
        guidance=(
            "Deploy guardrails and content filters. Test models against "
            "adversarial inputs. Implement input validation."
        ),
    ),
    # =========================================================================
    # Collection
    # =========================================================================
    "AML.T0035": ATLASTechnique(
        id="AML.T0035",
        tactic="Collection",
        title="Collect AI System Telemetry",
        description=(
            "Adversary collects telemetry, logs, or metadata from AI "
            "systems to inform further attacks."
        ),
        check_ids=[
            "code-ai-logging-insufficient",
            "cloudtrail-ai-events",
        ],
        soc2_equivalent=["CC7.2", "CC7.3"],
        guidance=(
            "Ensure logging captures AI events but restrict log access. "
            "Monitor for unusual log query patterns."
        ),
    ),
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def get_atlas_technique(technique_id: str) -> ATLASTechnique | None:
    """Look up a MITRE ATLAS technique by ID."""
    return ATLAS_TECHNIQUES.get(technique_id)


def get_atlas_techniques_for_check(check_id: str) -> list[ATLASTechnique]:
    """Find all ATLAS techniques that a given check maps to."""
    return [t for t in ATLAS_TECHNIQUES.values() if check_id in t.check_ids]


def get_automated_atlas_techniques() -> list[ATLASTechnique]:
    """Get all techniques that have automated checks."""
    return [t for t in ATLAS_TECHNIQUES.values() if t.check_ids]


def get_atlas_techniques_by_tactic(tactic: str) -> list[ATLASTechnique]:
    """Get all techniques for a specific tactic."""
    return [t for t in ATLAS_TECHNIQUES.values() if t.tactic == tactic]


def get_atlas_tactics() -> list[str]:
    """Get all unique tactic names."""
    return sorted({t.tactic for t in ATLAS_TECHNIQUES.values()})
