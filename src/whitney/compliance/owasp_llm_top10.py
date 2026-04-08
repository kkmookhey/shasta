"""OWASP Top 10 for LLM Applications v2.0 framework definitions.

Maps Whitney AI checks to the OWASP LLM Top 10 risk items.
This is now table stakes for AI security vendors — every competitor
maps to OWASP LLM Top 10.

Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class OWASPLLMRisk:
    """A single OWASP LLM Top 10 risk item."""

    id: str  # e.g., "LLM01"
    title: str
    description: str
    check_ids: list[str] = field(default_factory=list)
    soc2_equivalent: list[str] = field(default_factory=list)
    guidance: str = ""


# ---------------------------------------------------------------------------
# OWASP LLM Top 10 v2.0 Risk Items
# ---------------------------------------------------------------------------

OWASP_LLM_TOP10: dict[str, OWASPLLMRisk] = {
    "LLM01": OWASPLLMRisk(
        id="LLM01",
        title="Prompt Injection",
        description=(
            "An attacker manipulates an LLM through crafted inputs, causing "
            "the LLM to execute unintended actions. Direct prompt injections "
            "overwrite system prompts, while indirect injections manipulate "
            "inputs from external sources."
        ),
        check_ids=[
            "code-prompt-injection-risk",
            "bedrock-guardrails-configured",
            "bedrock-content-filter",
            "azure-openai-content-filter",
        ],
        soc2_equivalent=["CC6.1", "CC7.2"],
        guidance=(
            "Sanitise user input before including in prompts. Use structured "
            "message APIs. Deploy guardrails on Bedrock and content filters "
            "on Azure OpenAI. Implement input validation and output filtering."
        ),
    ),
    "LLM02": OWASPLLMRisk(
        id="LLM02",
        title="Insecure Output Handling",
        description=(
            "Insufficient validation, sanitisation, and handling of LLM "
            "outputs before passing them downstream, potentially leading "
            "to XSS, CSRF, SSRF, privilege escalation, or remote code execution."
        ),
        check_ids=[
            "code-no-output-validation",
        ],
        soc2_equivalent=["CC7.2"],
        guidance=(
            "Validate and sanitise LLM outputs before use. Parse structured "
            "responses with Pydantic or JSON schema. Never render LLM output "
            "as executable code without review."
        ),
    ),
    "LLM03": OWASPLLMRisk(
        id="LLM03",
        title="Training Data Poisoning",
        description=(
            "Manipulation of training data or fine-tuning procedures to "
            "introduce vulnerabilities, backdoors, or biases into the model."
        ),
        check_ids=[
            "code-training-data-unencrypted",
            "s3-training-data-encrypted",
            "s3-training-data-versioned",
        ],
        soc2_equivalent=["CC6.1", "CC6.7"],
        guidance=(
            "Encrypt training data at rest and in transit. Version training "
            "data for lineage. Validate data sources and integrity before "
            "training. Use HTTPS for data retrieval."
        ),
    ),
    "LLM04": OWASPLLMRisk(
        id="LLM04",
        title="Model Denial of Service",
        description=(
            "An attacker interacts with an LLM in a way that consumes an "
            "exceptionally high amount of resources, resulting in degraded "
            "service quality or high costs."
        ),
        check_ids=[
            "code-no-rate-limiting",
        ],
        soc2_equivalent=["CC6.1"],
        guidance=(
            "Implement rate limiting on AI-serving endpoints. Set token and "
            "cost budgets per user. Use request throttling and queue management."
        ),
    ),
    "LLM05": OWASPLLMRisk(
        id="LLM05",
        title="Supply Chain Vulnerabilities",
        description=(
            "Vulnerabilities in third-party AI components including outdated "
            "SDKs with known CVEs, compromised model weights, and poisoned "
            "training data from external sources."
        ),
        check_ids=[
            "code-outdated-ai-sdk",
            "lambda-ai-api-keys-not-hardcoded",
        ],
        soc2_equivalent=["CC7.1", "CC9.1"],
        guidance=(
            "Keep AI SDKs updated. Use the AI SBOM to track all AI "
            "dependencies. Scan third-party models before deployment. "
            "Manage API keys via secrets manager."
        ),
    ),
    "LLM06": OWASPLLMRisk(
        id="LLM06",
        title="Sensitive Information Disclosure",
        description=(
            "LLMs may reveal sensitive information including PII, proprietary "
            "algorithms, confidential business data, or system prompts in "
            "their responses."
        ),
        check_ids=[
            "code-pii-in-prompts",
            "code-meta-prompt-exposed",
            "code-ai-api-key-exposed",
            "code-ai-key-in-env-file",
        ],
        soc2_equivalent=["CC6.1", "P6.1"],
        guidance=(
            "Remove PII from prompts. Store system prompts in environment "
            "variables, not inline. Never hardcode API keys. Use anonymisation "
            "before sending data to models."
        ),
    ),
    "LLM07": OWASPLLMRisk(
        id="LLM07",
        title="Insecure Plugin Design",
        description=(
            "LLM plugins or tools that accept free-form text from the model "
            "without sufficient input validation, enabling privilege "
            "escalation, data exfiltration, or remote code execution."
        ),
        check_ids=[
            "code-agent-unrestricted-tools",
        ],
        soc2_equivalent=["CC6.1", "CC7.2"],
        guidance=(
            "Restrict agent tool capabilities. Use allowlists for permitted "
            "operations. Sandbox dangerous tools. Implement human-in-the-loop "
            "for destructive operations."
        ),
    ),
    "LLM08": OWASPLLMRisk(
        id="LLM08",
        title="Excessive Agency",
        description=(
            "Granting LLMs or agents too much autonomy — excessive "
            "functionality, permissions, or scope — allowing harmful "
            "actions based on unexpected outputs."
        ),
        check_ids=[
            "code-agent-unrestricted-tools",
            "bedrock-agent-guardrails",
            "code-rag-no-access-control",
        ],
        soc2_equivalent=["CC6.1", "CC6.3"],
        guidance=(
            "Apply least-privilege to agent tools. Require human approval "
            "for high-impact actions. Add guardrails to Bedrock agents. "
            "Filter RAG queries by user context."
        ),
    ),
    "LLM09": OWASPLLMRisk(
        id="LLM09",
        title="Overreliance",
        description=(
            "Systems or people depending on LLM output without adequate "
            "oversight, verification, or fallback mechanisms, leading to "
            "misinformation, legal issues, or security vulnerabilities."
        ),
        check_ids=[
            "code-no-fallback-handler",
            "code-no-model-versioning",
        ],
        soc2_equivalent=["CC7.2", "CC7.5"],
        guidance=(
            "Implement error handling and fallback behaviour for AI calls. "
            "Pin model versions for reproducibility. Maintain human oversight "
            "for critical decisions."
        ),
    ),
    "LLM10": OWASPLLMRisk(
        id="LLM10",
        title="Model Theft",
        description=(
            "Unauthorised access to proprietary LLMs, including model "
            "weights, parameters, or through side-channel attacks and "
            "model extraction techniques."
        ),
        check_ids=[
            "code-ai-api-key-exposed",
            "sagemaker-endpoint-encryption",
            "azure-openai-private-endpoint",
            "bedrock-vpc-endpoint",
        ],
        soc2_equivalent=["CC6.1", "CC6.7"],
        guidance=(
            "Protect API keys. Encrypt model endpoints. Use private "
            "endpoints and VPC isolation. Monitor for unusual query "
            "patterns indicating extraction attempts."
        ),
    ),
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def get_owasp_llm_risk(risk_id: str) -> OWASPLLMRisk | None:
    """Look up an OWASP LLM Top 10 risk by ID."""
    return OWASP_LLM_TOP10.get(risk_id)


def get_owasp_llm_risks_for_check(check_id: str) -> list[OWASPLLMRisk]:
    """Find all OWASP LLM risks that a given check maps to."""
    return [r for r in OWASP_LLM_TOP10.values() if check_id in r.check_ids]


def get_automated_owasp_llm_risks() -> list[OWASPLLMRisk]:
    """Get all risk items that have automated checks."""
    return [r for r in OWASP_LLM_TOP10.values() if r.check_ids]
