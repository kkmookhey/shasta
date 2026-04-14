"""EU AI Act obligation framework definitions.

Maps Whitney AI checks to EU AI Act (Regulation (EU) 2024/1689) obligations
for high-risk AI systems. The EU AI Act establishes a risk-based regulatory
framework for AI systems in the European Union.

Risk levels:
  - Unacceptable: Banned (social scoring, real-time biometric ID, etc.)
  - High: Subject to strict obligations (Articles 8-15)
  - Limited: Transparency obligations (Article 52)
  - Minimal: No specific obligations

For organizations deploying high-risk AI, Articles 9-15 are the focus.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EUAIActObligation:
    """A single EU AI Act obligation."""

    id: str  # e.g., "EUAI-9"
    article: str  # e.g., "Art. 9"
    title: str
    description: str
    risk_level: str  # "high", "limited", "minimal"
    check_ids: list[str] = field(default_factory=list)
    requires_policy: bool = False
    guidance: str = ""


# ---------------------------------------------------------------------------
# EU AI Act Obligations — High-Risk AI Systems (Articles 9-15) + Art. 52
# ---------------------------------------------------------------------------

EU_AI_ACT_OBLIGATIONS: dict[str, EUAIActObligation] = {
    # =========================================================================
    # Chapter 3, Section 2 — Requirements for High-Risk AI Systems
    # =========================================================================
    "EUAI-9": EUAIActObligation(
        id="EUAI-9",
        article="Art. 9",
        title="Risk Management System",
        description=(
            "A risk management system shall be established, implemented, "
            "documented, and maintained in relation to high-risk AI systems "
            "as a continuous iterative process throughout the entire "
            "lifecycle."
        ),
        risk_level="high",
        requires_policy=True,
        guidance=(
            "Requires a documented AI risk register covering "
            "identification, estimation, evaluation, and treatment of "
            "risks. Use the risk register workflow to maintain a living "
            "risk register aligned with the AI system lifecycle."
        ),
    ),
    "EUAI-10": EUAIActObligation(
        id="EUAI-10",
        article="Art. 10",
        title="Data Governance",
        description=(
            "High-risk AI systems which make use of techniques involving "
            "the training of AI models with data shall be developed on "
            "the basis of training, validation, and testing data sets "
            "that meet quality criteria."
        ),
        risk_level="high",
        check_ids=[
            "code-pii-in-prompts",
            "code-training-data-unencrypted",
            "s3-training-data-encrypted",
        ],
        guidance=(
            "Training data must be governed: no unprotected PII in "
            "prompts, training data encrypted at rest, and data "
            "quality/provenance documented. Implement data lineage "
            "tracking."
        ),
    ),
    "EUAI-11": EUAIActObligation(
        id="EUAI-11",
        article="Art. 11",
        title="Technical Documentation",
        description=(
            "The technical documentation of a high-risk AI system shall "
            "be drawn up before that system is placed on the market or "
            "put into service and shall be kept up to date."
        ),
        risk_level="high",
        requires_policy=True,
        guidance=(
            "Requires comprehensive technical documentation including "
            "system architecture, data specifications, training "
            "methodology, performance metrics, and known limitations. "
            "Use architecture review output as the foundation."
        ),
    ),
    "EUAI-12": EUAIActObligation(
        id="EUAI-12",
        article="Art. 12",
        title="Record-Keeping",
        description=(
            "High-risk AI systems shall technically allow for the "
            "automatic recording of events (logs) over the lifetime of "
            "the system, to ensure traceability of the AI system's "
            "functioning."
        ),
        risk_level="high",
        check_ids=[
            "bedrock-model-invocation-logging",
            "azure-openai-diagnostic-logging",
            "code-ai-logging-insufficient",
            "cloudtrail-ai-events",
        ],
        guidance=(
            "All AI system interactions must be logged: enable model "
            "invocation logging on Bedrock, diagnostic logging on Azure "
            "OpenAI, and ensure application-level AI logging captures "
            "inputs, outputs, and decisions."
        ),
    ),
    "EUAI-13": EUAIActObligation(
        id="EUAI-13",
        article="Art. 13",
        title="Transparency",
        description=(
            "High-risk AI systems shall be designed and developed in "
            "such a way to ensure that their operation is sufficiently "
            "transparent to enable deployers to interpret the system's "
            "output and use it appropriately."
        ),
        risk_level="high",
        check_ids=[
            "code-meta-prompt-exposed",
        ],
        guidance=(
            "AI system behavior must be interpretable by users. Document "
            "system prompts (without exposing them publicly), explain "
            "model capabilities and limitations, and provide clear "
            "output interpretation guidance."
        ),
    ),
    "EUAI-14": EUAIActObligation(
        id="EUAI-14",
        article="Art. 14",
        title="Human Oversight",
        description=(
            "High-risk AI systems shall be designed and developed in "
            "such a way that they can be effectively overseen by natural "
            "persons during the period in which they are in use."
        ),
        risk_level="high",
        requires_policy=True,
        guidance=(
            "Requires documented human-in-the-loop or human-on-the-loop "
            "controls. Architecture review must demonstrate how human "
            "oversight is maintained, including intervention mechanisms "
            "and override capabilities."
        ),
    ),
    "EUAI-15": EUAIActObligation(
        id="EUAI-15",
        article="Art. 15",
        title="Accuracy, Robustness, Cybersecurity",
        description=(
            "High-risk AI systems shall be designed and developed in "
            "such a way that they achieve an appropriate level of "
            "accuracy, robustness, and cybersecurity, and perform "
            "consistently in those respects throughout their lifecycle."
        ),
        risk_level="high",
        check_ids=[
            "bedrock-guardrails-configured",
            "azure-openai-content-filter",
            "code-prompt-injection-risk",
            "bedrock-content-filter",
        ],
        guidance=(
            "AI systems must be resilient: configure guardrails and "
            "content filters to prevent harmful outputs, protect against "
            "prompt injection and adversarial attacks, and document "
            "accuracy benchmarks."
        ),
    ),
    # =========================================================================
    # Title IV — Transparency Obligations for Certain AI Systems
    # =========================================================================
    "EUAI-52": EUAIActObligation(
        id="EUAI-52",
        article="Art. 52",
        title="Transparency for Certain AI Systems",
        description=(
            "Providers shall ensure that AI systems intended to interact "
            "with natural persons are designed and developed in such a "
            "way that the natural person is informed that they are "
            "interacting with an AI system."
        ),
        risk_level="limited",
        requires_policy=True,
        guidance=(
            "Requires a disclosure policy for chatbots and AI-generated "
            "content. Users must be clearly informed when interacting "
            "with AI. Document disclosure mechanisms (banners, labels, "
            "watermarks) in your AI policy."
        ),
    ),
}


# ---------------------------------------------------------------------------
# Helper functions (mirror framework.py pattern)
# ---------------------------------------------------------------------------


def get_eu_ai_act_obligation(obligation_id: str) -> EUAIActObligation | None:
    """Look up an EU AI Act obligation by ID."""
    return EU_AI_ACT_OBLIGATIONS.get(obligation_id)


def get_eu_ai_act_obligations_for_check(
    check_id: str,
) -> list[EUAIActObligation]:
    """Find all EU AI Act obligations that a given check maps to."""
    return [obl for obl in EU_AI_ACT_OBLIGATIONS.values() if check_id in obl.check_ids]


def get_automated_eu_ai_act_obligations() -> list[EUAIActObligation]:
    """Get all obligations that have automated checks."""
    return [obl for obl in EU_AI_ACT_OBLIGATIONS.values() if obl.check_ids]


def get_policy_required_eu_ai_act_obligations() -> list[EUAIActObligation]:
    """Get all obligations that require policy documents."""
    return [obl for obl in EU_AI_ACT_OBLIGATIONS.values() if obl.requires_policy]
