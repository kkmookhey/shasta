"""Security questionnaire auto-fill engine.

Maps scan findings to questionnaire answers automatically. The engine does not
interpret question semantics -- it relies on explicit check_id and policy_type
mappings to determine answers:

  - If all mapped findings PASS -> "Yes" (high confidence)
  - If mixed pass/fail -> "Partial" (medium confidence)
  - If all FAIL -> "No" (high confidence)
  - If no mapped data -> manual review required

This approach gives deterministic, auditable answers backed by evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from shasta.evidence.models import ComplianceStatus, Finding, ScanResult


@dataclass
class Question:
    """A single question from a security questionnaire.

    Attributes:
        id: Unique identifier, e.g. "SIG-A.01.01".
        text: The question text as it appears on the questionnaire.
        category: Grouping category, e.g. "Access Control".
        expected_answer: Answer format -- "yes_no", "text", or "date".
        check_ids: Shasta check_ids whose findings answer this question.
        test_ids: Control test IDs (CT-*) related to this question.
        policy_type: If set, the engine also checks for this policy file.
        frameworks: Compliance framework references, e.g. ["SOC 2 CC6.1"].
    """

    id: str
    text: str
    category: str
    expected_answer: str
    check_ids: list[str] = field(default_factory=list)
    test_ids: list[str] = field(default_factory=list)
    policy_type: str = ""
    frameworks: list[str] = field(default_factory=list)


@dataclass
class Answer:
    """An auto-generated or manual answer to a questionnaire question.

    Attributes:
        question_id: The Question.id this answers.
        answer: "Yes", "No", "Partial", "N/A", or freeform text.
        evidence_refs: List of resource IDs / finding IDs backing the answer.
        confidence: "high", "medium", "low", or "manual".
        notes: Explanatory notes for the reviewer.
    """

    question_id: str
    answer: str
    evidence_refs: list[str] = field(default_factory=list)
    confidence: str = "low"
    notes: str = ""


@dataclass
class QuestionnaireResult:
    """Aggregated result of filling a questionnaire.

    Attributes:
        questionnaire_type: Name of the questionnaire (e.g. "SIG Lite").
        total_questions: Total number of questions processed.
        auto_answered: Number of questions answered automatically.
        manual_required: Number requiring manual review.
        coverage_pct: Percentage of questions auto-answered.
        answers: The list of generated answers.
    """

    questionnaire_type: str
    total_questions: int
    auto_answered: int
    manual_required: int
    coverage_pct: float
    answers: list[Answer] = field(default_factory=list)


class QuestionnaireEngine:
    """Fills security questionnaires using scan findings.

    The engine indexes findings by check_id and evaluates each question
    by looking up its mapped check_ids. It also checks for policy documents
    when a question references a policy_type.

    Usage::

        engine = QuestionnaireEngine(scan)
        result = engine.fill(SIG_LITE_QUESTIONS, questionnaire_type="SIG Lite")
    """

    def __init__(self, scan: ScanResult, policy_dir: str | Path = "data/policies") -> None:
        """Initialize the engine with scan data.

        Args:
            scan: A completed ScanResult containing findings.
            policy_dir: Directory where generated policy documents live.
        """
        self._scan = scan
        self._policy_dir = Path(policy_dir)
        self._findings_by_check: dict[str, list[Finding]] = self._index_findings(scan.findings)

    @staticmethod
    def _index_findings(findings: list[Finding]) -> dict[str, list[Finding]]:
        """Index findings by check_id for O(1) lookup."""
        index: dict[str, list[Finding]] = {}
        for f in findings:
            index.setdefault(f.check_id, []).append(f)
        return index

    def fill(
        self,
        questions: list[Question],
        questionnaire_type: str = "Generic",
    ) -> QuestionnaireResult:
        """Fill a questionnaire by mapping questions to findings.

        Args:
            questions: The list of questions to answer.
            questionnaire_type: Human-readable name for the questionnaire.

        Returns:
            A QuestionnaireResult with all answers populated.
        """
        answers: list[Answer] = []
        auto_count = 0

        for q in questions:
            answer = self._answer_question(q)
            answers.append(answer)
            if answer.confidence != "manual":
                auto_count += 1

        total = len(questions)
        manual = total - auto_count
        coverage = (auto_count / total * 100.0) if total > 0 else 0.0

        return QuestionnaireResult(
            questionnaire_type=questionnaire_type,
            total_questions=total,
            auto_answered=auto_count,
            manual_required=manual,
            coverage_pct=round(coverage, 1),
            answers=answers,
        )

    def _answer_question(self, question: Question) -> Answer:
        """Determine the answer for a single question.

        Logic:
          1. Collect all findings for the question's check_ids.
          2. If findings exist, evaluate pass/fail/partial.
          3. If a policy_type is set, check for the policy file.
          4. Combine signals into a final answer.
        """
        related_findings: list[Finding] = []
        for check_id in question.check_ids:
            related_findings.extend(self._findings_by_check.get(check_id, []))

        has_findings = len(related_findings) > 0
        has_policy = self._check_policy_exists(question.policy_type)

        # No data at all -- manual review required
        if not has_findings and not has_policy and not question.policy_type:
            if not question.check_ids:
                return Answer(
                    question_id=question.id,
                    answer="Manual review required",
                    confidence="manual",
                    notes="No automated checks mapped to this question.",
                )
            return Answer(
                question_id=question.id,
                answer="Manual review required",
                confidence="manual",
                notes=(
                    f"Mapped checks ({', '.join(question.check_ids)}) produced "
                    f"no findings. Service may not be in use or checks were not run."
                ),
            )

        # Evaluate finding statuses
        passed = [f for f in related_findings if f.status == ComplianceStatus.PASS]
        failed = [f for f in related_findings if f.status == ComplianceStatus.FAIL]
        partial = [f for f in related_findings if f.status == ComplianceStatus.PARTIAL]

        evidence_refs = [f.resource_id for f in related_findings]

        # Pure policy question (no check_ids, only policy_type)
        if not has_findings and question.policy_type:
            if has_policy:
                return Answer(
                    question_id=question.id,
                    answer="Yes",
                    evidence_refs=[f"policy:{question.policy_type}"],
                    confidence="medium",
                    notes=f"Policy document '{question.policy_type}' exists.",
                )
            return Answer(
                question_id=question.id,
                answer="No",
                confidence="medium",
                notes=f"Policy document '{question.policy_type}' not found.",
            )

        # Evaluate based on findings
        if failed and not passed and not partial:
            # All fail
            answer_text = "No"
            confidence = "high"
            notes = f"All {len(failed)} checked resource(s) are non-compliant."
        elif not failed and not partial and passed:
            # All pass
            answer_text = "Yes"
            confidence = "high"
            notes = f"All {len(passed)} checked resource(s) are compliant."
        elif passed and (failed or partial):
            # Mixed
            answer_text = "Partial"
            confidence = "medium"
            parts = []
            if passed:
                parts.append(f"{len(passed)} pass")
            if failed:
                parts.append(f"{len(failed)} fail")
            if partial:
                parts.append(f"{len(partial)} partial")
            notes = f"Mixed results: {', '.join(parts)}."
        elif partial and not failed and not passed:
            answer_text = "Partial"
            confidence = "medium"
            notes = f"{len(partial)} resource(s) partially compliant."
        else:
            answer_text = "Manual review required"
            confidence = "manual"
            notes = "Findings exist but status is inconclusive."

        # Augment with policy info if relevant
        if question.policy_type:
            if has_policy:
                evidence_refs.append(f"policy:{question.policy_type}")
                notes += f" Policy '{question.policy_type}' exists."
            else:
                # Downgrade confidence if policy is missing
                if answer_text == "Yes":
                    answer_text = "Partial"
                    confidence = "medium"
                notes += f" Policy '{question.policy_type}' not found."

        return Answer(
            question_id=question.id,
            answer=answer_text,
            evidence_refs=evidence_refs,
            confidence=confidence,
            notes=notes,
        )

    def _check_policy_exists(self, policy_type: str) -> bool:
        """Check whether a policy document exists in the policy directory.

        Looks for files matching the pattern ``{policy_type}*.md`` in
        the configured policy directory.
        """
        if not policy_type:
            return False
        if not self._policy_dir.exists():
            return False
        matches = list(self._policy_dir.glob(f"{policy_type}*.md"))
        return len(matches) > 0
