"""Output generators for completed questionnaire results.

Produces CSV and Markdown files suitable for sharing with enterprise
buyers, auditors, or uploading into GRC platforms.
"""

from __future__ import annotations

import csv
from datetime import UTC, datetime
from itertools import groupby
from pathlib import Path

from shasta.questionnaire.engine import Question, QuestionnaireResult


def generate_csv(
    result: QuestionnaireResult,
    questions: list[Question],
    output_path: str | Path = "data/questionnaires",
) -> Path:
    """Generate a CSV file from a completed questionnaire.

    Columns: Question ID, Category, Question, Answer, Confidence,
    Evidence References, Notes, Frameworks.

    Args:
        result: The filled QuestionnaireResult.
        questions: The original question list (for text/category lookup).
        output_path: Directory to write the CSV file into.

    Returns:
        Path to the generated CSV file.
    """
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(UTC)
    slug = result.questionnaire_type.lower().replace(" ", "-")
    filename = f"{slug}-{now.strftime('%Y-%m-%d')}.csv"
    filepath = output_dir / filename

    questions_by_id = {q.id: q for q in questions}

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "Question ID",
                "Category",
                "Question",
                "Answer",
                "Confidence",
                "Evidence References",
                "Notes",
                "Frameworks",
            ]
        )

        for answer in result.answers:
            q = questions_by_id.get(answer.question_id)
            if not q:
                continue
            writer.writerow(
                [
                    q.id,
                    q.category,
                    q.text,
                    answer.answer,
                    answer.confidence,
                    "; ".join(answer.evidence_refs),
                    answer.notes,
                    "; ".join(q.frameworks),
                ]
            )

    return filepath


def generate_markdown(
    result: QuestionnaireResult,
    questions: list[Question],
    output_path: str | Path = "data/questionnaires",
    scan_date: str | None = None,
) -> Path:
    """Generate a Markdown report from a completed questionnaire.

    The report includes a coverage summary, answers grouped by category,
    and evidence citations for each answer.

    Args:
        result: The filled QuestionnaireResult.
        questions: The original question list.
        output_path: Directory to write the Markdown file into.
        scan_date: Optional scan date string for the header.

    Returns:
        Path to the generated Markdown file.
    """
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(UTC)
    slug = result.questionnaire_type.lower().replace(" ", "-")
    filename = f"{slug}-{now.strftime('%Y-%m-%d')}.md"
    filepath = output_dir / filename

    answers_by_id = {a.question_id: a for a in result.answers}

    date_str = scan_date or now.strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []

    # Header
    lines.append(f"# {result.questionnaire_type} — Auto-Fill Report")
    lines.append("")
    lines.append(
        f"Auto-filled **{result.auto_answered}/{result.total_questions}** questions "
        f"(**{result.coverage_pct}%** coverage) from Shasta scan dated {date_str}."
    )
    lines.append("")

    # Summary table
    lines.append("## Coverage Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Questionnaire | {result.questionnaire_type} |")
    lines.append(f"| Total Questions | {result.total_questions} |")
    lines.append(f"| Auto-Answered | {result.auto_answered} |")
    lines.append(f"| Manual Review Required | {result.manual_required} |")
    lines.append(f"| Coverage | {result.coverage_pct}% |")
    lines.append("")

    # Confidence breakdown
    high = sum(1 for a in result.answers if a.confidence == "high")
    medium = sum(1 for a in result.answers if a.confidence == "medium")
    low = sum(1 for a in result.answers if a.confidence == "low")
    manual = sum(1 for a in result.answers if a.confidence == "manual")

    lines.append("### Confidence Breakdown")
    lines.append("")
    lines.append("| Confidence | Count |")
    lines.append("|------------|-------|")
    lines.append(f"| High | {high} |")
    lines.append(f"| Medium | {medium} |")
    lines.append(f"| Low | {low} |")
    lines.append(f"| Manual | {manual} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Group questions by category
    sorted_questions = sorted(questions, key=lambda q: q.category)
    grouped = groupby(sorted_questions, key=lambda q: q.category)

    lines.append("## Answers by Category")
    lines.append("")

    for category, cat_questions in grouped:
        cat_questions_list = list(cat_questions)
        lines.append(f"### {category}")
        lines.append("")

        for q in cat_questions_list:
            answer = answers_by_id.get(q.id)
            if not answer:
                continue

            # Confidence indicator
            conf_label = {
                "high": "HIGH",
                "medium": "MED",
                "low": "LOW",
                "manual": "MANUAL",
            }.get(answer.confidence, answer.confidence.upper())

            lines.append(f"**{q.id}:** {q.text}")
            lines.append("")
            lines.append(f"- **Answer:** {answer.answer}")
            lines.append(f"- **Confidence:** {conf_label}")

            if answer.evidence_refs:
                refs = ", ".join(f"`{r}`" for r in answer.evidence_refs[:5])
                if len(answer.evidence_refs) > 5:
                    refs += f" (+{len(answer.evidence_refs) - 5} more)"
                lines.append(f"- **Evidence:** {refs}")

            if answer.notes:
                lines.append(f"- **Notes:** {answer.notes}")

            if q.frameworks:
                lines.append(f"- **Frameworks:** {', '.join(q.frameworks)}")

            lines.append("")

        lines.append("---")
        lines.append("")

    # Footer
    lines.append("## Notes for Reviewer")
    lines.append("")
    lines.append(
        "- **High confidence** answers are backed by automated scan evidence "
        "where all checked resources passed or failed consistently."
    )
    lines.append(
        "- **Medium confidence** answers have mixed results or are backed by "
        "policy document existence only."
    )
    lines.append(
        "- **Manual** answers require human review — either no automated checks "
        "exist for that question, or the relevant services were not scanned."
    )
    lines.append("")
    lines.append("*Generated by Shasta Security Questionnaire Auto-Fill Engine.*")

    filepath.write_text("\n".join(lines), encoding="utf-8")
    return filepath
