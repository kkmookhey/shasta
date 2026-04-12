"""HIPAA Security Rule policy document generator.

Addresses Bug #5 from 2026-04-11: after running a HIPAA gap analysis,
``/policy-gen`` produced SOC 2 policies only — none of the HIPAA-specific
documents that an OCR audit expects. This module adds six HIPAA-specific
policy templates mirroring the pattern used in ``shasta.policies.generator``
and ``whitney.policies.generator``.

Templates:
  - hipaa_breach_notification          § 164.402 – 164.408
  - hipaa_business_associate_management § 164.308(b)(1), § 164.314(a)
  - hipaa_workforce_training           § 164.308(a)(5)
  - hipaa_security_management          § 164.308(a)(1)
  - hipaa_minimum_necessary_access     § 164.502(b), § 164.514(d)
  - hipaa_contingency_plan             § 164.308(a)(7)
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import BaseLoader, Environment

HIPAA_POLICIES: dict[str, dict] = {
    "hipaa_breach_notification": {
        "title": "HIPAA Breach Notification Procedure",
        "hipaa_controls": ["164.402", "164.404", "164.406", "164.408"],
        "filename": "hipaa-breach-notification.md",
        "template": """\
# HIPAA Breach Notification Procedure

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Privacy / Security Officer
**HIPAA Controls:** 45 CFR §§ 164.402, 164.404, 164.406, 164.408

## 1. Purpose
This procedure defines how {{ company_name }} detects, investigates, and notifies affected parties of any breach of unsecured Protected Health Information (PHI) as required by the HIPAA Breach Notification Rule.

## 2. Scope
Applies to all workforce members and business associates handling PHI on behalf of {{ company_name }}.

## 3. Definitions
A **breach** is the acquisition, access, use, or disclosure of PHI in a manner not permitted by the Privacy Rule that compromises the security or privacy of the PHI, unless a risk assessment demonstrates a low probability of compromise (§ 164.402).

## 4. Discovery and Risk Assessment
Any suspected breach must be reported to the Privacy Officer within 24 hours of discovery. The Privacy Officer conducts a four-factor risk assessment:
1. Nature and extent of PHI involved (types of identifiers, likelihood of re-identification).
2. Unauthorized person who used/received the PHI.
3. Whether the PHI was actually acquired or viewed.
4. Extent to which the risk has been mitigated.

## 5. Notification Timelines
- **Individuals (§ 164.404):** Written notice by first-class mail within 60 calendar days of discovery.
- **HHS (§ 164.408):** Breaches affecting 500+ individuals — notify HHS concurrently with individuals. Smaller breaches logged and reported annually within 60 days of year-end.
- **Media (§ 164.406):** Breaches affecting 500+ residents of a single state — notify prominent media outlets without unreasonable delay.
- **Business Associates (§ 164.410):** Must notify {{ company_name }} within 60 days of discovery.

## 6. Notice Content
Each individual notice must contain: (a) a brief description of what happened, (b) the types of PHI involved, (c) steps individuals should take to protect themselves, (d) what {{ company_name }} is doing to investigate and mitigate, (e) contact information including a toll-free number.

## 7. Documentation
The Privacy Officer maintains a breach log retained for at least six (6) years, including risk assessment, notification records, and remediation actions taken.

## 8. Review
This procedure is reviewed annually by the Privacy Officer and updated when regulations or business operations change.
""",
    },
    "hipaa_business_associate_management": {
        "title": "HIPAA Business Associate Management Policy",
        "hipaa_controls": ["164.308(b)(1)", "164.308(b)(3)", "164.314(a)"],
        "filename": "hipaa-business-associate-management.md",
        "template": """\
# HIPAA Business Associate Management Policy

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Privacy / Security Officer
**HIPAA Controls:** 45 CFR §§ 164.308(b)(1), 164.308(b)(3), 164.314(a)

## 1. Purpose
This policy ensures that {{ company_name }} obtains satisfactory assurances from every Business Associate (BA) that will create, receive, maintain, or transmit PHI on its behalf, as required by the HIPAA Security and Privacy Rules.

## 2. Scope
All third parties that handle PHI under any arrangement with {{ company_name }}, including cloud providers, analytics vendors, billing services, and subcontractors.

## 3. Business Associate Identification
Department owners must identify BAs before engagement. A vendor is a BA if it performs a function or activity involving PHI disclosure on behalf of {{ company_name }}. The Privacy Officer maintains a central BA inventory.

## 4. Business Associate Agreements (BAAs)
No PHI may be shared with a BA until a signed BAA is in place. Each BAA must, at minimum:
- Establish permitted and required uses of PHI.
- Require the BA to implement appropriate safeguards (§ 164.308, § 164.312).
- Require breach reporting within the timeframe defined in § 164.410.
- Require the BA to ensure subcontractors agree in writing to the same terms.
- Provide for return or destruction of PHI upon termination.
- Authorize termination for material breach.

## 5. Due Diligence
Before signing a BAA, {{ company_name }} performs security due diligence including review of SOC 2 / HITRUST / ISO 27001 reports, data flow mapping, and documented security controls.

## 6. Ongoing Monitoring
BAs are reviewed at least annually: BAA validity, updated attestations, incident history, and whether the scope of PHI handling has changed.

## 7. Termination
Upon contract termination, the Privacy Officer verifies that PHI is returned or destroyed and obtains written confirmation within 30 days.

## 8. Documentation
BAAs, due diligence records, and termination confirmations are retained for six (6) years after the agreement ends.
""",
    },
    "hipaa_workforce_training": {
        "title": "HIPAA Workforce Security Awareness and Training Program",
        "hipaa_controls": ["164.308(a)(5)"],
        "filename": "hipaa-workforce-training.md",
        "template": """\
# HIPAA Workforce Security Awareness and Training Program

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Security Officer
**HIPAA Controls:** 45 CFR § 164.308(a)(5) — Security Awareness and Training

## 1. Purpose
Establishes mandatory security awareness and training for all members of the {{ company_name }} workforce who have access to PHI, as required by the HIPAA Security Rule.

## 2. Scope
Applies to all employees, contractors, interns, and volunteers. Business associate personnel are covered by their own training programs as required by their BAA.

## 3. Required Training Topics
The training curriculum includes, at minimum:
- The Privacy Rule, Security Rule, and Breach Notification Rule.
- Recognizing and reporting suspected security incidents (§ 164.308(a)(5)(ii)(B)).
- Protection from malicious software and phishing (§ 164.308(a)(5)(ii)(B)).
- Log-in monitoring and the reporting of unusual access (§ 164.308(a)(5)(ii)(C)).
- Password management and acceptable use (§ 164.308(a)(5)(ii)(D)).
- Mobile device and remote work security.
- {{ company_name }}'s internal policies on minimum necessary access and incident response.

## 4. Frequency
- **Onboarding:** New workforce members complete training within 14 days of hire and before accessing PHI.
- **Annual refresher:** All workforce members complete a refresher module every 12 months.
- **Ad-hoc updates:** Targeted reminders are issued after material regulatory changes or significant incidents.

## 5. Tracking and Completion
The Security Officer tracks completion in the HR/LMS system. Non-completion is escalated to the employee's manager after 14 days and to executive leadership after 30 days.

## 6. Sanctions
Failure to complete required training, or violation of HIPAA policies, is subject to the {{ company_name }} Sanctions Policy up to and including termination (§ 164.308(a)(1)(ii)(C)).

## 7. Documentation
Training content, completion records, and sanction records are retained for six (6) years.

## 8. Review
The Security Officer reviews this program annually and updates materials to reflect current threats and regulatory guidance.
""",
    },
    "hipaa_security_management": {
        "title": "HIPAA Security Management Process",
        "hipaa_controls": ["164.308(a)(1)"],
        "filename": "hipaa-security-management.md",
        "template": """\
# HIPAA Security Management Process

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Security Officer
**HIPAA Controls:** 45 CFR § 164.308(a)(1) — Security Management Process

## 1. Purpose
Establishes the overarching security management program at {{ company_name }} required by the HIPAA Security Rule, including risk analysis, risk management, sanctions, and information system activity review.

## 2. Scope
Applies to all systems, applications, and processes that create, receive, maintain, or transmit electronic PHI (ePHI).

## 3. Risk Analysis (§ 164.308(a)(1)(ii)(A))
{{ company_name }} conducts a documented risk analysis at least annually and after any material change to the environment. The analysis identifies threats and vulnerabilities, assesses likelihood and impact to ePHI confidentiality/integrity/availability, and results in a prioritized risk register.

## 4. Risk Management (§ 164.308(a)(1)(ii)(B))
Risks above the defined tolerance are assigned an owner, a treatment (mitigate / transfer / accept / avoid), and a target date. Progress is reviewed quarterly by the Security Officer and reported to executive leadership.

## 5. Sanctions Policy (§ 164.308(a)(1)(ii)(C))
Workforce members who fail to comply with security policies are subject to disciplinary action proportional to the severity and intent of the violation. Sanctions are documented and retained for six (6) years.

## 6. Information System Activity Review (§ 164.308(a)(1)(ii)(D))
Security and audit logs from systems handling ePHI are reviewed on a regular schedule:
- Authentication and privileged-access logs — weekly.
- Access to sensitive records — monthly.
- Automated alerting for high-severity anomalies — continuous.
Reviews and findings are documented.

## 7. Roles
The Security Officer owns this process. System owners are responsible for implementing controls within their systems. Executive leadership reviews program effectiveness annually.

## 8. Documentation and Retention
All artifacts (risk analysis, risk register, sanction records, activity reviews) are retained for at least six (6) years from the date of creation or last effective date, whichever is later.
""",
    },
    "hipaa_minimum_necessary_access": {
        "title": "HIPAA Minimum Necessary Access Policy",
        "hipaa_controls": ["164.502(b)", "164.514(d)"],
        "filename": "hipaa-minimum-necessary-access.md",
        "template": """\
# HIPAA Minimum Necessary Access Policy

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Privacy Officer
**HIPAA Controls:** 45 CFR §§ 164.502(b), 164.514(d)

## 1. Purpose
Implements the HIPAA Minimum Necessary standard: use, disclosure, and requests for PHI are limited to the least amount reasonably necessary to accomplish the intended purpose.

## 2. Scope
Applies to every use, disclosure, or request of PHI by {{ company_name }} workforce members, except in cases exempt from the minimum necessary standard (e.g., disclosures to the individual, to HHS, or required by law).

## 3. Role-Based Access
Access to PHI is assigned by role. The Privacy Officer and each system owner maintain a documented mapping between roles and the categories of PHI each role may access. Role assignments are reviewed at least quarterly.

## 4. Routine Uses and Disclosures
For routine uses and disclosures, {{ company_name }} maintains documented protocols that specify the categories of PHI that may be shared and the workforce members authorized to share them.

## 5. Non-Routine Requests
Non-routine requests (one-off research queries, ad-hoc exports, legal disclosures) are reviewed by the Privacy Officer against the minimum necessary standard before fulfilment. Decisions are documented.

## 6. Incoming Requests
Requests for PHI from other covered entities, business associates, or researchers are reviewed for minimum necessary scope. {{ company_name }} may rely on the requestor's representation if the requestor is a public official acting within the scope of their authority or another covered entity.

## 7. Technical Enforcement
Access control systems enforce role-based restrictions through authentication, authorization, and audit logging. Direct database access to PHI is restricted to named, authorized administrators and all such access is logged.

## 8. Violations and Review
Violations are reported to the Privacy Officer and handled under the Sanctions Policy. This policy is reviewed annually and upon material changes to data flows or roles.
""",
    },
    "hipaa_contingency_plan": {
        "title": "HIPAA Contingency Plan",
        "hipaa_controls": ["164.308(a)(7)"],
        "filename": "hipaa-contingency-plan.md",
        "template": """\
# HIPAA Contingency Plan

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Security Officer
**HIPAA Controls:** 45 CFR § 164.308(a)(7) — Contingency Plan

## 1. Purpose
Establishes and maintains the policies and procedures required by the HIPAA Security Rule to respond to emergencies or other occurrences (e.g., fire, vandalism, system failure, natural disaster) that damage systems containing ePHI.

## 2. Scope
Applies to all {{ company_name }} systems, applications, and data stores that create, receive, maintain, or transmit ePHI.

## 3. Data Backup Plan (§ 164.308(a)(7)(ii)(A))
{{ company_name }} maintains retrievable exact copies of ePHI. Backups are performed on a schedule commensurate with data change rate (daily for transactional systems, weekly minimum otherwise), encrypted at rest, stored in a geographically separate location, and retention policies are documented.

## 4. Disaster Recovery Plan (§ 164.308(a)(7)(ii)(B))
A documented procedure exists to restore any loss of ePHI-containing systems. Recovery Time Objective (RTO) and Recovery Point Objective (RPO) are defined for each critical system and reviewed annually.

## 5. Emergency Mode Operation Plan (§ 164.308(a)(7)(ii)(C))
Procedures define how {{ company_name }} continues critical business processes protecting ePHI during an emergency, including fallback access mechanisms and pre-authorised break-glass accounts with post-event review.

## 6. Testing and Revision (§ 164.308(a)(7)(ii)(D))
The contingency plan is tested at least annually using tabletop exercises and/or technical restore tests. Results, gaps, and remediation actions are documented and fed into the next revision.

## 7. Applications and Data Criticality Analysis (§ 164.308(a)(7)(ii)(E))
{{ company_name }} maintains a prioritised list of applications and data needed to support other contingency plan components, reviewed whenever the system inventory changes materially.

## 8. Roles and Responsibilities
The Security Officer owns the plan. System owners execute restore procedures. Executive leadership authorises emergency mode operations.

## 9. Documentation and Retention
Plans, test results, and activation records are retained for six (6) years.
""",
    },
}


def generate_hipaa_policy(
    policy_id: str,
    company_name: str = "Acme Corp",
    effective_date: str | None = None,
    **kwargs,
) -> str:
    """Render a single HIPAA policy document from its template."""
    if policy_id not in HIPAA_POLICIES:
        raise ValueError(
            f"Unknown HIPAA policy: {policy_id}. Available: {list(HIPAA_POLICIES.keys())}"
        )

    policy = HIPAA_POLICIES[policy_id]
    env = Environment(loader=BaseLoader(), autoescape=False)
    template = env.from_string(policy["template"])

    if effective_date is None:
        effective_date = datetime.now().strftime("%Y-%m-%d")

    return template.render(
        company_name=company_name,
        effective_date=effective_date,
        **kwargs,
    )


def generate_all_hipaa_policies(
    company_name: str = "Acme Corp",
    output_path: Path | str = "data/policies",
    **kwargs,
) -> list[Path]:
    """Render all HIPAA policies and write them to ``output_path``."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    paths: list[Path] = []
    for policy_id, policy in HIPAA_POLICIES.items():
        content = generate_hipaa_policy(policy_id, company_name=company_name, **kwargs)
        filepath = output_dir / policy["filename"]
        filepath.write_text(content, encoding="utf-8")
        paths.append(filepath)
    return paths


def list_hipaa_policies() -> list[dict]:
    """Return metadata for every HIPAA policy template."""
    return [
        {
            "id": pid,
            "title": p["title"],
            "hipaa_controls": p["hipaa_controls"],
            "filename": p["filename"],
        }
        for pid, p in HIPAA_POLICIES.items()
    ]
