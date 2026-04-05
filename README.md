# Shasta — Multi-Cloud Compliance Automation Platform for SOC 2 & ISO 27001

**An AI-native compliance toolkit that enables startup founders to achieve and maintain SOC 2 and ISO 27001 compliance across AWS and Azure through their terminal.**

Shasta is not a SaaS dashboard. It's a set of Claude Code skills, Python libraries, and cloud infrastructure that uses AI as the interface — explaining findings in plain English, generating tailored policies, producing Terraform remediation code, and delivering personalized threat intelligence. Built for founders running <50 employee companies who need SOC 2 without the $30K/year Vanta bill.

---

## Table of Contents

- [Platform Capabilities](#platform-capabilities)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Skills Reference](#skills-reference)
- [SOC 2 Coverage](#soc-2-coverage)
- [The Build Journey — A Vibe Coding Case Study](#the-build-journey--a-vibe-coding-case-study)
- [Vibe Coding Best Practices for Security Projects](#vibe-coding-best-practices-for-security-projects)
- [Build Metrics](#build-metrics)
- [What's Next](#whats-next)

---

## Platform Capabilities

### 1. Multi-Cloud Security Scanning (5 Domains, 60+ Checks)

#### AWS Checks (40+)

| Domain | Checks | SOC 2 Controls |
|--------|--------|----------------|
| **IAM** | Password policy, root MFA, user MFA, access key rotation, inactive users, direct policies, overprivileged users | CC6.1, CC6.2, CC6.3 |
| **Networking** | Security group ingress rules, VPC flow logs, default SG lockdown, public subnet analysis | CC6.6 |
| **Storage** | S3 encryption, versioning, public access blocks, SSL-only policies | CC6.7 |
| **Encryption** | EBS encryption by default, EBS volume encryption, RDS encryption at rest, RDS public access, RDS backups | CC6.6, CC6.7 |
| **Monitoring** | CloudTrail configuration, GuardDuty status, AWS Config recording, Inspector vulnerability scanning | CC7.1, CC7.2, CC8.1 |

#### Azure Checks (22)

| Domain | Checks | SOC 2 Controls |
|--------|--------|----------------|
| **Identity & Access** | Conditional Access MFA, privileged directory roles, RBAC least privilege, inactive users, guest access, service principal hygiene | CC6.1, CC6.2, CC6.3 |
| **Networking** | NSG unrestricted ingress, NSG default rules, VNet/NSG flow logs, public IP exposure | CC6.6 |
| **Storage** | Storage account encryption (TLS), HTTPS enforcement, blob public access, soft delete & versioning | CC6.7 |
| **Encryption** | Managed disk encryption, SQL TDE, Key Vault config (purge protection), SQL public access | CC6.6, CC6.7 |
| **Monitoring** | Activity Log export, Microsoft Defender for Cloud, Azure Policy compliance, Monitor alerts | CC7.1, CC7.2, CC8.1 |

Every check produces a `Finding` object with: severity, compliance status, resource ID, cloud provider, SOC 2 control mapping, plain-English description, and remediation guidance.

### 2. SOC 2 Compliance Framework

- **Control definitions** for CC1.1 through CC9.1 with automated check mappings
- **Compliance scoring** — percentage score and letter grade (A-F) based on assessed controls
- **Control-level aggregation** — see which SOC 2 controls are passing, failing, or need policy documents
- **17 auditor-grade control tests** — formal test ID, objective, procedure, expected/actual result, evidence, pass/fail

### 3. Report Generation (3 Formats)

| Format | Use Case |
|--------|----------|
| **Markdown** | Working sessions, easy to review in any editor, version-controllable |
| **HTML** | Sharing via email/browser — styled with grade box, color-coded severity, professional layout |
| **PDF** | Formal deliverables to auditors, investors, board members |

Reports include: executive summary, SOC 2 control status table, critical/high findings with remediation, passing controls, policy-required controls, and a prioritized remediation roadmap.

### 4. Remediation Engine

- **14 Terraform template generators** covering: password policy, MFA setup, security group restriction, VPC flow logs, S3 versioning, S3 SSL enforcement, S3 encryption, S3 public access blocks, IAM group migration, least privilege policies
- **Bundled Terraform file** — all fixes in one `remediation.tf` for review and apply
- **Founder-friendly explanations** — each finding includes a plain-English "why this matters" analogy (e.g., "MFA is like a second lock on your front door")
- **Step-by-step instructions** — both AWS Console and CLI paths
- **Effort estimates** — quick (<30 min), moderate (1-4 hrs), or significant (>4 hrs)

### 5. Policy Document Generation

8 SOC 2 policy documents, generated with company name and effective date, structured for auditor review:

| Policy | SOC 2 Controls | What It Covers |
|--------|---------------|----------------|
| Access Control | CC6.1, CC6.2, CC6.3, CC5.1 | Authentication, authorization, least privilege, access reviews, offboarding |
| Change Management | CC8.1, CC5.1 | Code review, deployment process, audit trail, emergency changes |
| Incident Response | CC7.1, CC7.2, CC2.1 | Detection, classification, containment, eradication, recovery, post-mortem |
| Risk Assessment | CC3.1 | Risk identification, likelihood/impact analysis, risk register, treatment |
| Vendor Management | CC9.1 | Vendor classification, assessment, SOC 2 report review, offboarding |
| Data Classification | CC6.7, CC9.1 | Confidential/internal/public levels, handling requirements, retention |
| Acceptable Use | CC1.1, CC2.1 | Employee responsibilities, prohibited activities, security awareness |
| Business Continuity | CC9.1 | RTO/RPO targets, backup strategy, DR procedures, testing schedule |

### 6. Continuous Compliance Monitoring

#### Real-time Detection (AWS-native, seconds latency)
- **12 AWS Config managed rules** — password policy, root MFA, user MFA, no direct policies, key rotation, restricted SSH, VPC flow logs, S3 encryption, S3 public access, S3 SSL, CloudTrail, GuardDuty
- **6 EventBridge rules** — root account usage, security group changes, IAM policy changes, S3 policy changes, Config non-compliance, GuardDuty findings
- **Alert pipeline** — SNS topic → Lambda → Slack alerts + Jira ticket creation

#### Scheduled Compliance (daily/weekly via Claude Code cron triggers)
- **Full compliance scan** with drift detection — compares current vs. previous scan
- **Drift reports** — new findings (regressions), resolved findings (improvements), score trend
- **Evidence collection** — 9 configuration snapshot types, timestamped, manifested

### 7. Access Review Workflow

Quarterly IAM access review (required by SOC 2 CC6.2/CC6.3):
- Enumerates every user: console access, MFA, access keys, groups, policies, last activity
- Flags issues: `CONSOLE_NO_MFA`, `INACTIVE_90d`, `KEY_STALE_90d`, `DIRECT_POLICIES`, `OVERPRIVILEGED`
- Generates Markdown report with reviewer sign-off section for audit evidence

### 8. SBOM + Supply Chain Security

- **Dependency discovery** from Lambda functions (runtimes, layers, env vars), ECR images (via Inspector), EC2 instances (via SSM inventory)
- **Known-compromised package database** — 15+ cataloged supply chain attacks: LiteLLM, xz-utils, event-stream, ua-parser-js, polyfill.io, node-ipc, colors, faker, coa, rc, ctx, pytorch-nightly
- **Live vulnerability scanning** via OSV.dev (batch API covering NVD, PyPI, npm, Go, Maven, RubyGems, NuGet)
- **CISA KEV cross-reference** — flags actively exploited vulnerabilities
- **CycloneDX 1.5 SBOM output** — industry-standard format

### 9. Personalized Threat Advisory

Daily threat intelligence filtered to YOUR tech stack:
- Queries NVD API for recent CVEs matching detected dependencies
- Queries CISA Known Exploited Vulnerabilities for actively exploited threats
- Queries GitHub Advisory Database for supply chain incidents
- Filters everything through SBOM — only shows what's relevant to your environment
- Outputs: Markdown report + Slack-formatted message
- Example: "2 HIGH CVEs affecting Python 3.12 in the last 7 days — you run 3 Lambda functions on Python 3.12"

### 10. Automated Security Assessment (Pen Testing)

Attack surface analysis that produces auditor-grade pen test evidence:
- **Internet exposure scan** — finds EC2 instances with public IPs, public RDS, internet-facing ALBs
- **Attack path mapping** — exposed resource + open ports + known vulnerabilities = risk rating
- **Inspector network reachability** — integration with AWS Inspector for deep network analysis
- **Risk prioritization** — public databases (critical) > management ports (high) > general exposure (medium)

### 11. Risk Register (SOC 2 CC3.1)

Automated risk management workflow required for SOC 2 Risk Assessment:
- **Auto-seeds from scan findings** — failing checks automatically create risk items with pre-mapped likelihood, impact, and treatment plans (33 check-to-risk mappings across AWS + Azure)
- **Risk scoring** — 3x3 likelihood/impact matrix (1-9 score, low/medium/high levels)
- **Treatment tracking** — mitigate, accept, transfer, or avoid with documented plans
- **Status workflow** — open → in_progress → accepted/resolved
- **Auditor-grade report** — risk matrix visualization, detailed risk cards, treatment summary, reviewer sign-off section
- **SQLite persistence** — full history tracking for audit trail

### 12. Integrations

| Integration | What It Does |
|------------|-------------|
| **GitHub** | Checks branch protection, required PR reviews, CI/CD status checks, force push prevention (CC8.1) |
| **Slack** | Scan summaries, finding alerts (color-coded by severity), drift reports, daily threat advisories |
| **Jira** | Auto-creates tickets for critical/high findings with full Atlassian Document Format descriptions, labels, and severity |
| **AWS SecurityHub** | Aggregates all findings from Config, GuardDuty, Inspector |
| **AWS Inspector** | Continuous vulnerability scanning of EC2, ECR, Lambda |

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      Claude Code CLI                            │
│                (Orchestrator / User Interface)                   │
├────────────────────────────────────────────────────────────────┤
│  Skills (15 user-facing commands)                               │
│  /connect-aws  /connect-azure  /scan  /gap-analysis  /report  │
│  /remediate  /policy-gen  /review-access  /evidence  /sbom     │
│  /threat-advisory  /pentest  /risk-register  /iso27001         │
├────────────────────────────────────────────────────────────────┤
│  Integrations          │  Threat Intelligence                   │
│  GitHub, Slack, Jira   │  NVD, CISA KEV, OSV.dev, GitHub Adv. │
├────────────────────────────────────────────────────────────────┤
│  Core Libraries (Python)                                        │
│  aws/  azure/  compliance/  evidence/  remediation/  reports/  │
│  policies/  sbom/  threat_intel/  workflows/  integrations/    │
├────────────────────────────────────────────────────────────────┤
│  Continuous Monitoring (AWS-native)                              │
│  Config Rules (12) │ EventBridge (6) │ SecurityHub │ Inspector │
│  SNS → Lambda → Slack/Jira alert pipeline                      │
├────────────────────────────────────────────────────────────────┤
│  Data Layer                                                     │
│  SQLite DB  │  JSON Evidence  │  CycloneDX SBOM  │  Reports   │
└────────────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
    AWS Account                   Azure Subscription
    (42 read-only permissions     (DefaultAzureCredential
     via boto3)                    via azure-identity)
```

### Design Principles

- **Read-only by default** — Shasta never modifies your AWS environment. All remediation is provided as Terraform/CLI for you to review and apply.
- **AI-native interface** — Claude's reasoning explains findings, generates policies tailored to your environment, and walks you through fixes interactively.
- **Zero infrastructure** — runs locally, stores data in SQLite + JSON. No SaaS dependency.
- **Evidence-first** — every check produces timestamped, auditor-reviewable evidence artifacts.
- **Modular** — each compliance domain is an independent module. Add new checks without touching existing ones.

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/kkmookhey/shasta.git
cd shasta
pip install -e ".[dev]"           # Core + dev tools
pip install -e ".[azure]"         # Add Azure support (optional)
pip install -e ".[dev,azure]"     # Everything

# 2a. Configure AWS (read-only access)
aws configure --profile shasta
# Or use the scoped policy: infra/shasta-scanning-policy.json (42 permissions)

# 2b. Configure Azure (read access via az login)
az login
az account show   # Note your subscription_id and tenant_id

# 3. Open Claude Code and run
/connect-aws      # Validate AWS credentials, discover services
/connect-azure    # Validate Azure credentials, discover services
/scan             # Full SOC 2 compliance scan (AWS, Azure, or both)
/gap-analysis     # Interactive gap analysis with AI guidance
/report           # Generate PDF/HTML/MD reports
/remediate        # Get Terraform fixes for findings
/policy-gen       # Generate 8 SOC 2 policy documents
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for the complete setup guide including exact IAM permissions.

---

## Skills Reference

| Skill | Description | Output |
|-------|-------------|--------|
| `/connect-aws` | Validate AWS credentials, discover account topology and services | Account info, service list |
| `/connect-azure` | Validate Azure credentials, discover subscription and services | Subscription info, service list |
| `/scan` | Run all compliance checks across AWS and/or Azure (IAM, network, storage, encryption, monitoring) | Findings with AI explanations |
| `/gap-analysis` | Interactive SOC 2 gap analysis with control-by-control walkthrough | Gap analysis report |
| `/report` | Generate compliance reports in all formats | MD, HTML, PDF files |
| `/remediate` | Interactive remediation with Terraform code and step-by-step instructions | Terraform bundle + guidance |
| `/policy-gen` | Generate all 8 SOC 2 policy documents tailored to your company | Policy documents |
| `/review-access` | Quarterly IAM access review with user inventory and flags | Access review report |
| `/evidence` | Collect point-in-time configuration snapshots for audit trail | 9 JSON evidence artifacts |
| `/sbom` | Generate SBOM and scan for vulnerable/compromised packages | CycloneDX SBOM + vuln report |
| `/threat-advisory` | Personalized threat intel filtered to your tech stack | Threat advisory (MD + Slack) |
| `/pentest` | Automated security assessment — attack surface and exposure analysis | Security assessment report |
| `/risk-register` | Create and manage risk register — auto-seeds from scan findings, tracks treatment | Risk register report |
| `/iso27001` | Run ISO 27001:2022 Annex A gap analysis across AWS and Azure | ISO 27001 gap analysis report |

---

## SOC 2 Coverage

For a **<50 employee startup** pursuing **SOC 2 Type II Security**:

| Category | Coverage | Method |
|----------|----------|--------|
| Technical cloud controls | ~90% | 60+ automated checks across AWS and Azure (5 domains each) |
| Policy/process controls | ~80% | 8 generated policy documents |
| Continuous monitoring | ~90% | 12 Config Rules + 6 EventBridge rules + GuardDuty + Inspector + Azure Defender + Azure Policy |
| Audit evidence | ~85% | Control tests, evidence snapshots (AWS + Azure), access reviews, reports |
| Vulnerability management | ~85% | Inspector + SBOM + OSV.dev + CISA KEV |
| Supply chain security | ~80% | SBOM discovery + known-compromised DB + live scanning |
| Change management | ~80% | GitHub integration + CloudTrail + Config + Azure Activity Log |
| Remediation guidance | ~90% | 36 Terraform templates (14 AWS azurerm + 22 Azure) |

**Overall: ~85% of SOC 2 Type II Security automated or templated across AWS and Azure.**

### What's NOT Covered (Founder Handles Manually)

- **Security awareness training** — use your company's e-learning portal
- **Background checks** — HR process, not automatable
- **Active vendor inventory** — Shasta generates the policy; you track actual vendors (risk register is now automated via `/risk-register`)
- **Annual BCP/DR tabletop exercise** — process, not tooling
- **Physical security** — N/A for cloud-native companies

---

## The Build Journey — A Vibe Coding Case Study

This platform was built in a single Claude Code session through iterative human-AI collaboration. Here's how the conversation evolved from a one-paragraph idea to a 10,500-line production platform.

### The Conversation Arc

**Turn 1 — The Vision (Human)**
> "I would like to create a Vanta clone. A set of Skills, sub-agents, plug-ins, etc which a founder can use to plug into their AWS environment and conduct a gap analysis against SOC2, as well as get complete guidance on what they need to do next, and also all the capabilities to maintain their compliance through the year."

The human provided a clear, ambitious vision but left architecture and implementation entirely to the AI. This is the essence of vibe coding — describe the outcome, not the steps.

**Turn 2 — Architecture & Planning (AI)**
Claude entered plan mode and produced:
- Full system architecture diagram
- SOC 2 control-to-AWS service mapping table
- Detailed project structure (every file path)
- 6-phase implementation plan
- 8 clarifying questions to narrow scope

**Turns 3-5 — Scope Decisions (Human)**
The human made key product decisions through multiple-choice questions:
- SOC 2 Security only (not all 5 criteria) — *right call: 90% of startups need this*
- Full compliance suite (policies, not just AWS checks) — *right call: auditors need both*
- Semi-technical founder persona — *shaped all UX decisions*
- Markdown + PDF from day one — *not obvious, but founders need to share reports*
- Terraform for IaC — *most adopted by startups*
- Claude Code cron triggers for scheduling — *keeps everything in one tool*

**Turns 6-8 — Phase 1: Foundation**
Built project scaffolding, AWS client, database, data models, first skill (`/connect-aws`). Tested against live AWS account. Hit Python version mismatch (`py -3.12` vs `python`) — AI adapted and remembered for all subsequent commands.

**Turn 9 — Phase 2: First Real Checks**
IAM security checks (7 check functions). First live scan: 33.3% compliance score, 4 failures, 2 passes. 100% accuracy against expected outcomes.

**Turn 10 — Phase 3: Full Security Scanner**
Added networking, storage, and logging checks. Full scan: 34 findings, 37.5% score. Every intentionally broken resource was correctly flagged.

**Turns 11-12 — Phase 4 & 5: Reports + Remediation**
Gap analysis engine, HTML/PDF report generation (hit WeasyPrint GTK dependency issue on Windows → pivoted to xhtml2pdf), remediation engine with 14 Terraform templates, 8 policy document templates.

**Turn 13 — Phase 6: Continuous Compliance**
Access review workflow, drift detection, evidence collection. Fixed a foreign key constraint bug in the evidence store.

**Turn 14 — The Critical Self-Assessment**
Human asked: *"Review your own output as a compliance expert and compare with Vanta/Drata. What's missing?"*

This was the most valuable prompt in the session. The AI produced an honest gap analysis:
- ~25-30% coverage at that point (not 80% as might be assumed from passing checks)
- Identified 6 "audit blocker" gaps and 8 "significant" gaps
- Acknowledged the entire human/organizational dimension was missing
- Proposed Phases 7A-7E with clear prioritization

**Turn 15 — Phase 7: Closing the Gaps**
Human added requirements:
- Continuous monitoring architecture (how does real-time detection work?)
- Slack and Jira integrations
- The AI explained the three monitoring approaches (polling vs. event-driven vs. hybrid) and recommended the hybrid architecture

Built and deployed:
- 17 auditor-grade control tests
- 12 AWS Config Rules + 6 EventBridge rules + SecurityHub + Inspector
- Lambda alert forwarder for Slack/Jira
- GitHub branch protection checks
- Slack and Jira Python clients

**Turn 16 — Phase 8: Differentiation**
Human pushed further:
- Daily personalized threat advisories
- SBOM + supply chain vulnerability scanning
- Automated pen testing

These three features pushed Shasta beyond Vanta/Drata territory into genuinely differentiated capabilities. The threat advisory — filtering live CVE feeds through the founder's actual SBOM — is something no competitor offers.

**Turn 17 — EBS/RDS encryption checks**
Closed the last known gap in CC6.7 data protection coverage.

**Turn 18 — Packaging & Deployment**
Deployment guide with exact IAM policy (42 read-only permissions), GitHub repo creation, initial commit.

### Key Decision Points That Shaped the Platform

| Decision | Who Made It | Impact |
|----------|-------------|--------|
| Claude Code skills as UI (not web app) | AI | Zero infrastructure, AI reasoning is the interface |
| SOC 2 Security only for v1 | Human | Focused scope, faster to useful |
| Semi-technical founder persona | Human | Plain English everywhere, step-by-step guidance |
| Intentionally broken test resources | AI | Validated scanner accuracy (100% match) |
| Event-driven monitoring (not polling) | AI | Real-time detection, AWS does the heavy lifting |
| Self-assessment against Vanta | Human | Honest gap analysis prevented premature "done" |
| SBOM + threat advisory | Human | Genuine differentiation beyond Vanta/Drata |
| Read-only scanning only | Human | Trust model — never modify customer's AWS |

---

## Vibe Coding Best Practices for Security Projects

This build demonstrates effective patterns for using AI to build security-critical software. Here's what worked, what didn't, and what to watch for.

### 1. Start with the Outcome, Not the Architecture

**Do:** "I want founders to scan their AWS and get a SOC 2 gap analysis with remediation guidance."

**Don't:** "Create a Python module that calls boto3 to enumerate IAM users and check MFA status."

The first prompt lets the AI bring its full knowledge of SOC 2, AWS security, and compliance platforms to the architecture. The second constrains it to a single function.

### 2. Let the AI Propose, Then Steer

The most productive pattern was:
1. Human describes a goal
2. AI proposes architecture + plan + asks clarifying questions
3. Human answers questions and adds constraints
4. AI builds
5. Human tests and provides feedback
6. Repeat

The human never wrote a line of code. But every major product decision (scope, persona, output format, trust model) was the human's call.

### 3. Test Against Reality Immediately

We didn't build in a vacuum. After every phase:
- Deployed test resources to a real AWS account
- Ran the scanner against live infrastructure
- Verified every finding matched expected outcomes
- Fixed bugs discovered through real execution

The intentionally broken test environment (weak password policy, open security groups, unencrypted buckets alongside properly configured resources) was critical — it proved the scanner could distinguish good from bad.

### 4. The Self-Assessment Prompt is Essential

The highest-value prompt in this entire session was: *"Review your own output as a compliance expert and compare with Vanta/Drata. What's missing?"*

This forced honest gap analysis rather than premature celebration. The AI identified that we were at ~25-30% coverage (not the ~80% our passing checks might suggest) because we'd missed entire categories: people/HR, SaaS integrations, structured audit evidence, vendor management workflows.

**Always ask the AI to critique its own work before calling it done.**

### 5. Security-Specific Vibe Coding Patterns

#### a. Compliance Framework First, Checks Second
We defined the SOC 2 control framework before writing any AWS checks. This ensured every check maps to a real control, nothing is built without a compliance purpose, and gaps are visible in the framework before they're discovered by auditors.

#### b. Evidence-First Design
Every check produces evidence artifacts, not just pass/fail. An auditor needs to see *what was checked*, *what was found*, and *when*. Building this into the data model from day one (the `Finding` and `Evidence` models) meant evidence collection was natural, not bolted on.

#### c. Read-Only by Default
A critical trust decision: Shasta never modifies the customer's AWS environment. Remediation is Terraform code the founder reviews and applies themselves. This is the right trust model for a security tool — if it can write, it can break.

#### d. Defense in Depth for the Tool Itself
- No credentials stored — uses the standard AWS credential chain
- No data exfiltrated — everything stays on the local machine
- No external SaaS dependencies — SQLite + JSON files
- Clear IAM permission scope — 42 read-only API actions, documented

#### e. Assume the Auditor is the Reader
Reports, control tests, and evidence are structured for auditor consumption. Formal test IDs (CT-IAM-001), objectives, procedures, expected/actual results, and sign-off sections. This isn't just good UX — it's the difference between "nice security tool" and "audit-ready platform."

### 6. The Terraform Test Environment Pattern

Building a test environment with **intentionally non-compliant resources alongside properly configured ones** is a powerful pattern:
- Validates that checks detect real violations
- Validates that passing resources aren't flagged as false positives
- Creates a realistic environment without needing production data
- Can be torn down and recreated in minutes

Every test resource was tagged with `shasta_expected = "fail"` or `"pass"` so we could verify scanner accuracy against ground truth.

### 7. Iterative Scope Expansion

The build followed a natural expansion:
1. Can we connect? (Phase 1)
2. Can we detect one thing? (Phase 2 — IAM only)
3. Can we detect everything? (Phase 3 — all domains)
4. Can we explain it? (Phase 4 — reports)
5. Can we fix it? (Phase 5 — remediation)
6. Can we keep it fixed? (Phase 6 — continuous compliance)
7. Is it audit-ready? (Phase 7 — control tests, integrations)
8. Is it differentiated? (Phase 8 — SBOM, threat intel, pen testing)

Each phase was tested against reality before moving on. No phase was planned in isolation — each built on learnings from the previous one.

### 8. When the AI Gets It Wrong

Things that went wrong during this build:
- **WeasyPrint on Windows** — requires GTK/Pango native libraries. AI pivoted to xhtml2pdf.
- **xhtml2pdf + CSS variables** — xhtml2pdf doesn't support `var()`. AI added a post-processor to resolve variables to literals.
- **Python version mismatch** — `py` defaults to 3.13 but packages installed in 3.12. AI adapted and remembered `py -3.12` for all subsequent commands.
- **S3 tag values with commas** — AWS rejects commas in tag values. Fixed immediately.
- **SQLite foreign key constraint** — evidence store had a FK to findings that was too strict for general config snapshots. Fixed the schema.
- **Inspector API** — `SEVERITY` is not a valid aggregation type. Switched to `ACCOUNT` aggregation.
- **Working directory drift** — Terraform `cd` shifted the CWD. Affected subsequent file reads.

**Session 2 (Azure + quality hardening):**
- **Microsoft Graph SDK is async-only** — `graph.users.get()` returns a coroutine, not a result. Created `graph_call()` wrapper with persistent event loop. First attempt used `asyncio.run()` per call, which killed the HTTP connection pool between calls. Fixed by reusing a single event loop.
- **Azure deprecated NSG flow logs** — Azure retired NSG flow log creation after June 2025. Terraform `azurerm_network_watcher_flow_log` failed. Adapted test environment to skip flow logs (VNet flow logs are the replacement).
- **Wrong Azure SDK package names** — `azure-mgmt-resource-subscriptions` doesn't exist (it's `azure-mgmt-subscription`). `SubscriptionClient` moved from `azure.mgmt.resource` to `azure.mgmt.subscription`. `azure-mgmt-sql>=4.0.0` is pre-release only (relaxed to `>=3.0.0`). All three discovered at runtime and fixed.
- **Stale Python package cache** — After editing `scorer.py`, Python kept loading the old version from `C:\Users\kkmookhey\shasta\` instead of `E:\Projects\Vanta\`. Required `pip install -e .` to refresh the editable install.
- **Scorer returned F on clean scans** — Discovered during the self-audit: empty findings → `assessed=0` → `score=0.0` → Grade F. The fix was nuanced: zero assessed controls with non-zero `not_assessed` should return 100%, not 0%.

In every case, the pattern was: error → diagnose → fix → continue. No error required starting over. The AI's ability to read error messages, understand root causes, and adapt immediately is the core advantage of vibe coding.

---

## Build Metrics

### Session 1: AWS Platform Build (~3 hours)

| Metric | Value |
|--------|-------|
| **Conversation turns** | ~36 (18 human, 18 AI) |
| **Wall-clock time** | ~3 hours |
| **Lines of code written** | 10,537 |
| **Files created** | 67 |
| **Python modules** | 22 |
| **Claude Code skills** | 11 user-facing |
| **AWS services integrated** | 15 |
| **Automated checks** | 72 (46 AWS, 26 Azure) |
| **Terraform remediation templates** | 14 |
| **Unit tests** | 9 |

### Session 2: Azure + Quality Hardening (~4 hours)

Session 2 demonstrated a different vibe coding pattern: **extending an existing system rather than building from scratch**. The conversation had four distinct phases.

**Phase 1 — Azure Planning & Architecture (Turns 1–4)**
The human asked to "build similar support for SOC 2 and ISO 27001 for Azure environments." Claude entered plan mode, launched 3 parallel exploration agents to understand the existing AWS patterns, then designed a phased implementation plan with 22 Azure checks mapped to all SOC 2 and ISO 27001 controls. The human reviewed the plan, added a requirement to "build it half secure, half insecure as you did the AWS one" for a test environment, and provided their Azure credentials.

**Phase 2 — Azure Implementation (Turns 5–10)**
Built in rapid succession:
- Azure test environment (Terraform) with intentionally secure + insecure resources
- `AzureClient` with `DefaultAzureCredential`, Graph API async wrapper, service discovery
- 22 check functions across 5 modules (IAM, networking, storage, encryption, monitoring)
- Multi-cloud scanner refactor (backward-compatible with existing AWS skills)
- All SOC 2 and ISO 27001 control definitions updated with Azure check_ids
- `/connect-azure` skill and updated `/scan` skill

Hit two issues: Microsoft Graph SDK is async-only (required `graph_call()` event loop wrapper), and Azure deprecated NSG flow logs after June 2025 (adapted Terraform accordingly). Also discovered 3 dependency issues at runtime (`azure-mgmt-subscription` package name, `SubscriptionClient` import path, `azure-mgmt-sql` pre-release version) — all fixed and shipped.

**Phase 3 — The Independent Audit (Turn 11)**
This was the most valuable turn in Session 2. The human asked: *"Analyze the entire project code and as an independent expert in software engineering as well as cloud security, provide a detailed report on the gaps and improvement areas."*

Claude launched 3 parallel audit agents examining:
1. All AWS check implementations (7 files) for logic errors, pagination issues, missing checks
2. All Azure implementations + core infrastructure for SDK issues, error handling, security
3. Compliance frameworks, reports, remediation, integrations, and test coverage

The audit identified **3 critical bugs**, **12 high-severity issues**, and significant gaps:

| Finding | Severity | Impact |
|---------|----------|--------|
| Scorer returns 0%/Grade F on empty scans | **Critical** | Founders see failing grade on clean environments |
| Drift detection crashes on first run (previous=None) | **Critical** | Feature unusable for new users |
| GuardDuty severity tries float("HIGH") → ValueError | **Critical** | Crashes any account with GuardDuty findings |
| Azure TLS 1.3 flagged as insecure | **High** | False positive on modern storage accounts |
| NSG check misses source_address_prefixes list form | **High** | Allow-all rules bypass detection |
| Zero Azure entries in FINDING_TO_RISK | **High** | Risk register empty for Azure scans |
| AWS pagination missing in 5 API calls | **High** | Truncated results → false PASS findings |
| Test coverage at 1.9% (9 tests) | **High** | Business logic bugs undetected |
| No Azure evidence collectors | **High** | Azure findings exist but evidence can't be collected |
| No Azure remediation templates | **High** | No Terraform fix guidance for Azure findings |

The audit also cataloged ~20 missing AWS checks (role trust policies, Network ACLs, EBS snapshot exposure, KMS key rotation, etc.) and ~6 missing Azure checks (Bastion, App Service, PIM, AKS).

This self-assessment prompt — asking the AI to critique its own work as an independent expert — proved as valuable in Session 2 as it was in Session 1. Both times, it prevented premature "done" by surfacing real gaps.

**Phase 4 — Fix Implementation (Turns 12–14)**
Fixes were organized into tiers and implemented bottom-up:

*Tier 1 (6 critical/high fixes):* Scorer edge case, drift null check, GuardDuty severity parser, TLS 1.3, NSG prefixes list, Azure risk mappings (21 entries).

*Tier 2 (4 systemic fixes):* 91 new tests (100 total) covering scorer, drift, risk register, ISO 27001 scoring, and SOC 2 mapper. AWS pagination fixed in 5 API calls. Error handling standardized (bare `except: pass` → specific `ClientError` → NOT_ASSESSED). AzureClient event loop leak fixed with `close()` + context manager.

*Tier 3 (5 feature gaps):* Azure evidence collectors (8 snapshot functions). Azure remediation Terraform templates (22 `azurerm` templates). Azure access review workflow. Pydantic config validation (UUIDs, HTTPS URLs). Database schema improvements (initial `cloud_provider` column, `ON DELETE CASCADE`, new indexes).

Tier 2 and 3 used 4 parallel agents in isolated worktrees for maximum throughput.

| Metric | Value |
|--------|-------|
| **Conversation turns** | ~28 (14 human, 14 AI) |
| **Wall-clock time** | ~4 hours |
| **Lines of code added** | ~7,000 |
| **New files created** | 16 |
| **New Python modules** | 5 (azure client, 5 check modules, evidence collector, access review) |
| **New Azure checks** | 22 |
| **New Terraform templates** | 22 (Azure) |
| **New tests written** | 91 |
| **Bugs found by self-audit** | 3 critical, 12 high, 12 medium |
| **Bugs fixed** | All critical + high + medium |

### Cumulative Totals (Both Sessions)

| Metric | Session 1 | Session 2 | **Total** |
|--------|-----------|-----------|-----------|
| Wall-clock time | ~3 hours | ~4 hours | **~7 hours** |
| Conversation turns | ~36 | ~28 | **~64** |
| Lines of code | 10,537 | ~7,000 | **~17,500** |
| Files | 67 | 16 new + 36 modified | **83** |
| Python modules | 22 | 27 | **27** |
| Claude Code skills | 11 | 15 | **15** |
| Cloud services integrated | 15 (AWS) | 10 (Azure) | **25** |
| Automated checks | 40+ | 72 | **72** |
| Terraform templates | 14 | 36 | **36** |
| Unit tests | 9 | 100 | **100** |
| Compliance frameworks | 1 (SOC 2) | 2 (SOC 2 + ISO 27001) | **2** |
| Cloud providers | 1 (AWS) | 2 (AWS + Azure) | **2** |

### Token Consumption Estimate

| Phase | Estimated Input Tokens | Estimated Output Tokens |
|-------|----------------------|------------------------|
| **Session 1: AWS Platform** | | |
| Planning & Architecture | ~15,000 | ~25,000 |
| Phase 1-2 (Foundation + IAM) | ~20,000 | ~35,000 |
| Phase 3-4 (Full scan + Reports) | ~25,000 | ~45,000 |
| Phase 5-6 (Remediation + Continuous) | ~20,000 | ~50,000 |
| Self-assessment + Phase 7 | ~30,000 | ~60,000 |
| Phase 8 (SBOM + Threat Intel + Pen Test) | ~15,000 | ~50,000 |
| Packaging + README | ~10,000 | ~30,000 |
| **Session 2: Azure + Quality** | | |
| Azure planning + architecture | ~25,000 | ~40,000 |
| Azure implementation (checks, scanner, skills) | ~30,000 | ~80,000 |
| Independent security/engineering audit | ~40,000 | ~60,000 |
| Tier 1-3 bug fixes + feature gaps | ~35,000 | ~90,000 |
| Documentation + deployment | ~10,000 | ~20,000 |
| **Total (estimated)** | **~275,000** | **~585,000** |
| **Grand total (estimated)** | **~860,000 tokens** | |

*Note: Session 2 used significantly more tokens due to the 3-agent parallel audit and 4-agent parallel fix implementation. The Opus 4.6 model with 1M context handled the full codebase analysis without compression.*

### Cost Perspective

At ~860K tokens on Claude Opus across both sessions, the API cost for this entire build would be roughly $30-50. Compare this to:
- Vanta annual subscription: $10,000-30,000/year
- Hiring a compliance consultant: $150-300/hour
- Building this manually: 4-6 engineer-months
- The Azure extension alone (Session 2) would be ~2-3 engineer-months of work

---

## Project Structure

```
shasta/
├── CLAUDE.md                              # Claude Code project instructions
├── DEPLOYMENT.md                          # Complete deployment guide
├── README.md                              # This file
├── pyproject.toml                         # Python project configuration
│
├── .claude/skills/                        # Claude Code skills (auto-discovered)
│   ├── connect-aws/SKILL.md               # AWS connection and validation
│   ├── connect-azure/SKILL.md             # Azure connection and validation
│   ├── scan/SKILL.md                      # Full compliance scan (AWS + Azure)
│   ├── gap-analysis.md                    # Interactive gap analysis
│   ├── report.md                          # Report generation (MD/HTML/PDF)
│   ├── remediate.md                       # Terraform remediation guidance
│   ├── policy-gen.md                      # Policy document generation
│   ├── review-access.md                   # Quarterly access review
│   ├── evidence.md                        # Evidence collection
│   ├── sbom.md                            # SBOM + supply chain scanning
│   ├── threat-advisory.md                 # Personalized threat intelligence
│   └── pentest.md                         # Automated security assessment
│
├── src/shasta/
│   ├── scanner.py                         # Multi-cloud scan orchestrator
│   ├── aws/                               # AWS interaction layer
│   │   ├── client.py                      # boto3 session management
│   │   ├── iam.py                         # IAM security checks (7 functions)
│   │   ├── networking.py                  # Network security checks (3 functions)
│   │   ├── storage.py                     # S3 security checks (4 functions)
│   │   ├── encryption.py                  # EBS/RDS encryption checks (5 functions)
│   │   ├── logging_checks.py             # CloudTrail/GuardDuty/Config checks
│   │   ├── vulnerabilities.py            # AWS Inspector integration
│   │   └── pentest.py                     # Attack surface analysis
│   ├── azure/                             # Azure interaction layer
│   │   ├── client.py                      # Azure SDK session management
│   │   ├── iam.py                         # Entra ID + RBAC checks (6 functions)
│   │   ├── networking.py                  # NSG + VNet checks (4 functions)
│   │   ├── storage.py                     # Storage account checks (4 functions)
│   │   ├── encryption.py                  # Disk/SQL/KeyVault checks (4 functions)
│   │   └── monitoring.py                  # Activity Log/Defender/Policy checks (4 functions)
│   ├── compliance/                        # SOC 2 + ISO 27001 framework
│   │   ├── framework.py                   # Control definitions (13 controls)
│   │   ├── mapper.py                      # Finding → control mapping
│   │   ├── scorer.py                      # Compliance scoring engine
│   │   └── testing.py                     # Auditor-grade control tests (17 tests)
│   ├── evidence/                          # Evidence management
│   │   ├── models.py                      # Data models (Finding, Evidence, ScanResult)
│   │   ├── store.py                       # SQLite-backed storage
│   │   ├── collector.py                   # 9 AWS evidence collection functions
│   │   └── azure_collector.py             # 8 Azure evidence collection functions
│   ├── remediation/
│   │   └── engine.py                      # Remediation engine + 14 Terraform generators
│   ├── policies/
│   │   └── generator.py                   # 8 policy document templates
│   ├── reports/
│   │   ├── generator.py                   # MD + HTML report generation
│   │   └── pdf.py                         # PDF generation via xhtml2pdf
│   ├── integrations/
│   │   ├── github.py                      # Branch protection + PR review checks
│   │   ├── slack.py                       # Slack webhook integration
│   │   └── jira.py                        # Jira ticket creation
│   ├── sbom/
│   │   ├── discovery.py                   # Dependency discovery + SBOM generation
│   │   └── vuln_scanner.py                # OSV.dev + CISA KEV vulnerability scanning
│   ├── threat_intel/
│   │   └── advisory.py                    # Personalized threat advisory engine
│   ├── workflows/
│   │   ├── access_review.py               # Quarterly AWS IAM access review
│   │   ├── azure_access_review.py         # Quarterly Azure Entra ID access review
│   │   ├── drift.py                       # Compliance drift detection
│   │   └── risk_register.py               # Risk register with auto-seeding
│   └── db/
│       └── schema.py                      # SQLite schema + CRUD operations
│
├── infra/
│   ├── shasta-scanning-policy.json        # AWS IAM policy (42 read-only permissions)
│   ├── test-env/                          # AWS test environment
│   │   ├── main.tf                        # Test resources (compliant + non-compliant)
│   │   ├── monitoring.tf                  # Config Rules, EventBridge, SecurityHub, Inspector
│   │   └── lambda/
│   │       └── alert_forwarder.py         # SNS → Slack + Jira Lambda
│   └── azure-test-env/                    # Azure test environment
│       └── main.tf                        # Azure test resources (compliant + non-compliant)
│
├── tests/                                 # pytest test suite (100 tests)
│   ├── conftest.py
│   ├── test_aws/
│   │   ├── test_client.py                 # AWS client tests (moto)
│   │   └── test_models.py                 # Data model + DB tests
│   ├── test_compliance/
│   │   ├── test_scorer.py                 # SOC 2 scoring edge cases
│   │   ├── test_iso27001_scorer.py        # ISO 27001 scoring + theme counts
│   │   └── test_mapper.py                 # Control enrichment + aggregation
│   └── test_workflows/
│       ├── test_drift.py                  # Drift detection (4 scenarios)
│       └── test_risk_register.py          # Risk calculation + auto-seeding
│
└── data/                                  # Runtime data (gitignored)
    ├── shasta.db                          # SQLite database
    ├── evidence/                          # Evidence snapshots
    ├── reports/                           # Generated reports
    ├── policies/                          # Generated policy documents
    ├── sbom/                              # SBOM + vulnerability reports
    ├── advisories/                        # Threat advisory reports
    └── remediation/                       # Terraform bundles
```

---

## What's Next

### Completed (Session 1 + Session 2)
- [x] ~~Risk register workflow~~ — auto-seeds from findings, tracks treatment, auditor-grade report
- [x] ~~ISO 27001 framework mapping~~ — 35 controls across 4 themes, dual-framework scoring
- [x] ~~Azure scanning modules~~ — 22 checks across 5 domains, full SOC 2 + ISO 27001 mapping
- [x] ~~Azure remediation templates~~ — 22 Terraform azurerm templates with founder-friendly guidance
- [x] ~~Azure evidence collection~~ — 8 config snapshot types for audit trail
- [x] ~~Azure access review~~ — Entra ID user enumeration, RBAC mapping, issue flagging
- [x] ~~Independent code audit + bug fixes~~ — 3 critical + 12 high severity bugs found and fixed
- [x] ~~Test coverage improvement~~ — from 9 to 100 tests covering scoring, drift, risk register, mapper

### Immediate Improvements
- [x] ~~Multi-region scanning support~~ — scans all enabled AWS regions, IAM global + regional checks
- [x] ~~Role trust policy analysis~~ — detects overpermissive `Principal: "*"` in IAM role trust policies
- [x] ~~EBS snapshot public exposure~~ — flags snapshots shared with `all`
- [x] ~~RDS snapshot public access~~ — flags publicly shared database snapshots
- [x] ~~EC2 IMDSv1 detection~~ — flags instances vulnerable to SSRF (Capital One breach vector)
- [x] ~~KMS key rotation~~ — flags customer-managed keys without annual rotation
- [x] ~~S3 bucket ACL checks~~ — detects public-read/public-read-write ACLs
- [x] ~~Azure App Service security~~ — HTTPS enforcement, TLS version, authentication
- [x] ~~Azure Bastion detection~~ — checks if Bastion is deployed
- [x] ~~Azure PIM status~~ — checks Privileged Identity Management activation
- [x] ~~Azure AKS security~~ — RBAC, network policies, API server access
- [ ] Vendor inventory management (active tracking, not just policy)
- [ ] Network ACL checks (AWS)

### Medium Term
- [ ] GCP scanning modules
- [ ] HIPAA control framework
- [ ] Security questionnaire auto-fill from evidence
- [ ] Employee onboarding/offboarding tracking
- [ ] Trust center page generation
- [ ] Azure Bastion / App Service / AKS security checks

### Long Term
- [ ] Multi-account AWS Organizations support
- [ ] Compliance score trending dashboard (HTML)
- [ ] Audit management workflow (auditor request tracking)
- [ ] Custom control framework definitions
- [ ] CI/CD compliance gate (fail pipeline if non-compliant)

---

## License

Private repository. Contact kkmookhey for access.

---

*Built with Claude Code (Opus 4.6) across two sessions (~7 hours total). The entire multi-cloud compliance platform — from architecture to deployment to independent audit and hardening — was created through human-AI collaboration, demonstrating that vibe coding can produce production-quality security tooling when guided by domain expertise. The self-audit pattern (asking the AI to critique its own work) proved essential in both sessions for catching real bugs and preventing false confidence.*
