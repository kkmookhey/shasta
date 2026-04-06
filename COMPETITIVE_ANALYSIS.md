# Competitive Landscape Analysis — Compliance & AI Security (April 2026)

## The Two Markets Shasta + Whitney Compete In

**Market 1: Compliance Automation** — $10-30K/year SaaS tools that help startups achieve SOC 2, ISO 27001, HIPAA.

**Market 2: AI Security & Governance** — Rapidly consolidating market where $96B in M&A happened in 2024-2025, driven by EU AI Act enforcement and enterprise AI adoption.

Shasta competes in Market 1. Whitney competes in Market 2. Together, they cover both — which no single product in either market does today.

---

## Market 1: Compliance Automation Players

### Vanta — The Category Leader

**Valuation:** $2.45B (Series D, $150M raised July 2025)
**Pricing:** $10,000-$80,000/year (median $20,000/year)
**Customers:** 9,000+ companies

| Capability | Vanta | Shasta |
|-----------|-------|--------|
| SOC 2 automated checks | ~200+ across 35 frameworks | 72 checks (46 AWS + 26 Azure) across 2 frameworks |
| Cloud providers | AWS, Azure, GCP, OCI | AWS, Azure |
| SaaS integrations | 300+ (Okta, Google Workspace, Datadog, Jira, Slack, etc.) | 3 (GitHub, Slack, Jira) |
| Trust Center | Yes — AI-powered, conversational Q&A for visitors | Not yet |
| Questionnaire Automation | Yes — AI automates 80% of responses, 95% acceptance rate | Not yet |
| Policy generation | Yes — templates + AI customization | Yes — 8 templates with Jinja2 |
| Vendor risk management | Yes — active tracking + assessments | Policy only |
| Continuous monitoring | Yes — real-time | Yes — AWS Config Rules + EventBridge |
| Access reviews | Yes — automated | Yes — AWS + Azure |
| Evidence collection | Yes — continuous | Yes — 17 AWS + Azure snapshot types |
| SBOM / supply chain | No | Yes — CycloneDX + OSV.dev + CISA KEV |
| Threat intelligence | No | Yes — personalized daily advisories |
| Pen testing | No (partner referral) | Yes — automated attack surface analysis |
| Risk register | Yes | Yes — auto-seeded from findings |
| AI governance | Announced — basic questionnaire features | Yes (Whitney) — code scanning + cloud checks + ISO 42001 + EU AI Act |
| Remediation | Guided steps | Terraform code generation (36 templates) |
| Interface | Web dashboard | AI-native CLI (conversational) |
| Pricing | $10K-$80K/year | $0 (open source) |
| Self-hosted | No | Yes — runs locally, no SaaS dependency |

**Vanta's moat:** 300+ integrations, 9,000 customers, brand recognition, dedicated auditor network.
**Shasta's edge:** AI-native interface, Terraform remediation, SBOM/threat intel, pen testing, AI governance, zero cost, self-hosted, no data leaves your machine.

### Drata — The Agentic Challenger

**Valuation:** $1B+ (backed by ICONIQ, GGV)
**Pricing:** $7,500-$55,000/year
**Positioning:** "Agentic Trust Management Platform" — autonomous AI agents for compliance

| Capability | Drata | Shasta |
|-----------|-------|--------|
| Autonomous AI agents | Yes — agents automate compliance tasks | Claude Code IS the agent |
| Multi-framework | SOC 2, ISO 27001, HIPAA, GDPR, PCI DSS + 14 more | SOC 2, ISO 27001, ISO 42001, EU AI Act |
| Real-time monitoring | Yes | Yes (AWS-native) |
| Audit hub | Yes — auditors access directly | Reports + evidence (PDF/HTML) |
| Dashboard | Yes — visual compliance dashboard | CLI + HTML reports |
| Risk management | Yes | Yes — auto-seeded risk register |
| Pricing | $7,500-$55,000/year | $0 |

**Drata's moat:** "Agentic" positioning, strong multi-framework coverage, audit hub.
**Shasta's edge:** AI-native from day 1 (not bolted on), code-level analysis, AI governance layer.

### Secureframe — The Integration King

**Pricing:** $7,500-$100,000/year (median $20,500)
**Positioning:** 100+ integrations, compliance expert templates

| Capability | Secureframe | Shasta |
|-----------|------------ |--------|
| Integrations | 100+ | 3 + cloud-native |
| Policy templates | Expert-written, version-controlled | 8 SOC 2 templates |
| Vendor management | Yes — centralized with reminders | Policy only |
| Employee management | Yes — onboarding/offboarding tracking | Not yet |
| Custom frameworks | Bring your own framework | Not yet (roadmap) |

### Sprinto, Thoropass, OneLeet — The Challengers

| Company | Pricing | Differentiator |
|---------|---------|---------------|
| Sprinto | $7,500-$20,000/year | Widest framework coverage, BYOF |
| Thoropass | $14,500+/year | Bundled audit + platform |
| OneLeet | $15,000-$50,000/year | Assigned security engineer ("done for you") |

---

## Market 2: AI Security Players

### The Acquisitions (2024-2026) — What Got Bought and Why

| Company | Acquirer | Price | Year | What They Did |
|---------|---------|-------|------|--------------|
| **Wiz** | Google | **$32B** | 2026 | Cloud + AI security platform. Context graph connecting code, cloud, and runtime. AI-SPM, attack path analysis. |
| **Protect AI** | Palo Alto Networks | ~$500M | 2025 | AI Radar: ML supply chain security, ML BOM, model scanning. Code-first approach to ML pipeline security. |
| **CalypsoAI** | F5 | $180M | 2025 | Real-time AI guardrails, red-teaming at scale (10,000+ attack prompts/month), data leakage prevention. |
| **Lakera** | Check Point | Undisclosed | 2025 | AI-native prompt injection detection, guardrails for LLMs. |
| **Promptfoo** | OpenAI | Undisclosed | 2026 | Open-source LLM evaluation + security testing. Adversarial testing (prompt injection, jailbreaks, data leaks). 150K+ developers, 25% of Fortune 500. |
| **Aim Security** | Cato Networks | Undisclosed | 2025 | AI security posture management. |

**Total AI security M&A in 2024-2025:** $96B across 400 transactions (270% YoY increase).

### The Funded Independents

| Company | Funding | Valuation | What They Do |
|---------|---------|-----------|-------------|
| **Noma Security** | $132M | ~$500M+ | AI agent security: discovery, posture management, runtime protection. Agentic Risk Map (ARM). 1,300% ARR growth in 2025. |
| **WitnessAI** | $85M | ~$300M+ | "Confidence layer" for enterprise AI: agent activity tracking, policy enforcement, prompt tampering detection. |
| **HiddenLayer** | $56M | ~$200M+ | AI supply chain security: discovers AI models/agents/MCP servers, scores risk, blocks installs. 4 modules: Discovery, Supply Chain, Attack Sim, Runtime. |
| **7AI** | $130M | $700M | Largest cybersecurity Series A ever. AI-powered autonomous defense. |

### What The Big Players Are Building

| Company | AI Security Strategy |
|---------|---------------------|
| **Palo Alto Networks** | Prisma AIRS (from Protect AI acquisition) — "industry's most comprehensive AI security platform" |
| **Google/Wiz** | Wiz AI-SPM extending to all clouds. AI threat detection and response. Agentic AI security strategy. |
| **ServiceNow** | Spent $11.6B on: Armis ($7.75B), Moveworks ($2.85B), Veza ($1B) — converging IT ops + AI security |
| **Microsoft** | Copilot for Security, Defender for AI, Azure AI Content Safety |
| **OpenAI** | Promptfoo acquisition — baking security testing into the Frontier platform |

---

## The Gap Map: What Exists vs. What We Built

### Compliance Automation (Market 1)

| Feature | Vanta | Drata | Secureframe | **Shasta** |
|---------|-------|-------|-------------|------------|
| SOC 2 | Yes | Yes | Yes | **Yes** |
| ISO 27001 | Yes | Yes | Yes | **Yes** |
| HIPAA | Yes | Yes | Yes | Roadmap |
| GCP | Yes | Yes | Yes | Roadmap |
| AWS checks | ~100+ | ~80+ | ~80+ | **46** |
| Azure checks | ~80+ | ~60+ | ~60+ | **26** |
| SaaS integrations | 300+ | 200+ | 100+ | **3** |
| AI-powered questionnaire | Yes | Yes | Yes | Roadmap |
| Trust center | Yes | Yes | No | Roadmap |
| Vendor management | Yes | Yes | Yes | Policy only |
| Employee tracking | Yes | Yes | Yes | No |
| Terraform remediation | No | No | No | **Yes (36 templates)** |
| SBOM + supply chain | No | No | No | **Yes** |
| Threat intelligence | No | No | No | **Yes** |
| Pen test automation | No | No | No | **Yes** |
| Multi-region scanning | Yes | Yes | Yes | **Yes** |
| Self-hosted / no SaaS | No | No | No | **Yes** |
| AI-native interface | Partial (agents) | Partial (agents) | No | **Yes (Claude Code)** |
| **Cost** | $10-80K/yr | $7.5-55K/yr | $7.5-100K/yr | **$0** |

### AI Security & Governance (Market 2)

| Feature | Noma ($132M) | HiddenLayer ($56M) | CalypsoAI (F5) | Protect AI (PAN) | Promptfoo (OpenAI) | **Whitney** |
|---------|-------------|-------------------|----------------|-----------------|-------------------|-------------|
| AI system discovery | Yes | Yes | No | Yes | No | **Yes** |
| AI agent security | Yes (ARM) | Partial | Partial | No | No | **Yes (code checks)** |
| Model scanning | No | Yes | No | Yes | No | Roadmap |
| Prompt injection detection | Runtime | No | Yes (runtime) | No | Yes (testing) | **Yes (code analysis)** |
| Red-teaming / attack sim | No | Yes | Yes (10K/month) | No | Yes | Roadmap |
| AI supply chain / SBOM | No | Yes | No | Yes (MLBOM) | No | **Yes (AI SBOM)** |
| Code repository scanning | No | No | No | No | No | **Yes (15 checks)** |
| ISO 42001 mapping | No | No | No | No | No | **Yes** |
| EU AI Act classification | No | No | No | No | No | **Yes** |
| NIST AI RMF | No | No | No | No | No | **Yes (via ISO 42001)** |
| AI policy generation | No | No | No | No | No | **Roadmap (8 templates)** |
| Runtime guardrails | No | No | Yes | No | No | No (code-time only) |
| Pricing | Enterprise SaaS | Enterprise SaaS | Enterprise SaaS | Enterprise SaaS | Open source + SaaS | **$0 (open source)** |

---

## The Strategic Insight

### What the funded companies have that we don't:
1. **Runtime protection** — Noma, CalypsoAI, and WitnessAI intercept AI calls in real-time. Whitney operates at code-time and scan-time, not runtime.
2. **300+ SaaS integrations** — Vanta's moat is breadth of integrations (Okta, Google Workspace, Datadog, etc.). Shasta has 3.
3. **Enterprise sales teams** — They have SDRs, AEs, customer success. We have a GitHub repo.
4. **Web dashboards** — Every competitor has a visual dashboard. We have CLI + HTML reports.

### What we have that the funded companies don't:

1. **Code-level AI security analysis** — No AI security company scans your actual code for prompt injection risks, PII in prompts, or unguarded agents. Noma does runtime. CalypsoAI does runtime. HiddenLayer does model scanning. Promptfoo does evaluation testing. **Nobody scans the code.** Whitney does.

2. **Compliance + AI governance in one tool** — Vanta does compliance but not AI governance. Noma does AI security but not SOC 2. **Nobody does both.** Shasta + Whitney does.

3. **Three AI compliance frameworks mapped** — No product maps findings to ISO 42001 + EU AI Act + NIST AI RMF simultaneously. Whitney does.

4. **Terraform remediation** — No compliance platform generates actual infrastructure-as-code fixes. They all give you a description and say "go fix it." Shasta gives you the Terraform.

5. **Zero cost, self-hosted** — Every competitor is $7,500-$80,000/year SaaS. Shasta + Whitney is free, runs locally, and your data never leaves your machine.

6. **AI-native interface** — Vanta and Drata are bolting AI agents onto web dashboards. Shasta was born in Claude Code — the AI IS the interface. You don't navigate menus; you have a conversation.

7. **Built in public, in 8.5 hours** — The funded companies spent years and hundreds of millions of dollars. One practitioner + Claude Code built a competitive platform in a week. That's the story.

---

## The Two Audiences

### Audience 1: Pre-Series A Startups (The Users)

**Their problem:** Need SOC 2 to close their first enterprise deal. Can't afford $10K/year for Vanta. Don't have a security team.

**What Shasta + Whitney gives them:**
- SOC 2 + ISO 27001 compliance for $0
- AI governance (ISO 42001 + EU AI Act) before their competitors even know these frameworks exist
- Terraform fixes they can review and apply
- Auditor-grade evidence and reports
- All through a conversation, not a dashboard they need to learn

**The value prop:** "Get SOC 2 ready in a weekend, not a quarter. For free."

### Audience 2: Funded Compliance/AI Security Companies (The Wake-Up Call)

**The message:** One domain expert + Claude Code produced in 8.5 hours what you raised $50-150M to build over 2-3 years. The platform has:
- 72 cloud security checks across AWS and Azure
- 45 AI governance checks across code and cloud
- 4 compliance frameworks (SOC 2, ISO 27001, ISO 42001, EU AI Act)
- 36 Terraform remediation templates
- SBOM, threat intelligence, pen testing, risk register
- Multi-region scanning, evidence collection, drift detection
- 100 automated tests
- ~24,500 lines of production code

This isn't a demo. It's a working platform scanning real cloud environments and real code repositories.

**The implication:** The moat isn't the software. It's the distribution, the integrations, the enterprise sales motion. But the core product? That's an afternoon of vibe coding. And it's only going to get faster.

---

## What to Build Next (Priority by Competitive Gap)

| Priority | Feature | Why | Competitor Parity |
|----------|---------|-----|-------------------|
| 1 | **Okta integration** | 70%+ of SOC 2 startups use Okta. Auditors always ask. | Vanta, Drata, Secureframe all have it |
| 2 | **Trust center page** | Vanta charges $5K/yr for this. We can generate it for free. | Vanta's premium feature |
| 3 | **Questionnaire auto-fill** | Saves 10-20 hrs/quarter. High-value, uses existing evidence. | Vanta AI's flagship feature |
| 4 | **GCP checks** | Table stakes for multi-cloud. | All competitors have it |
| 5 | **HIPAA framework** | Opens healthcare vertical. | Vanta, Drata, Secureframe |
| 6 | **AI runtime guardrails** | Whitney's gap vs. Noma/CalypsoAI. | Noma, CalypsoAI, WitnessAI |
| 7 | **Visual dashboard** | CLI limits adoption by non-technical users. | Every competitor |
| 8 | **More SaaS integrations** | Google Workspace, Datadog, PagerDuty | All competitors |

---

## Sources

### Compliance Platforms
- [Vanta Pricing 2026](https://www.secureleap.tech/blog/vanta-review-pricing-top-alternatives-for-compliance-automation)
- [Vanta Plans and Pricing](https://www.vanta.com/pricing)
- [Vanta Trust Center](https://www.vanta.com/products/trust-center)
- [Vanta Questionnaire Automation](https://www.vanta.com/products/questionnaire-automation)
- [Vanta AI Agent Announcement](https://www.businesswire.com/news/home/20250610126271/en/Introducing-the-Vanta-AI-Agent-to-Scale-Security-and-Transform-Trust)
- [Vanta $150M Series D](https://theaiinsider.tech/2025/07/25/vanta-secures-150m-series-d-to-power-the-future-of-ai-driven-trust/)
- [Drata Pricing 2026](https://www.vendr.com/marketplace/drata)
- [Drata Agentic Platform](https://drata.com/)
- [Drata Review 2026](https://sprinto.com/blog/honest-drata-review/)
- [Secureframe Pricing](https://secureframe.com/pricing)
- [Secureframe Pricing Analysis](https://www.complyjet.com/blog/secureframe-pricing-analysis)
- [Sprinto vs Thoropass](https://sprinto.com/blog/sprinto-vs-thoropass/)
- [Top Compliance Tools 2026](https://www.smartly.rocks/articles/top-6-compliance-tools/)

### AI Security Market
- [$3.6B Funding, $96B M&A in AI Security](https://softwarestrategiesblog.com/2026/03/28/agentic-ai-security-startups-funding-mna-rsac-2026/)
- [2025 AI Security Acquisitions](https://pulse.latio.tech/p/unpacking-the-2025-ai-security-acquisitions)
- [AI Security Market 2025 Funding Data](https://softwarestrategiesblog.com/2025/12/30/ai-security-startups-funding-2025/)
- [Cybersecurity M&A Round-Up March 2026](https://www.infosecurity-magazine.com/news-features/cyber-ma-roundup-march-26/)
- [AI Safety Funding Trends 2022-2026](https://newmarketpitch.com/blogs/news/ai-safety-funding-trends)

### Specific Companies
- [Google Completes Wiz Acquisition ($32B)](https://cloud.google.com/blog/products/identity-security/google-completes-acquisition-of-wiz)
- [Wiz AI-SPM and Agents](https://www.wiz.io/blog/introducing-wiz-agents)
- [Palo Alto Networks Acquires Protect AI](https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-completes-acquisition-of-protect-ai)
- [Noma Security $100M Raise](https://noma.security/blog/noma-security-raises-100m-to-drive-adoption-of-ai-agent-security/)
- [OpenAI Acquires Promptfoo](https://openai.com/index/openai-to-acquire-promptfoo/)
- [F5 Acquires CalypsoAI ($180M)](https://www.f5.com/company/news/press-releases/f5-to-acquire-calypsoai-to-bring-advanced-ai-guardrails-to-large-enterprises)
- [WitnessAI $58M Funding](https://siliconangle.com/2026/01/13/witnessai-debuts-agentic-security-enterprises-deploy-autonomous-ai-agents/)
- [HiddenLayer AI Threat Landscape 2026](https://www.prnewswire.com/news-releases/hiddenlayer-releases-the-2026-ai-threat-landscape-report-spotlighting-the-rise-of-agentic-ai-and-the-expanding-attack-surface-of-autonomous-systems-302716687.html)

### Regulatory
- [ISO 42001 Standard](https://www.iso.org/standard/42001)
- [Gartner: 70% AI Governance Adoption by 2026](https://www.isaca.org/resources/news-and-trends/isaca-now-blog/2025/iso-42001-balancing-ai-speed-safety)
- [EU AI Act Timeline](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- [EU AI Act 2026 Compliance Guide](https://secureprivacy.ai/blog/eu-ai-act-2026-compliance)
- [Microsoft ISO 42001 Compliance](https://learn.microsoft.com/en-us/compliance/regulatory/offering-iso-42001)
