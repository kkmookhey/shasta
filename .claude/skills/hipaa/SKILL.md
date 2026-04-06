---
name: hipaa
description: Run a HIPAA Security Rule gap analysis against your cloud environment.
user-invocable: true
---

# HIPAA Gap Analysis

You are running a HIPAA Security Rule compliance assessment for a founder. Same cloud checks as SOC 2, but mapped to HIPAA Security Rule safeguards (Administrative, Physical, Technical).

## What to do

Read `shasta.config.json` for `python_cmd`. Use that for all commands (shown as `<PYTHON_CMD>`).

### Run HIPAA scan + generate report

```bash
<PYTHON_CMD> -c "
import json
from shasta.config import get_aws_client
from shasta.scanner import run_full_scan
from shasta.compliance.hipaa_mapper import get_hipaa_control_summary
from shasta.compliance.hipaa_scorer import calculate_hipaa_score
from shasta.reports.hipaa_report import save_hipaa_report
from shasta.db.schema import ShastaDB

client = get_aws_client()
client.validate_credentials()
print('Running HIPAA compliance scan...')
scan = run_full_scan(client, framework='hipaa')

db = ShastaDB(); db.initialize(); db.save_scan(scan)

report_path = save_hipaa_report(scan)
print(f'Report saved: {report_path}')

score = calculate_hipaa_score(scan.findings)
controls = get_hipaa_control_summary(scan.findings)

output = {
    'report_path': str(report_path),
    'score': {
        'percentage': score.score_percentage,
        'grade': score.grade,
        'passing': score.passing,
        'failing': score.failing,
        'requires_policy': score.requires_policy,
    },
    'by_safeguard': {
        'administrative': {'pass': score.administrative_pass, 'fail': score.administrative_fail},
        'physical': {'pass': score.physical_pass, 'fail': score.physical_fail},
        'technical': {'pass': score.technical_pass, 'fail': score.technical_fail},
    },
    'controls': {
        k: {
            'title': v['title'],
            'safeguard': v['safeguard'],
            'status': v['overall_status'],
            'pass': v['pass_count'],
            'fail': v['fail_count'],
            'soc2_equiv': v['soc2_equivalent'],
            'iso27001_equiv': v['iso27001_equivalent'],
        }
        for k, v in controls.items()
        if v['has_automated_checks'] or v['overall_status'] != 'not_assessed'
    }
}
print(json.dumps(output, indent=2))
"
```

### Present results

- **Score and grade** — explain HIPAA compliance readiness
- **Report path** — mention the saved Markdown report
- **By safeguard:** Administrative, Physical, Technical status
- **Control-by-control breakdown** — grouped by safeguard type, starting with Technical (most relevant for cloud)
- For each failing control: what it requires, what's missing, how to fix
- **Cross-reference to SOC 2 and ISO 27001:** "Fixing 164.312(a)(1) also addresses SOC 2 CC6.1 and ISO 27001 A.5.15/A.8.5 — most of the work overlaps"
- **Policy-required controls:** which need documentation vs. technical fixes (many Administrative safeguards need policies)
- **PHI-specific guidance:** remind about BAAs, data classification, 6-year log retention, minimum necessary standard
- Suggest `/report` for PDF generation, `/remediate` for fix guidance, `/policy-gen` for policy documents
