---
name: scan
description: Run SOC 2 compliance checks against the connected AWS account and display findings.
user-invocable: true
---

# Scan

You are running a SOC 2 compliance scan for a semi-technical founder. Explain findings in plain English.

## What to do

Read `shasta.config.json` for `python_cmd`. Use that for all commands (shown as `<PYTHON_CMD>`).

### Check for a recent scan first

Before running a fresh scan, check if a recent one exists (within the last hour). If so, ask the user whether to reuse it or run fresh.

```bash
<PYTHON_CMD> -c "
from shasta.db.schema import ShastaDB
db = ShastaDB(); db.initialize()
scan = db.get_recent_scan(max_age_minutes=60)
if scan:
    print(f'RECENT_SCAN_FOUND|{scan.id}|{scan.completed_at}|{scan.summary.total_findings if scan.summary else 0} findings')
else:
    print('NO_RECENT_SCAN')
# Also check access review cadence
last_review = db.get_last_review_date()
if last_review: print(f'LAST_ACCESS_REVIEW|{last_review}')
else: print('NO_ACCESS_REVIEW_FOUND')
"
```

If a recent scan exists, tell the user: "Found a scan from X minutes ago with Y findings. Use that, or run a fresh scan?" If they want fresh, or none exists, proceed.

### Run fresh scan (with summary mode)

```bash
<PYTHON_CMD> -c "
import json
from shasta.config import get_aws_client
from shasta.scanner import run_full_scan
from shasta.compliance.mapper import get_control_summary
from shasta.compliance.scorer import calculate_score
from shasta.reports.summary import summarize_scan
from shasta.db.schema import ShastaDB

client = get_aws_client()
client.validate_credentials()
print('Running full compliance scan...')
scan = run_full_scan(client)
db = ShastaDB(); db.initialize(); db.save_scan(scan)

score = calculate_score(scan.findings)
summary = summarize_scan(scan)
summary['score'] = {
    'percentage': score.score_percentage,
    'grade': score.grade,
    'controls_passing': score.passing,
    'controls_failing': score.failing,
}
summary['control_summary'] = {
    k: {'title': v['title'], 'overall_status': v['overall_status'], 'pass_count': v['pass_count'], 'fail_count': v['fail_count']}
    for k, v in get_control_summary(scan.findings).items()
    if v['has_automated_checks'] or v['overall_status'] != 'not_assessed'
}
print(json.dumps(summary, indent=2))
"
```

### Present results

- **Always show scan timestamp:** "Scan completed at <time>" or "Based on scan from X minutes ago"
- Show overall score and grade
- For each check group: "X of Y security groups allow unrestricted ingress — top 5 shown, full list in report"
- Critical & high findings with remediation
- SOC 2 control status table
- If last access review is >90 days ago, warn: "Quarterly access review overdue — run /review-access"

### Tone
- Use analogies, be specific, celebrate what's passing, frame low scores as roadmaps
