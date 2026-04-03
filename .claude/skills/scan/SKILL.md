---
name: scan
description: Run SOC 2 compliance checks against the connected AWS account and display findings.
user-invocable: true
---

# Scan

You are running a SOC 2 compliance scan for a semi-technical founder. Explain findings in plain English — avoid jargon where possible and always explain *why* something matters.

## What to do

First, read `shasta.config.json` to get the python command (`python_cmd` field). Use that for all commands below (shown as `<PYTHON_CMD>`).

1. **Run the full compliance scan:**
   ```bash
   <PYTHON_CMD> -c "
   import json
   from shasta.config import get_aws_client
   from shasta.scanner import run_full_scan
   from shasta.compliance.mapper import get_control_summary
   from shasta.compliance.scorer import calculate_score
   from shasta.db.schema import ShastaDB

   client = get_aws_client()
   client.validate_credentials()

   print('Running full compliance scan...')
   scan = run_full_scan(client)

   db = ShastaDB()
   db.initialize()
   db.save_scan(scan)

   score = calculate_score(scan.findings)

   output = {
       'score': {
           'percentage': score.score_percentage,
           'grade': score.grade,
           'controls_passing': score.passing,
           'controls_failing': score.failing,
           'controls_partial': score.partial,
           'total_findings': score.total_findings,
           'findings_passed': score.findings_passed,
           'findings_failed': score.findings_failed,
       },
       'findings': [
           {
               'check_id': f.check_id,
               'title': f.title,
               'description': f.description,
               'severity': f.severity.value,
               'status': f.status.value,
               'domain': f.domain.value,
               'resource_id': f.resource_id,
               'remediation': f.remediation,
               'soc2_controls': f.soc2_controls,
           }
           for f in sorted(scan.findings, key=lambda x: ['critical','high','medium','low','info'].index(x.severity.value))
       ],
       'control_summary': {
           k: {
               'title': v['title'],
               'overall_status': v['overall_status'],
               'pass_count': v['pass_count'],
               'fail_count': v['fail_count'],
           }
           for k, v in get_control_summary(scan.findings).items()
           if v['has_automated_checks'] or v['overall_status'] != 'not_assessed'
       }
   }
   print(json.dumps(output, indent=2))
   "
   ```

2. **Present results clearly:**
   - Overall score and grade
   - Critical & high findings with plain-English explanations and specific remediation
   - SOC 2 control status table
   - Prioritized next steps

## Tone
- Use analogies ("MFA is like a second lock on your front door")
- Be specific ("restrict sg-xxx to your office IP" not "fix your security groups")
- Celebrate what's passing
- If score is low, frame as roadmap not failure
