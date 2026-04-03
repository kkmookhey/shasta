---
name: gap-analysis
description: Run a full SOC 2 gap analysis against the connected AWS account and present findings with remediation guidance.
user-invocable: true
---

# Gap Analysis

You are performing a SOC 2 gap analysis for a semi-technical founder.

## What to do

Read `shasta.config.json` for `python_cmd`. Use that command for all Python calls (shown as `<PYTHON_CMD>` below).

1. **Run scan and generate reports:**
   ```bash
   <PYTHON_CMD> -c "
   from shasta.config import get_aws_client
   from shasta.scanner import run_full_scan
   from shasta.reports.generator import save_markdown_report, save_html_report
   from shasta.db.schema import ShastaDB

   client = get_aws_client()
   client.validate_credentials()
   print('Running full compliance scan...')
   scan = run_full_scan(client)
   db = ShastaDB(); db.initialize(); db.save_scan(scan)
   md = save_markdown_report(scan)
   html = save_html_report(scan)
   print(f'Markdown: {md}')
   print(f'HTML: {html}')
   print(f'{scan.summary.passed} passed, {scan.summary.failed} failed of {scan.summary.total_findings}')
   "
   ```

2. **Read the Markdown report** and present interactively like a consultant:
   - Headline score and one-sentence assessment
   - Findings grouped by SOC 2 control (not by AWS service)
   - For each failing control: what the auditor expects, what's missing, exact steps
   - Controls needing policy documents
   - Prioritized remediation roadmap
   - Offer `/remediate` to fix specific findings
