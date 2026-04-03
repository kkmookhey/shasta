---
name: report
description: Generate professional compliance reports (Markdown, HTML, PDF) from the latest scan data.
user-invocable: true
---

# Report

Generate professional SOC 2 compliance reports.

## What to do

Read `shasta.config.json` for `python_cmd`. Use that for all commands (shown as `<PYTHON_CMD>`).

1. **Generate all report formats:**
   ```bash
   <PYTHON_CMD> -c "
   from shasta.config import get_aws_client
   from shasta.scanner import run_full_scan
   from shasta.reports.generator import save_markdown_report, save_html_report
   from shasta.reports.pdf import save_pdf_report
   from shasta.db.schema import ShastaDB

   client = get_aws_client()
   client.validate_credentials()
   print('Running compliance scan...')
   scan = run_full_scan(client)
   db = ShastaDB(); db.initialize(); db.save_scan(scan)
   print('Generating reports...')
   md = save_markdown_report(scan)
   html = save_html_report(scan)
   pdf = save_pdf_report(scan)
   print(f'Markdown: {md}')
   print(f'HTML:     {html}')
   print(f'PDF:      {pdf}')
   "
   ```

2. **Tell the user where reports are** and what each is for:
   - **Markdown** — working sessions, version control
   - **HTML** — sharing via email/browser
   - **PDF** — formal deliverables to auditors/investors
