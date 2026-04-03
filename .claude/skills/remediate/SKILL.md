---
name: remediate
description: Get interactive remediation guidance for compliance findings, including Terraform code and step-by-step instructions.
user-invocable: true
---

# Remediate

Help a founder fix their SOC 2 compliance issues. Be specific, actionable, encouraging.

## What to do

Read `shasta.config.json` for `python_cmd`. Use that for all commands (shown as `<PYTHON_CMD>`).

1. **Generate remediations:**
   ```bash
   <PYTHON_CMD> -c "
   import json
   from shasta.config import get_aws_client
   from shasta.scanner import run_full_scan
   from shasta.remediation.engine import generate_all_remediations, save_terraform_bundle

   client = get_aws_client()
   client.validate_credentials()
   scan = run_full_scan(client)
   remediations = generate_all_remediations(scan.findings)
   tf_path = save_terraform_bundle(remediations)

   print(json.dumps({
       'terraform_file': str(tf_path),
       'total': len(remediations),
       'remediations': [{
           'title': r.finding.title, 'severity': r.finding.severity.value,
           'effort': r.effort, 'explanation': r.explanation,
           'steps': r.steps, 'has_terraform': bool(r.terraform),
           'soc2_controls': r.finding.soc2_controls,
       } for r in remediations]
   }, indent=2))
   "
   ```

2. **Present interactively:** group by priority/effort, quick wins first. For each: plain-English explanation, numbered steps, Terraform code if available.

3. **Offer to help apply:** guide through `terraform plan`/`apply` or AWS Console steps. After fixing, offer to re-run `/scan`.
