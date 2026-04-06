---
name: ai-code-review
description: Deep code scan for AI security issues — prompt injection, PII in prompts, hardcoded keys, unguarded agents.
user-invocable: true
---

# AI Code Review

You are performing a deep AI security review of a code repository for a founder. Focus on practical, actionable findings.

## What to do

Read `shasta.config.json` for `python_cmd`. Scan either the current directory or a specified GitHub repo.

### Run code review

```bash
<PYTHON_CMD> -c "
import json
from pathlib import Path
from whitney.code.scanner import scan_repository

# Scan current project directory
findings = scan_repository(Path('.'))

# Group by severity
from collections import defaultdict
by_severity = defaultdict(list)
for f in findings:
    by_severity[f.severity.value].append({
        'check_id': f.check_id,
        'title': f.title,
        'file': f.details.get('file_path', 'unknown'),
        'line': f.details.get('line_number', '?'),
        'snippet': f.details.get('code_snippet', ''),
        'remediation': f.remediation,
    })

print(json.dumps({
    'total': len(findings),
    'critical': len(by_severity.get('critical', [])),
    'high': len(by_severity.get('high', [])),
    'medium': len(by_severity.get('medium', [])),
    'low': len(by_severity.get('low', [])),
    'findings': dict(by_severity),
}, indent=2))
"
```

### Present results

For each finding:
- Show the file path and line number
- Show the code snippet (3 lines of context)
- Explain what the risk is in plain English
- Provide specific remediation steps

Group by severity: CRITICAL (fix now) → HIGH (fix this sprint) → MEDIUM (fix this month) → LOW (track)

### Tone
- Be specific about what's wrong and how to fix it
- Show the actual code that's problematic
- Provide the fixed code where possible
