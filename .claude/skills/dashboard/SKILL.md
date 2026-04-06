---
name: dashboard
description: Launch the Shasta web dashboard to view compliance posture, findings, controls, and risk register in a browser.
---

# Dashboard

Launch the local web dashboard for browsing compliance data.

## Steps

1. Start the dashboard server:
   ```
   py -3.12 -m shasta.dashboard
   ```

2. Tell the user:
   - Dashboard is running at **http://127.0.0.1:8080**
   - Open that URL in a browser to view:
     - Compliance scores (SOC 2, ISO 27001)
     - Findings list with filters
     - Control status grid
     - Scan history
     - Risk register
   - Press Ctrl+C to stop the server

## Notes
- Requires scan data in `data/shasta.db` — run `/scan` first if no data exists
- Uses FastAPI + Jinja2 + Tailwind CSS (CDN) + HTMX + Chart.js
- No build step required
