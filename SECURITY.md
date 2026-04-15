# Security Policy

## Reporting a vulnerability

Email **`contact@transilience.ai`** with a description, reproduction steps,
and the affected Shasta or Whitney version. Please do **not** open a public
GitHub issue for security vulnerabilities.

## SLA

| Stage | Target |
|---|---|
| Acknowledgement | within 48 hours |
| Status update | within 7 days |
| Fix or mitigation | within 30 days |

## Scope

**In scope**

- Vulnerabilities in Shasta or Whitney source code.
- Supply-chain or CI/CD issues in this repository (e.g. compromised
  workflows in `.github/workflows/`).
- Vulnerabilities in published artifacts (PyPI packages, release tarballs).
- Data-exposure issues in the optional dashboard (`shasta[dashboard]`) or
  trust-center generator.

**Out of scope**

- Compliance findings Shasta reports against your own cloud account —
  those are the intended product output, not Shasta vulnerabilities. Open
  a normal issue.
- Vulnerabilities in third-party cloud services Shasta scans (AWS, Azure).
  Report those to the respective provider.
- Vulnerabilities in dependencies that do not affect Shasta's actual use
  of them. (Still appreciated, just lower priority.)

## Disclosure

We credit reporters in the fix commit and in `CHANGELOG.md` unless the
reporter requests anonymity. For high-severity issues we also publish a
GitHub advisory (`gh advisory create`).
