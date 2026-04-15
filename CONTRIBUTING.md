# Contributing to Shasta

Thanks for your interest in contributing. Shasta is a multi-cloud compliance
and AI governance toolkit — keeping it correct is more important than keeping
it big, so the bar on PRs is "does this stay honest under the integrity
tests." This page tells you how to stay green.

## Read this first

Shasta's engineering rules live in [`ENGINEERING_PRINCIPLES.md`](./ENGINEERING_PRINCIPLES.md).
Read it once before your first PR. The 8 most load-bearing rules are inlined
at the top of [`CLAUDE.md`](./CLAUDE.md) so they're in context at every
Claude Code session.

Short version: numbers in docs are tests; no stub functions; multi-region by
default; framework controls on `Finding`, not in description strings; zero
LLM calls in the detection path; `NOT_ASSESSED` vs `NOT_APPLICABLE` vs
`FAIL` used correctly; walkers beat N near-duplicate checks.

## Workflow

1. **Open an issue first** using one of the templates in
   [`.github/ISSUE_TEMPLATE/`](./.github/ISSUE_TEMPLATE/) —
   `bug_report`, `feature_request`, or `new_check_proposal` for new
   check modules. The `new_check_proposal` form encodes the engineering
   principles at intake so your proposal can't accidentally skip them.
2. **Branch** with a prefix: `feature/`, `fix/`, `docs/`, or `check/`
   (for new check modules).
3. **Commit** using [Conventional Commits](https://www.conventionalcommits.org/):
   `type(scope): description`. Example: `feat(aws/iam): add root-key age check`.
4. **Open a PR** — the template in
   [`.github/pull_request_template.md`](./.github/pull_request_template.md)
   includes a principles checklist that mirrors `CLAUDE.md`. Every PR must
   link its issue with `Closes #N`.

## Required tests (must pass locally before PR)

See the **Required tests on every PR** section in
[`CLAUDE.md`](./CLAUDE.md#required-tests-on-every-pr):

- `pytest tests/test_integrity/` — doc-vs-code drift tests
- `pytest tests/test_aws/test_aws_sweep_smoke.py` — AWS module smoke tests
- `pytest tests/test_azure/test_smoke.py` — Azure module smoke tests

These are mechanically enforced by
[`.github/workflows/integrity.yml`](./.github/workflows/integrity.yml).
A drift in any numeric claim in `README.md` or `TRUST.md` fails the build
until either the code is restored or the doc is updated.

## Pre-commit

Run the `/audit` Claude Code skill on staged changes before every non-trivial
commit. It walks the engineering-principles checklist and reports pass/fail
per principle, catching doc drift and framework-mapping regressions before
CI does.

## Reporting vulnerabilities

Vulnerability reports go to `contact@transilience.ai`, not public issues —
see [`SECURITY.md`](./SECURITY.md).

## Code of Conduct

This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md).
Enforcement contact: `contact@transilience.ai`.

## License

By contributing, you agree that your contributions are licensed under the
MIT License — see [`LICENSE`](./LICENSE).
