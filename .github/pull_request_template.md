<!--
Thanks for opening a PR. Please fill out every section — the integrity
workflow in .github/workflows/integrity.yml will reject the PR if any of
the load-bearing principles in CLAUDE.md / ENGINEERING_PRINCIPLES.md are
violated, so checking them here first saves a round trip.
-->

## Summary

<!-- One paragraph: what does this PR change and why? -->

## Related issue

<!-- REQUIRED. PRs without a linked issue should not merge. -->

Closes #

## Changes

<!-- Bullet list of concrete changes. -->

-
-
-

## Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New compliance check
- [ ] New framework mapping (existing check → new control)
- [ ] New Terraform remediation template
- [ ] New Claude Code skill
- [ ] Refactor (no behavior change)
- [ ] Docs only
- [ ] Tests only
- [ ] CI / build

## Engineering principles checklist

These mirror the 8 load-bearing rules in
[`CLAUDE.md`](../blob/main/CLAUDE.md). Tick each one that applies to this PR.

- [ ] **Doc-vs-code drift considered.** Any numeric claim I added or
      changed in `README.md` / `TRUST.md` has a matching test in
      `tests/test_integrity/test_doc_claims.py`. (Principle 1)
- [ ] **No stub functions introduced.** Every new `check_* / run_* /
      generate_*` function has a real body. (Principle 2)
- [ ] **Multi-region / multi-subscription by default.** New AWS checks
      iterate `client.get_enabled_regions()`; new Azure checks iterate
      subscriptions via `AzureClient.for_subscription`. (Principle 3)
- [ ] **Framework controls populated on `Finding`.** I did not embed
      control IDs in description strings. (Principle 4)
- [ ] **Zero LLM calls in the detection path.** The default scan / scoring
      / mapping path is deterministic. (Principle 5)
- [ ] **`NOT_ASSESSED` vs `NOT_APPLICABLE` vs `FAIL` used correctly.**
      Empty results are not conflated with errors. (Principle 6)
- [ ] **Walker pattern considered.** If this PR touches ≥3 similar checks
      across services, I evaluated whether a walker would be cleaner.
      (Principle 7)
- [ ] **`/audit` slash command run.** Claude Code audit passed on the
      staged diff. (pre-commit discipline)

## Tests run locally

- [ ] `pytest tests/test_integrity/` (doc-vs-code drift)
- [ ] `pytest tests/test_aws/test_aws_sweep_smoke.py` (AWS structural)
- [ ] `pytest tests/test_azure/test_smoke.py` (Azure structural)
- [ ] `pytest` (full suite)
- [ ] `ruff check src/ tests/` and `ruff format --check src/ tests/`

## Additional notes

<!-- Anything reviewers should know: migration concerns, follow-up work,
rollout plan, etc. -->
