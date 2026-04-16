---
name: audit
description: Walk staged changes against the engineering principles checklist and report pass/fail per principle. Run before any non-trivial commit. Catches doc drift, stub functions, single-region defaults, missing framework mappings, and other regressions before they ship.
user-invocable: true
---

# Audit

You are running an engineering-principles audit on the user's staged or recent
changes in this repo. Your job is to walk every applicable rule from
[`ENGINEERING_PRINCIPLES.md`](../../../ENGINEERING_PRINCIPLES.md) against the
diff and report pass / fail / N/A per principle, with specific file:line
references for any failures.

This skill is invoked by the user as `/audit` before they commit or push.
Treat it as a pre-commit gate, not as a code review. Be terse, opinionated,
and concrete.

## Inputs to gather

Run these in parallel before doing any analysis:

```bash
git diff --cached --stat                     # what's staged
git diff --cached --name-only                # changed file list
git diff --cached                            # full staged diff
git status -s                                # also catch unstaged
```

If nothing is staged, fall back to the most recent commit:
```bash
git diff HEAD~1 --stat
git show HEAD --stat
```

Also load the principles file once for reference:
```bash
cat ENGINEERING_PRINCIPLES.md
```

## How to run the audit

For each principle below, decide one of:
- **PASS** — the diff complies (or the principle is N/A for this change)
- **FAIL** — the diff violates the principle; you must explain how, where (file:line), and what to do
- **WARN** — the diff is suspicious but not clearly wrong; flag for human review

Process the principles in order. Stop and report immediately if a hard
build-break-shaped principle (#1, #2, #11) fails — those are non-negotiable.

### #1 Numbers in docs are tests waiting to be written

- Did the diff add or modify any numeric claim in `README.md`,
  `CHANGELOG.md`, or `TRUST.md`?
- If yes: is there a corresponding entry in
  `tests/test_integrity/test_doc_claims.py` that AST-counts the source?
- If the diff bumped a count in the source (added a check function, added
  a Terraform template, added a test): does the corresponding doc claim
  still match? Run `pytest tests/test_integrity/ -q` to verify.
- **FAIL** if a doc number changed without a matching test, or if a code
  change drifts an existing tracked number.

### #2 Stub-shaped functions

- Walk every new or modified function in the diff.
- For functions named `check_*` / `run_*` / `generate_*` / `scan_*`:
  is the body just `pass`, `return []`, `return None`,
  `raise NotImplementedError`, or docstring-only?
- **FAIL** with file:line if any stub-shaped function exists.

### #3 Multi-region / multi-subscription default

- Did the diff add a new check module under `src/shasta/aws/` or
  `src/shasta/azure/`?
- If AWS: does its `run_all_*` runner iterate
  `client.get_enabled_regions()` via `client.for_region(r)`?
- If Azure: does the runner support multi-subscription via
  `AzureClient.for_subscription(sid)`, or at minimum honor the existing
  `_run_azure_extras` dispatch path?
- **FAIL** if a new module hardcodes a single region/subscription.

### #4 Audit your own code with vendor skepticism

- Did the diff add a numeric claim, "supports X" assertion, or capability
  description anywhere?
- For each: grep the source to verify the claim. If you can't find the
  implementation, **FAIL** with the unverifiable claim quoted.

### #5 Treat empty results different from errors

- Walk every new check function. Does it use `NOT_ASSESSED` for
  permission/error cases, `NOT_APPLICABLE` for empty inventories, and
  `FAIL` only for actual non-compliance?
- A check that wraps everything in `try/except: return []` is a
  **FAIL** — it conflates errors with absence.

### #6 Build the harder system first

- Mostly N/A at audit time. **PASS** unless the diff is introducing a new
  cloud/framework where the easier side is being built first; if so,
  **WARN** with a note that the abstractions may need to be revisited.

### #7 Cross-cutting walkers beat per-service code

- If the diff adds 3+ near-duplicate functions across services (e.g.
  `check_storage_X`, `check_keyvault_X`, `check_sql_X`), **WARN** and
  recommend folding into a walker.
- If the duplication is only 2 instances, **PASS** — premature abstraction
  is its own anti-pattern.

### #8 Configuration tables beat scattered if-statements

- Did the diff add a hardcoded list of items inside a check function
  (e.g. a list of required Defender plans, deprecated runtimes, expected
  log categories)?
- If the same shape exists as a module-level constant elsewhere, **WARN**
  and point to the existing pattern.

### #9 Frameworks belong on the data model

- Did the diff add new check functions?
- For each: does the `Finding(...)` constructor populate
  `soc2_controls`, `cis_aws_controls`, `cis_azure_controls`,
  `mcsb_controls` as appropriate for the framework the check maps to?
- A new AWS check should populate `cis_aws_controls`. A new Azure check
  should populate `cis_azure_controls` + `mcsb_controls`.
- **FAIL** if a new check has zero framework mappings, or uses
  free-text in `description` to convey control IDs.

### #10 Backwards compatibility is additive

- Did the diff change an existing field type or function signature on
  `Finding`, `ScanResult`, `AzureClient`, `AWSClient`, or any public API?
- **FAIL** if so, unless there's a clear deprecation path documented.

### #11 Detection layer is deterministic — zero LLM calls

- Did the diff add an import of `anthropic`, `openai`, `langchain`,
  `litellm`, or any HTTP call to `api.anthropic.com` / `api.openai.com`
  inside `src/shasta/` or `src/whitney/`?
- **HARD FAIL** if so. The detection layer is deterministic by design.

### #12 Read the deprecation notices

- Did the diff add a new check that targets an external API?
- Look up whether that API has a known deprecation date. If the API is
  deprecated within 18 months, **WARN** with a recommendation to use the
  successor API.

### #13 Checks that return a count, not the actual items

- Did the diff add a check that reports a count
  (`f"Found {N} foo issues"`) without listing the top items by severity?
- **WARN** with a recommendation to use the same pattern as
  `_list_top_guardduty_findings` in `src/shasta/aws/logging_checks.py`.

### #14 Severity by impact, not by API-returned numeric

- Did the diff add a check that maps severity directly from a vendor's
  numeric severity (e.g. `severity = vendor_severity`)?
- Is there a critical-type-prefix override list (like
  `_GUARDDUTY_CRITICAL_TYPE_PREFIXES`)?
- **WARN** if the vendor severity is taken at face value without a
  type-based override.

### #15 Failure messages tell the reader what to do

- For every new test added in the diff, look at its assertion error
  message. Does it answer: what file, what line, what to change it to?
- **WARN** for tests with bare `assert x == y` that would produce
  uninformative failures.

### #16 Commit messages are first-line documentation

- N/A at audit time (the commit hasn't happened yet). But **remind** the
  user to use Problem / Resolution / Files / Tests structure if the
  diff is non-trivial.

### #17 Historical narrative is sacred

- Did the diff modify any line in `README.md`, `CHANGELOG.md`, or
  `TRUST.md` that contains `~~strikethrough~~`?
- **FAIL** with a note that historical entries must not be edited;
  add a new entry instead.

### #18 Lease-protected force pushes only

- Mostly N/A at staged-diff time. **PASS** unless the user is about to
  invoke `git push --force` (without `--force-with-lease`), in which case
  **HARD FAIL**.

### #19 One commit = one shippable artifact

- Look at the staged diff. Does it represent one coherent feature?
- If the diff mixes "fix bug" + "add feature" + "refactor unrelated code",
  **WARN** and recommend splitting.

### #20 Closed issues are an audit trail

- N/A at code audit time, but if the diff resolves a known bug or
  introduces a notable improvement, **REMIND** the user to file an issue
  documenting it (even if they immediately close it).

## Output format

Print a one-line header with the audit verdict, then a table of results,
then any required actions. Be direct.

```
AUDIT RESULT: PASS / FAIL / PASS WITH WARNINGS

Principles checked: 20
  PASS: <n>
  WARN: <n>
  FAIL: <n>

Failures:
  #2 Stub function detected: src/shasta/aws/foo.py:42 — check_thing()
     returns [] with no implementation. Either implement or delete.
  #9 Missing framework mapping: src/shasta/aws/foo.py:55 — new check
     function does not populate cis_aws_controls. Add the relevant
     CIS section ID(s).

Warnings:
  #7 Three near-duplicate checks added across storage/keyvault/sql.
     Consider folding into a walker — see private_endpoints.py for
     the pattern.

Actions before commit:
  - Fix the stub at src/shasta/aws/foo.py:42 (FAIL #2)
  - Add cis_aws_controls=[...] to the Finding in src/shasta/aws/foo.py:55 (FAIL #9)
  - (optional) Refactor the 3 near-duplicate checks into a walker (WARN #7)

After fixes, re-run /audit to confirm green, then proceed with commit.
```

If the audit is clean, just print:

```
AUDIT RESULT: PASS

All 20 principles satisfied. Safe to commit.
Run `pytest tests/test_integrity/` once before push if doc claims changed.
```

## Important guardrails

- Do **not** auto-fix violations. Report them. The user decides what to fix.
- Do **not** run the full test suite from this skill. The CI workflow does
  that on PR. Only run `pytest tests/test_integrity/` if the user explicitly
  asks or if a #1 violation is suspected and you need to confirm.
- Do **not** suggest principle additions or modifications in this skill.
  `ENGINEERING_PRINCIPLES.md` is the source of truth — propose changes
  there via a separate PR, not via /audit.
- Do **not** be exhaustive about #6, #16, #18, #20 at staged-diff time —
  they are mostly N/A and printing PASS for all of them is noise.
