# Engineering Principles

These are the rules of thumb we use when building Shasta and Whitney. Every
one of them is grounded in something concrete that broke (or almost broke)
this codebase. They are opinionated by design — feel free to disagree, but
disagree with a specific counter-example.

If you're new to the project, read this once before your first PR. If
you're returning, re-read it when you're about to write a new check
function, a new module, or a new README claim.

---

## Discipline (the rules that prevent silent rot)

### 1. Every number in your docs is a test waiting to be written

If your README says "22 Azure Terraform templates" or "100 tests" or
"33 check-to-risk mappings", that number is going to drift the moment
your codebase grows. The fix isn't vigilance — it's a test that
AST-counts the source tree and asserts the README claim matches.
`tests/test_integrity/test_doc_claims.py` caught **6 stale numbers** in
this codebase on its first run, including one that had been introduced
in the previous commit. Cost: ~150 lines. Caught: every phantom we'd
otherwise ship.

### 2. Stub-shaped functions are lies in code form

A function called `check_root_account()` whose body is `return []` is
worse than no function at all — it makes the system look more complete
than it is. Add an AST walker to your CI that flags any
`check_*` / `run_*` / `generate_*` function whose body is just `pass`,
`return []`, `return None`, `raise NotImplementedError`, or
docstring-only. Make it a hard build break, not a warning.

### 3. Default to multi-region / multi-subscription / multi-account

Single-region scanners are the most common false-clean failure mode in
compliance tooling. If your code has to be **told** which region or
subscription to look at, it has zero coverage on everything else and
will report green by default. Make the multi-account walk the default
path; make single-account the explicit override. We had to retrofit
this onto AWS and Azure separately, and the retrofit touched every
check module and every test. Bake it in on day one.

### 4. Audit your own code with the skepticism you'd apply to a vendor's

When the phantom-templates claim turned up, the right response wasn't
"fix that one" — it was "what else is hiding?" Six more stale numbers
came out of the audit, including one introduced in the previous commit.
Run the audit on a schedule, not just when something visibly breaks.
The bugs you find proactively are 10x cheaper than the bugs a customer
reports. Treat your own README and your own commit messages as
adversarial input.

### 5. Treat empty-results different from errors

A scanner that returns 0 findings on a real account because the API
errored is a critical bug. A scanner that returns 0 findings because
the account has no resources of that type is correct. Code the
difference explicitly: `NOT_ASSESSED` for permission/error cases,
`NOT_APPLICABLE` for empty inventories, `FAIL` for actual
non-compliance. Conflating them creates false-clean reports — and
false-clean is the worst possible failure mode for a compliance tool.

---

## Structure (factor decisions that pay off later)

### 6. Build the harder system first; the rest gets mechanical

Once one cloud (Azure) was fully wired to CIS v3.0 with modular shape —
`databases.py`, `serverless.py`, `appservice.py`, `backup.py`,
cross-cutting walkers, governance auditor — the equivalent AWS sweep
took ~70% less wall-clock time because the shape was already proven.
The hard pass forces you to discover the right factoring. Don't pick
the easy cloud, easy framework, or easy customer first; you'll build
the wrong abstractions and have to redo them.

### 7. Cross-cutting walkers beat per-service code by an order of magnitude

When you find yourself about to write the same gap N times across
different services, write the walker once. **One** Private Endpoint
walker covers Storage / Key Vault / SQL / Cosmos / ACR / App Service /
Cognitive Services. **One** VPC endpoint walker covers S3 / DynamoDB /
KMS / Secrets Manager / SSM / ECR / Logs / STS. **One** diagnostic-
settings matrix walker replaces dozens of per-service log checks. The
clue is when you keep writing `check_X_has_private_endpoint` for
varying X.

### 8. Configuration tables beat scattered if-statements

`DEFENDER_REQUIRED_PLANS`, `ACTIVITY_LOG_ALERT_OPERATIONS`,
`EXPECTED_VPC_ENDPOINTS`, `DEPRECATED_LAMBDA_RUNTIMES`,
`EXPECTED_DIAGNOSTIC_CATEGORIES` — every one of these is a declarative
table that drives a check. Adding a new Defender plan to monitor is
one tuple, not a new function. Adding a new deprecated runtime is one
string, not a new `check_*`. When the same control loop runs over a
list of items, externalize the list.

### 9. Frameworks belong on the data model, not in free-text descriptions

If your finding carries "CIS 3.5" inside a description string, you
cannot aggregate, filter, score, or export by framework — you'd be
regex-extracting it back out at every query. Add explicit list fields
on the model (`soc2_controls`, `cis_aws_controls`, `cis_azure_controls`,
`mcsb_controls`) and populate them at the source. Every framework
score then becomes a real query, not a parse. We added these mid-flight
and every check now carries them; the alternative would have been a
regex layer in the report generator forever.

### 10. Backwards compatibility is additive, not heroic

When we added `cis_aws_controls` / `cis_azure_controls` / `mcsb_controls`
to the `Finding` model, every existing caller kept working because the
new fields were optional lists with default factories. Don't change
existing field types or function signatures unless you have to; add
new ones. The migration cost of an additive change is zero. The
migration cost of a renamed field is "every consumer everywhere".

---

## Detection (the rules specific to security tooling)

### 11. The detection layer should be deterministic; the UI layer can be clever

Same infrastructure + same scan = same results. Every time. Auditors
need to be able to reproduce a finding six months later. That means:
SDK calls, AST matching, dictionary lookups, arithmetic. **No LLM
inference** in the scanning, scoring, mapping, policy generation, or
report pipelines. The LLM belongs in the UI layer where its job is to
translate findings into natural language for humans — not to find them.
This rule applies even (especially) when the team is excited about LLMs.

### 12. Read the deprecation notices

Azure NSG flow logs retire 2027-09-30. We had a check that targeted the
legacy NSG flow logs API and would have produced false-FAILs for
customers who had already migrated to VNet flow logs — and would have
gone silently dead post-deprecation. **Subscribe to the change feed for
every external API your code calls.** When AWS or Azure announces
deprecation, that's a sprint item, not a 2027 problem.

### 13. The most dangerous bug is a check that returns a count

The original GuardDuty check reported "24 medium-severity findings"
without ever calling `list_findings`. The number told you something was
wrong; it didn't tell you a credential-exfiltration finding was sitting
active right now. Counts hide the signal inside the noise. When a
check has anything more interesting than pass/fail to report, surface
the actual top items, ranked by danger — not just the histogram.

### 14. Factor severity by impact, not by API-returned numeric

GuardDuty's numeric severity is calibrated for triage queues; the type
of finding is calibrated for incident response. A "medium" severity
GuardDuty finding of type `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`
is a higher-priority incident than a "high" severity finding of type
`Recon:EC2/PortProbeUnprotectedPort`. Build a critical-type-prefix
table and override numeric severity when the type matches. The vendor
catalog is a starting point, not a source of truth.

---

## Process (how the team should work together)

### 15. Failure messages should tell the reader exactly what to do

```
AssertionError: README.md:153 claims 33 for FINDING_TO_RISK registry size,
but actual is 34 (tolerance ±0). Update the doc to 34.
```

That's a fixable error. `AssertionError: count mismatch` is not. Every
assertion in your test suite should answer three questions: **what file**,
**what line**, and **what to change it to**. The next person who hits
that failure (often you, in 3 weeks) needs to fix it without reading
the test source.

### 16. Commit messages are your first line of documentation

Looking back at this codebase, the commits with detailed
Problem / Resolution / Files structure are dramatically more useful 6
months later than the ones that just say "fix bug". A commit message
is a future incident report — write it for the version of you that
encounters this code in 18 months and has forgotten everything. The
diff shows *what*; the commit message shows *why*.

### 17. Historical narrative is sacred — mark it, don't edit it

Build logs, "Session 2 added X" recaps, dated post-mortems, CHANGELOG
entries — leave them alone. Use strikethrough markers (`~~done~~`) in
checklists so integrity tests can skip them. Editing historical text to
match current numbers is revisionism, and you lose the audit trail of
what shipped when. Treat the past as immutable; only the present is
editable.

### 18. Lease-protected force pushes are the safe form of force push

`git push --force` is an unconditional overwrite. `git push
--force-with-lease=main:<sha>` only succeeds if the remote is still at
the SHA you expect — if anyone else pushed in the interval, your push
fails safely. **Never use raw `--force` on a shared branch.** When the
local and remote histories are divergent, lease-protected force is the
right tool; use it deliberately, document the reason in the commit
that triggers the push, and verify the resulting state.

### 19. One commit = one shippable artifact

The AWS parity sweep was three stages but landed as one commit because
the stages depended on each other (Stage 2 imported types from Stage 1,
Stage 3 walkers used helpers from Stage 2). The CHANGELOG separated
them into three logical sections because each stage is independently
understandable. **Optimize commit boundaries for atomicity, not for
line count.** A 4000-line commit that ships one coherent feature is
fine; a 50-line commit that ships half of a broken feature is not.

### 20. Closed issues are an audit trail, not a TODO graveyard

The 10 issues we filed and closed on `transilienceai/shasta` aren't
there to track open work — they're there to document the failure
modes and resolutions for any future visitor (including future-you).
A repo with 10 closed issues containing detailed Problem / Impact /
Resolution / Commits / Files writeups looks dramatically more credible
than one with zero issues, even if the codebases are identical.
**Issues are public engineering memory.** Use them generously.

---

## Two meta-rules underneath all of these

### A. Discipline is finite; tests are infinite

Anything you tell yourself "I'll remember to update" you won't.
Anything you express as a test, you will. The doc-drift integrity test
caught its own author's off-by-one within minutes — that's the proof
point. If a rule matters, encode it as a test. If you can't encode it
as a test, write down why and revisit quarterly.

### B. Three similar lines of code is fine; three similar gaps across services is begging for a walker

The right time for an abstraction is when the duplication is provably
real, not when you suspect it might be. Don't pre-factor. But once
you've shipped the per-service version twice and are about to write a
third, stop and write the walker. The clue is repetition across
*similar shapes*, not repetition of *similar code*.

---

## When in doubt

* **Default to fail-closed.** A check that errors out should report
  `NOT_ASSESSED`, not `PASS`.
* **Default to less surface area.** A new check that covers one CIS
  control well is better than five checks that each cover 20%.
* **Default to deletion over deprecation.** Unused code rots. If a
  check function isn't called from any runner, delete it — don't leave
  it as a stub.
* **Default to citing the rule.** Every check should reference the
  framework section it implements (CIS, MCSB, SOC 2). Reviewers can
  audit the mapping; future-you can grep for it.
* **Default to honesty.** If something isn't done, say so. If a number
  isn't verified, say so. If a feature is partial, say so. Trust is
  more valuable than the marketing benefit of any specific claim.

---

*This file is itself subject to the principles it describes. If you find
a rule here that the codebase doesn't actually follow, that's a bug —
either in the code or in this file. Open an issue.*
