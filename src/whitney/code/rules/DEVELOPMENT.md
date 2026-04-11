# Code Scanner Development History

This document traces the evolution of Whitney's code scanning module from
its initial regex-only approach through to the current Semgrep-only
architecture with 65 rules. It exists so future contributors understand
*why* the architecture is what it is, not just *what* it is.

---

## Phase 1: Regex-Only Scanner (April 5-7, 2026)

Whitney launched with a pure-regex code scanner in `checks.py` and
`patterns.py`. Each check compiled a regex pattern and ran it against
every line of every file in the target repository.

**What worked:** Fast to write, zero dependencies, covered the 15
initial check categories (prompt injection, API key exposure, PII in
prompts, unsafe deserialization, etc.).

**What didn't:** Regex has no concept of code structure. It matches text,
not code. A pattern like `.query()` intended to catch unfiltered vector
database queries also matched SQLAlchemy queries, data pipeline calls,
and jQuery selectors. The string `"instructions:"` intended to catch
exposed system prompts matched help text, YAML configs, and docstrings.

The scanner produced findings. Whether those findings were *true* was a
different question entirely.

> Commits: `d84c947`, `c76ec1c`

---

## Phase 2: Semgrep + Regex Dual-Engine (April 7, 2026)

We added Semgrep as an AST-based scanning engine alongside the existing
regex. The idea was graceful degradation: if Semgrep was installed, use
it for 13 checks; if not, fall back to regex for all 15.

This produced 13 Semgrep YAML rules in `src/whitney/code/rules/` and a
subprocess wrapper in `semgrep_runner.py`. Two checks stayed Python-only
because they needed logic beyond pattern matching (rate limiting required
file-level memoization; outdated SDK needed version constraint parsing).

**Architecture:** Dual-engine with fallback.

> Commits: `253c4a1`, `ef78e4a`

---

## Phase 3: Real-World Testing — The FP Problem (April 7-10, 2026)

We built a validation harness (`scripts/test_weekend.py`) and ran the
scanner against 7 well-known repositories:

| Repo | Why |
|---|---|
| langchain-ai/langchain | Largest LLM framework |
| run-llama/llama_index | RAG framework |
| modelcontextprotocol/servers | Official MCP examples |
| a2aproject/a2a-samples | Official A2A examples |
| anthropics/anthropic-cookbook | Well-written examples (low-FP test) |
| openai/openai-cookbook | Well-written examples (low-FP test) |
| transilienceai/shasta | Our own repo (should be clean) |

The results were sobering. Regex-backed checks produced false positives
on comments, docstrings, string literals, test fixtures, and non-AI code
that happened to share vocabulary with AI patterns. The cookbooks — which
are written by the SDK maintainers themselves — triggered dozens of
findings that were clearly not security issues.

A companion script (`scripts/validate_findings.py`) generated Markdown
worksheets with code snippets for manual TP/FP/EP classification. The
FP rate on regex-backed checks was unacceptable for a tool whose output
feeds compliance reports.

**The question that changed the architecture:** "Why regex at all?"

If Semgrep gives us AST-aware, structure-aware, language-grammar-aware
matching — and it's deterministic, open-source, and widely adopted — the
regex fallback isn't a safety net. It's a liability. Every FP that
reaches a compliance report erodes trust in the entire platform.

> Commits: `ed875e1` (tightened regex patterns as interim fix),
> `184b3b2` (expanded Semgrep to 37 rules to reduce regex surface)

---

## Phase 4: Semgrep-Only — Drop the Regex (April 10, 2026)

We made Semgrep a hard requirement. `scanner.py` now raises
`SemgrepNotInstalledError` if Semgrep is not available. The regex
fallback was removed entirely.

This unlocked capabilities that were impossible under the dual-engine
model:

**Taint analysis** (5 rules in `prompt_injection_taint.yaml`): Semgrep
can trace data flow from a source (e.g., `request.form["input"]`) through
transformations to a sink (e.g., `openai.ChatCompletion.create(...)`).
Sanitizer functions like `bleach.clean()` and `html.escape()` break the
taint chain. This catches *actual* prompt injection paths, not just
string concatenation near an API call. Taint rules were added for Flask,
FastAPI, Django, and Express.js frameworks.

**Unsafe deserialization** (6 rules in `unsafe_deserialization.yaml`):
Based on Trail of Bits research, these rules detect `pickle.load`,
`torch.load` without `weights_only=True`, `numpy.load` with
`allow_pickle=True`, `joblib.load` from untrusted sources, `yaml.load`
without `SafeLoader`, and `shelve.open`. These are the actual RCE
vectors in ML pipelines (CWE-502).

**Rule count:** 20 YAML rules, 48 rules total.

> Commit: `a9c4506`

---

## Phase 5: Deep Research + Parallel Enhancement (April 10, 2026)

With the Semgrep-only architecture stable, we did a deep research pass
to identify gaps and then ran a parallel Claude Code session to execute
the enhancements.

### What the research identified

- **Pattern gaps:** FastAPI taint sources were too broad (matched every
  function with a string parameter, not just route handlers). The NumPy
  `np.load` alias wasn't covered. The `.format()` regex had a broken
  escape sequence. Express.js was missing Anthropic sink patterns.
  OpenAI's new key format (`sk-proj-*`, `sk-svcacct-*`) wasn't matched.

- **Missing rule categories:** No detection for LLM output flowing into
  `exec()`/`eval()`/`subprocess` (code execution via LLM). No detection
  for LLM output used as URLs in HTTP requests (SSRF). No checks for
  missing `max_tokens` (resource exhaustion). No checks for explicitly
  disabled guardrails (Gemini `BLOCK_NONE`, LangChain
  `allow_dangerous_*`).

- **Metadata gaps:** Rules lacked CWE IDs, OWASP LLM Top 10 mappings,
  confidence levels, and technology tags — making them harder to
  aggregate, filter, and report on.

- **No test corpus:** No Semgrep test files with `# ruleid:` / `# ok:`
  annotations to validate that rules fire (and don't fire) correctly.

### What the parallel session delivered

A separate Claude Code session executed the enhancements while the
primary session continued AWS testing work:

**5 critical pattern fixes:**
1. FastAPI taint source scoped to `@$APP.$METHOD(...)` decorators
2. `np.load` alias added alongside `numpy.load`
3. `.format()` regex fixed (`\}"` → `\}[^"]*"`)
4. Express Anthropic sinks added (`$CLIENT.messages.create`)
5. OpenAI key regex updated for new key formats

**4 new rule files (13 new rules):**
- `llm_output_execution.yaml` — 3 rules (CWE-94/95, OWASP LLM02)
- `llm_output_ssrf.yaml` — 3 rules (CWE-918, OWASP LLM02)
- `token_limit_missing.yaml` — 3 rules (CWE-770)
- `guardrails_disabled.yaml` — 4 rules (CWE-20, OWASP LLM02)

**8 quality fixes** across existing rules (sanitizer normalization,
`print()` removed as valid logging, MCP file-write modes, model
versioning list expanded to 30 models, Django `request.FILES` as taint
source, and more).

**Full metadata** added to all 65 rules: `cwe`, `owasp`, `confidence`,
`category`, `technology`, `references`.

**13 Semgrep test files** with `# ruleid:` and `# ok:` annotations.

**Auto-fix:** `yaml.load()` rule now includes `fix: yaml.safe_load($DATA)`.

### Verification

The primary session verified the parallel session's output before
committing:

- 20 YAML files, 65 rules — count confirmed
- All 65 rules have complete metadata (cwe, confidence, category,
  technology) — zero gaps
- Zero duplicate rule IDs
- 13 test files with 44 `# ruleid:` annotations
- Zero YAML parse errors
- 18/18 integrity tests pass
- 39/39 Whitney integrity tests pass

> Commits: `bd09564` (Semgrep rules 48 → 65)

---

## Current State (April 10, 2026)

| Metric | Value |
|---|---|
| Rule files | 20 YAML |
| Total rules | 65 |
| Test files | 13 (.py with `# ruleid:` annotations) |
| Engine | Semgrep only (no regex fallback) |
| Taint rules | 5 (Flask, FastAPI, Django, Express) |
| Languages | Python, JavaScript, TypeScript |
| Metadata | CWE, OWASP, confidence, category, technology on all rules |
| LLM calls | Zero (deterministic scanning) |

### Rule categories

| Category | Rules | CWE |
|---|---|---|
| Prompt injection (taint) | 5 | CWE-77 |
| Prompt injection (risk) | 5 | CWE-77 |
| Unsafe deserialization | 6 | CWE-502 |
| API key exposure | 5 | CWE-798 |
| MCP server security | 5 | CWE-284 |
| RAG access control | 5 | CWE-862 |
| Guardrails disabled | 4 | CWE-20 |
| Logging insufficient | 3 | CWE-778 |
| Agent unrestricted tools | 3 | CWE-284 |
| LLM output execution | 3 | CWE-94/95 |
| LLM output SSRF | 3 | CWE-918 |
| Meta-prompt exposed | 3 | CWE-200 |
| No fallback handler | 3 | CWE-755 |
| PII in prompts | 3 | CWE-359 |
| Token limit missing | 3 | CWE-770 |
| Output validation | 2 | CWE-20 |
| Key in env file | 1 | CWE-798 |
| Model endpoint public | 1 | CWE-284 |
| Model versioning | 1 | CWE-1104 |
| Training data unencrypted | 1 | CWE-311 |

---

## Architectural Decisions

**Why Semgrep, not regex?**
Regex matches text. Semgrep matches code. In a compliance tool, a false
positive in a report is worse than a missed finding — it erodes the
auditor's trust in every other finding. AST-aware matching eliminates
entire classes of FPs (matches in comments, docstrings, string literals,
variable names that happen to contain keywords).

**Why Semgrep, not a custom AST walker?**
Semgrep rules are declarative YAML. Adding a new detection pattern is a
data change, not a code change. The rule format is an industry standard
with public documentation, community rules, and editor support. A custom
walker would be more powerful but would require Python expertise to
extend.

**Why required, not optional?**
The dual-engine model created a situation where the "same" scanner
produced different results depending on whether Semgrep was installed.
This is unacceptable for a compliance tool — the scan output must be
deterministic and reproducible. Making Semgrep required eliminates the
variable.

**Why zero LLM calls?**
Detection must be deterministic. Running the same scanner on the same
code must produce the same findings every time. LLM-based detection
would introduce non-determinism, latency, cost, and a dependency on
external services. The LLM lives in the user-interface layer (Claude
Code skills), translating findings into natural language — not producing
them. This is enforced by integrity tests.

**Why taint analysis matters:**
Pattern matching catches `f"...{user_input}..."` being passed to an LLM
API. But taint analysis catches the case where `user_input` comes from
`request.form["input"]` three functions earlier and flows through a
transformation chain to the API call. The former catches obvious cases;
the latter catches the ones that actually get exploited.

---

## Lessons Learned

1. **Test against real repos early.** The FP problem was invisible in
   unit tests with synthetic code. It became obvious the moment we ran
   against LangChain and the Anthropic cookbook.

2. **Regex is a precision ceiling, not a starting point.** We spent time
   tightening regex patterns (`ed875e1`) before realizing the right
   answer was to remove the regex engine entirely. The tightening work
   wasn't wasted — it clarified exactly which FP classes are structural
   (can't be fixed with better regex) vs. accidental (can be fixed with
   better patterns).

3. **Parallel sessions work for enhancement, not architecture.** The
   Semgrep-only architecture decision had to happen in the primary
   session. But once the architecture was stable, a parallel session
   could add rules, metadata, and test files without coordination
   overhead. The key was that the primary session verified the output
   before committing.

4. **Metadata is not optional for compliance tools.** A finding without
   a CWE ID can't be mapped to a framework. A finding without a
   confidence level can't be triaged. Adding metadata to all 65 rules
   retroactively was more work than adding it from the start would have
   been.

5. **Drop the fallback.** The dual-engine "graceful degradation" felt
   like good engineering. In practice, it meant maintaining two code
   paths, testing two code paths, and explaining to users why results
   differed. Making the better engine required was simpler, more honest,
   and more reliable.
