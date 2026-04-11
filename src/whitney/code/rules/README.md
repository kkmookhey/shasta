# Whitney AI Security Rules for Semgrep

65 Semgrep rules for detecting AI/LLM security vulnerabilities in source code.

## Quick Start

```bash
# Install Semgrep
pip install semgrep

# Scan your repo
semgrep --config path/to/whitney/code/rules/ /path/to/your/repo

# Run rule tests
semgrep --test path/to/whitney/code/rules/
```

## What It Detects

| Category | Rules | Severity | OWASP LLM | CWE |
|----------|-------|----------|-----------|-----|
| **Prompt injection** (pattern + taint) | 10 | CRITICAL/HIGH | LLM01 | CWE-94 |
| **Unsafe deserialization** (pickle, torch, joblib) | 6 | CRITICAL/HIGH | LLM05 | CWE-502 |
| **LLM output → code execution** | 3 | CRITICAL/HIGH | LLM02 | CWE-94, CWE-95 |
| **LLM output → SSRF** | 3 | HIGH | LLM02 | CWE-918 |
| **API key exposure** | 5 | CRITICAL | LLM06 | CWE-798 |
| **MCP server security** (auth, tool scope, input) | 5 | HIGH/MEDIUM | LLM08 | CWE-78, CWE-89 |
| **RAG access control** (per-database patterns) | 5 | MEDIUM | LLM08 | CWE-862 |
| **Guardrails disabled** (safety settings off) | 4 | MEDIUM | LLM02 | CWE-20 |
| **Agent tool abuse** | 3 | HIGH | LLM08 | CWE-78 |
| **Insufficient logging** | 3 | MEDIUM | — | CWE-778 |
| **Token/cost limits missing** | 3 | MEDIUM | — | CWE-770 |
| **Missing error handling** | 3 | LOW | — | CWE-755 |
| **System prompt exposure** | 3 | MEDIUM | LLM07 | CWE-200 |
| **PII in prompts** (SSN, email, credit card) | 3 | HIGH | LLM06 | CWE-359 |
| **Output validation** | 2 | HIGH | LLM02 | CWE-20 |
| **Model versioning** | 1 | MEDIUM | — | CWE-1188 |
| **Training data security** | 1 | MEDIUM | — | CWE-319 |
| **API key in .env files** | 1 | CRITICAL | LLM06 | CWE-798 |
| **Unauthenticated model endpoint** | 1 | HIGH | LLM06 | CWE-306 |

## Rule Categories

### Taint Analysis Rules (`prompt_injection_taint.yaml`)
Traces user input from web framework request objects (Flask, FastAPI, Django, Express) to LLM API calls (OpenAI, Anthropic). Catches prompt injection even through intermediate variables. FastAPI rules are scoped to route handler decorators with `focus-metavariable` for precision.

### Unsafe Deserialization (`unsafe_deserialization.yaml`)
Based on Trail of Bits research. Detects `pickle.load()`, `torch.load()` without `weights_only=True`, `joblib.load()`, `numpy.load(allow_pickle=True)` (including `np.load` alias), unsafe `yaml.load()`, and Keras model loading without `safe_mode=True`. Includes auto-fix for `yaml.load()` → `yaml.safe_load()`.

### LLM Output Execution (`llm_output_execution.yaml`)
Detects LLM response content flowing into `exec()`, `eval()`, `subprocess`, or `os.system()`. Covers OpenAI, Anthropic, and generic variable-name heuristics.

### LLM Output SSRF (`llm_output_ssrf.yaml`)
Detects LLM response content used as URLs in HTTP requests (`requests`, `httpx`, `urllib`). Prevents server-side request forgery via prompt injection.

### MCP Server Security (`mcp_server.yaml`)
AST-scoped to `@server.tool()` decorated functions. Detects shell execution, filesystem writes (including binary modes), SQL injection, and untyped tool inputs in MCP server tools.

### RAG Access Control (`rag_no_access_control.yaml`)
Per-database rules for Pinecone, Chroma, Qdrant, Weaviate, and LangChain vector stores. Flags vector queries without tenant-isolation filters.

### Token/Cost Limits (`token_limit_missing.yaml`)
Detects OpenAI and Anthropic API calls without `max_tokens` set, which risks unbounded token generation and cost.

### Guardrails Disabled (`guardrails_disabled.yaml`)
Detects explicitly disabled safety settings: Gemini `BLOCK_NONE`, empty `safety_settings`, LangChain `allow_dangerous_*` flags, and missing OpenAI Moderation API checks.

## Metadata

Every rule includes structured metadata:
- **CWE** — Common Weakness Enumeration ID
- **OWASP LLM** — OWASP Top 10 for LLM Applications 2025 mapping
- **Confidence** — HIGH, MEDIUM, or LOW
- **Category** — `security` or `best-practice`
- **Technology** — Framework/SDK tags for filtering
- **References** — Links to relevant documentation
- **SOC 2 controls** — CC-series control mappings

## Frameworks Mapped

Each finding maps to multiple compliance frameworks:
- OWASP Top 10 for LLM Applications 2025
- OWASP Top 10 for Agentic AI
- NIST AI RMF 1.0
- NIST AI 600-1 (GenAI Profile)
- ISO/IEC 42001:2023
- EU AI Act
- MITRE ATLAS
- CWE (Common Weakness Enumeration)

## Languages

- **Python** — full AST + taint analysis
- **JavaScript / TypeScript** — AST pattern matching
- **Generic** — .env file scanning

## License

Part of the Whitney AI Governance Platform by Transilience AI.
