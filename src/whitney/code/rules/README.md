# Whitney AI Security Rules for Semgrep

48 Semgrep rules for detecting AI/LLM security vulnerabilities in source code.

## Quick Start

```bash
# Install Semgrep
pip install semgrep

# Scan your repo
semgrep --config path/to/whitney/code/rules/ /path/to/your/repo
```

## What It Detects

| Category | Rules | Severity | OWASP LLM |
|----------|-------|----------|-----------|
| **Prompt injection** (pattern + taint) | 10 | CRITICAL/HIGH | LLM01 |
| **Unsafe deserialization** (pickle, torch, joblib) | 6 | CRITICAL/HIGH | LLM05 |
| **MCP server security** (auth, tool scope, input) | 5 | HIGH/MEDIUM | Agentic #3 |
| **RAG access control** (per-database patterns) | 5 | MEDIUM | LLM08 |
| **API key exposure** | 3 | CRITICAL | LLM06 |
| **Agent tool abuse** | 3 | HIGH | LLM08 |
| **Insufficient logging** | 3 | MEDIUM | - |
| **Missing error handling** | 3 | LOW | LLM09 |
| **System prompt exposure** | 3 | MEDIUM | LLM07 |
| **Output validation** | 2 | HIGH | LLM02 |
| **Model versioning** | 1 | MEDIUM | - |
| **PII in prompts** | 1 | HIGH | LLM06 |
| **Training data security** | 1 | MEDIUM | LLM03 |
| **API key in .env files** | 1 | CRITICAL | LLM06 |

## Rule Categories

### Taint Analysis Rules (`prompt_injection_taint.yaml`)
Traces user input from web framework request objects (Flask, FastAPI, Django, Express) to LLM API calls (OpenAI, Anthropic). Catches prompt injection even through intermediate variables.

### Unsafe Deserialization (`unsafe_deserialization.yaml`)
Based on Trail of Bits research. Detects `pickle.load()`, `torch.load()` without `weights_only=True`, `joblib.load()`, `numpy.load(allow_pickle=True)`, unsafe `yaml.load()`, and Keras model loading without `safe_mode=True`.

### MCP Server Security (`mcp_server.yaml`)
AST-scoped to `@server.tool()` decorated functions. Detects shell execution, filesystem writes, SQL injection, and untyped tool inputs in MCP server tools.

### RAG Access Control (`rag_no_access_control.yaml`)
Per-database rules for Pinecone, Chroma, Qdrant, Weaviate, and LangChain vector stores. Flags vector queries without tenant-isolation filters.

## Frameworks Mapped

Each finding maps to multiple compliance frameworks:
- OWASP Top 10 for LLM Applications 2025
- OWASP Top 10 for Agentic AI
- NIST AI RMF 1.0
- NIST AI 600-1 (GenAI Profile)
- ISO/IEC 42001:2023
- EU AI Act
- MITRE ATLAS

## Languages

- **Python** — full AST + taint analysis
- **JavaScript / TypeScript** — AST pattern matching
- **Generic** — .env file scanning

## License

Part of the Whitney AI Governance Platform by Transilience AI.
