# Test file for guardrails_disabled.yaml rules
import google.generativeai as genai

# --- Empty safety settings ---
# ruleid: code-guardrails-disabled-empty-safety
model = genai.GenerativeModel("gemini-pro", safety_settings=[])

# --- LangChain allow dangerous ---
# ruleid: code-guardrails-disabled-langchain-allow-dangerous
loader = SomeLoader(path="data.pkl", allow_dangerous_deserialization=True)

# --- Safe: normal model usage ---
# ok: code-guardrails-disabled-empty-safety
model = genai.GenerativeModel("gemini-pro")
