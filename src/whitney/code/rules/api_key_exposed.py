# Test file for api_key_exposed.yaml rules

# ruleid: code-ai-api-key-exposed-openai
api_key = "sk-abc123def456ghi789jkl012mno"

# ruleid: code-ai-api-key-exposed-openai
OPENAI_API_KEY = "sk-proj-abc123def456-ghi789jkl012mno345"

# ruleid: code-ai-api-key-exposed-anthropic
api_key = "sk-ant-abc123-def456ghi789jkl012mno"

# ruleid: code-ai-api-key-exposed-huggingface
HF_TOKEN = "hf_abc123def456ghi789jkl012mno"

# ruleid: code-ai-api-key-exposed-google
GOOGLE_API_KEY = "AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# ruleid: code-ai-api-key-exposed-replicate
REPLICATE_API_TOKEN = "r8_abc123def456ghi789jkl012mno345pqrs"

# ok: code-ai-api-key-exposed-openai
api_key = os.environ.get("OPENAI_API_KEY")

# ok: code-ai-api-key-exposed-anthropic
api_key = os.environ["ANTHROPIC_API_KEY"]
