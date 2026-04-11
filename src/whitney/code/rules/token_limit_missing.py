# Test file for token_limit_missing.yaml rules
import openai
import anthropic

openai_client = openai.OpenAI()
anthropic_client = anthropic.Anthropic()

# ruleid: code-token-limit-missing-openai
response = openai_client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}]
)

# ok: code-token-limit-missing-openai
response = openai_client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}],
    max_tokens=1000
)

# ruleid: code-token-limit-missing-anthropic
response = anthropic_client.messages.create(
    model="claude-sonnet-4-20250514",
    messages=[{"role": "user", "content": "Hello"}]
)

# ok: code-token-limit-missing-anthropic
response = anthropic_client.messages.create(
    model="claude-sonnet-4-20250514",
    messages=[{"role": "user", "content": "Hello"}],
    max_tokens=1024
)
