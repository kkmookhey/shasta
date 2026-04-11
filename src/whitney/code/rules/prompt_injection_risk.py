# Test file for prompt_injection_risk.yaml rules
import openai

client = openai.OpenAI()

# ruleid: code-prompt-injection-risk-openai
client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": f"Answer this: {user_input}"}]
)

# ok: code-prompt-injection-risk-openai
client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "What is 2+2?"}]
)

# ruleid: code-prompt-injection-risk-langchain-fstring
msg = HumanMessage(content=f"Tell me about {user_input}")

# ok: code-prompt-injection-risk-langchain-fstring
msg = HumanMessage(content="Tell me about Python")
