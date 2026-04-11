# Test file for llm_output_ssrf.yaml rules
import openai
import requests

client = openai.OpenAI()

# --- OpenAI output → requests.get ---
response = client.chat.completions.create(model="gpt-4", messages=msgs)
url = response.choices[0].message.content
# ruleid: code-llm-output-ssrf-openai
data = requests.get(url)

# --- Direct use ---
# ruleid: code-llm-output-ssrf-openai
data = requests.get(response.choices[0].message.content)

# --- Safe: hardcoded URL ---
# ok: code-llm-output-ssrf-openai
data = requests.get("https://api.example.com/data")
