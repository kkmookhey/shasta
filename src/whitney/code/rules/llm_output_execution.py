# Test file for llm_output_execution.yaml rules
import openai
import subprocess
import os

client = openai.OpenAI()

# --- OpenAI output → exec ---
response = client.chat.completions.create(model="gpt-4", messages=msgs)
output = response.choices[0].message.content
# ruleid: code-llm-output-exec-openai
exec(output)

# --- Direct exec ---
# ruleid: code-llm-output-exec-openai
exec(response.choices[0].message.content)

# --- OpenAI output → subprocess ---
response = client.chat.completions.create(model="gpt-4", messages=msgs)
cmd = response.choices[0].message.content
# ruleid: code-llm-output-exec-openai
subprocess.run(cmd, shell=True)

# --- Safe: hardcoded exec ---
# ok: code-llm-output-exec-openai
exec("print('hello')")
