# Test file for meta_prompt_exposed.yaml rules

from flask import Flask
app = Flask(__name__)

# --- System prompt in route handler ---
@app.route("/chat")
def chat():
    # ruleid: code-meta-prompt-exposed-flask-route
    prompt = "You are a helpful assistant that answers questions"
    return prompt

# --- System prompt variable ---
# ruleid: code-meta-prompt-exposed-variable-assignment
system_prompt = "You are a helpful AI assistant"

# ruleid: code-meta-prompt-exposed-variable-assignment
SYSTEM_MESSAGE = '''You are a coding expert'''

# ok: code-meta-prompt-exposed-variable-assignment
greeting = "Hello, how can I help you?"
