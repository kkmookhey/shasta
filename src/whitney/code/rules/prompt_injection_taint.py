# Test file for prompt_injection_taint.yaml rules

from flask import Flask, request
import openai

app = Flask(__name__)
client = openai.OpenAI()

# --- Flask → OpenAI taint tests ---

@app.route("/chat", methods=["POST"])
def chat_vulnerable():
    user_input = request.form.get("message")
    # ruleid: code-prompt-injection-taint-flask-openai
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}]
    )
    return response.choices[0].message.content

@app.route("/chat-safe", methods=["POST"])
def chat_safe():
    user_input = request.form.get("message")
    cleaned = sanitize_prompt(user_input)
    # ok: code-prompt-injection-taint-flask-openai
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": cleaned}]
    )
    return response.choices[0].message.content

# --- Django taint tests ---

def django_view_vulnerable(request):
    user_input = request.POST.get("query")
    # ruleid: code-prompt-injection-taint-django
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}]
    )
    return response

def django_view_safe(request):
    user_input = request.POST.get("query")
    cleaned = validate_input(user_input)
    # ok: code-prompt-injection-taint-django
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": cleaned}]
    )
    return response
