# Test file for ai_logging_insufficient.yaml rules
import openai
import logging

logger = logging.getLogger(__name__)
client = openai.OpenAI()

# ruleid: code-ai-logging-insufficient-openai
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}]
)

# This should NOT trigger because logging is nearby
def logged_call():
    logger.info("Making API call")
    # ok: code-ai-logging-insufficient-openai
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}]
    )
    logger.info("Got response")
    return response

# This should still trigger — print is NOT acceptable logging
def print_only():
    print("Making API call")
    # ruleid: code-ai-logging-insufficient-openai
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}]
    )
    return response
