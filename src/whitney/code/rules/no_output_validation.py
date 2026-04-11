# Test file for no_output_validation.yaml rules
import openai
import json

client = openai.OpenAI()

# ruleid: code-no-output-validation-openai
def get_answer():
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}]
    )
    return response.choices[0].message.content

# ok: code-no-output-validation-openai
def get_answer_validated():
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}]
    )
    output = response.choices[0].message.content
    validated = json.loads(output)
    return validated
