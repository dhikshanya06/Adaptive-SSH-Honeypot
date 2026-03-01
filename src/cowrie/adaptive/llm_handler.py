import groq
import os

client = groq.Groq(api_key=os.environ.get("GROQ_API_KEY"))

def get_llm_response(command, session_history=[]):
    try:
        messages = [{"role": "user", "content": command}]
        r = client.chat.completions.create(model="llama-3.1-8b-instant", messages=messages, max_tokens=300)
        return r.choices[0].message.content
    except:
        cmd = command.split()[0] if command else "unknown"
        return f"-bash: {cmd}: command not found"
