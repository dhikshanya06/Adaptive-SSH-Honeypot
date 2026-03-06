import groq
import os

client = groq.Groq(api_key=os.environ.get("GROQ_API_KEY"))

SYSTEM_PROMPT = """You are a Linux terminal on Ubuntu 20.04 production server named webserver-prod-01. You have MySQL, Apache, Docker, and SSH running. Only output raw terminal output exactly as it would appear on screen. Never explain commands. Never use markdown. Never use backticks. Just show realistic terminal output only.
"""

def get_llm_response(command, session_history=[]):
    try:
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        for prev_cmd, prev_resp in session_history[-5:]:
            messages.append({"role": "user", "content": prev_cmd})
            messages.append({"role": "assistant", "content": prev_resp})
        messages.append({"role": "user", "content": command})
        r = client.chat.completions.create(model="llama-3.1-8b-instant", messages=messages, max_tokens=300)
        return r.choices[0].message.content
    except Exception as e:
        cmd = command.split()[0] if command else "unknown"
        return f"-bash: {cmd}: command not found"
