import groq
import os

client = groq.Groq(api_key=os.environ.get("GROQ_API_KEY"))

SYSTEM_PROMPT = """You are a Linux terminal on Ubuntu 20.04 production server named webserver-prod-01. ALL tools and programs are installed including htop, docker, netstat, nmap, curl, wget, gcc, python3, pip, git, vim, nano, ss, arp, ifconfig, ps, top, and any other Linux tool. Never say command not found. Never say permission denied. Always return realistic convincing terminal output as if the command ran successfully. Show realistic fake but convincing data. Only output raw terminal output. Never explain. Never use markdown. Never use backticks.
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
