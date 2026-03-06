"""
Train RL agent from Cowrie JSON logs.
Reads past sessions and uses them to pre-train the Q-table.
"""
import json
import os
import sys
sys.path.insert(0, '/home/cowrie/Adaptive-SSH-Honeypot/src')

from cowrie.adaptive.rl_agent import rl_agent

LOG_PATH = "var/log/cowrie/cowrie.json"

def categorize_command(cmd):
    cmd = cmd.lower()
    if any(x in cmd for x in ["ls", "pwd", "whoami", "id"]): return 0
    elif any(x in cmd for x in ["cat", "aws", "curl"]): return 1
    elif any(x in cmd for x in ["sudo", "chmod", "su"]): return 2
    elif any(x in cmd for x in ["rm", "wget", "python", "perl"]): return 3
    return 0

def train_from_logs():
    if not os.path.exists(LOG_PATH):
        print(f"[TRAIN] Log file not found: {LOG_PATH}")
        return

    sessions = {}
    total_lines = 0
    trained = 0

    print(f"[TRAIN] Reading {LOG_PATH}...")

    with open(LOG_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                total_lines += 1
                sid = entry.get("session", "unknown")
                event = entry.get("eventid", "")

                if sid not in sessions:
                    sessions[sid] = {"commands": [], "duration": 0}

                if event == "cowrie.command.input":
                    cmd = entry.get("input", "")
                    sessions[sid]["commands"].append(cmd)

                elif event == "cowrie.session.closed":
                    sessions[sid]["duration"] = entry.get("duration", 0)

            except json.JSONDecodeError:
                continue

    print(f"[TRAIN] Found {len(sessions)} sessions, {total_lines} log entries")

    for sid, data in sessions.items():
        cmds = data["commands"]
        duration = float(data["duration"] or 0)
        if not cmds:
            continue

        for i, cmd in enumerate(cmds):
            cat = categorize_command(cmd)
            honeytokens = ["credentials", "passwords", "backup", "aws", "private_key"]
            hflag = 1 if any(t in cmd.lower() for t in honeytokens) else 0
            bucket = 0 if i < 5 else (1 if i < 15 else 2)
            state = (cat, hflag, bucket, cat if not hflag else 3)

            # Infer action from log (default normal_response)
            action = 0

            # Compute reward based on session duration
            reward = 1
            if duration > 60: reward += 5
            if duration > 300: reward += 10
            if hflag: reward += 3

            next_state = state
            rl_agent.update(state, action, reward, next_state)
            trained += 1

    print(f"[TRAIN] Trained RL agent on {trained} commands from logs")
    print(f"[TRAIN] Q-table now has {len(rl_agent.q_table)} states")
    rl_agent.save_model()
    print("[TRAIN] Model saved!")

if __name__ == "__main__":
    train_from_logs()
