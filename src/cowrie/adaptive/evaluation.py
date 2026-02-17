
import json
import numpy as np
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Path to cowrie.json
# Assuming running from project root or src/cowrie/adaptive
# Let's try to find it dynamically or use absolute path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
LOG_FILE = os.path.join(PROJECT_ROOT, "var/log/cowrie/cowrie.json")

print(f"[*] Analyzing Log File: {LOG_FILE}")

if not os.path.exists(LOG_FILE):
    print(f"[!] Log file not found at {LOG_FILE}")
    exit(1)

sessions = {}

with open(LOG_FILE, "r") as f:
    for line in f:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
            
        sid = event.get("session")
        if not sid: continue

        if sid not in sessions:
            sessions[sid] = {
                "commands": 0,
                "honeytoken": False,
                "duration": 0,
                "start_time": None,
                "end_time": None
            }

        timestamp = event.get("timestamp") # ISO format, might need parsing if duration not provided

        if event["eventid"] == "cowrie.command.input":
            sessions[sid]["commands"] += 1
            # Check for honeytoken in command content (simple check)
            cmd = event.get("input", "").lower()
            if ".aws_backup_keys.txt" in cmd or "honeytoken" in cmd:
                 sessions[sid]["honeytoken"] = True

        msg = event.get("message", "")
        if isinstance(msg, list):
            msg = " ".join(str(m) for m in msg)
        
        if "honeytoken" in str(msg).lower():
            sessions[sid]["honeytoken"] = True
            
        # Catch explicit honeytoken trigger event if present
        if event["eventid"] == "cowrie.honeytoken.triggered":
             sessions[sid]["honeytoken"] = True

        if event["eventid"] == "cowrie.session.closed":
            sessions[sid]["duration"] = float(event.get("duration", 0))

# ---- METRICS ----

durations = [s["duration"] for s in sessions.values()]
commands = [s["commands"] for s in sessions.values()]
honey = [1 for s in sessions.values() if s["honeytoken"]]

print("-" * 40)
print("EVALUATION RESULTS")
print("-" * 40)
print("Total Sessions:", len(sessions))
if len(sessions) > 0:
    print("Average Duration:", np.mean(durations))
    print("Average Commands:", np.mean(commands))
    print("Honeytoken Trigger Rate:", len(honey)/len(sessions))
else:
    print("No sessions found.")

# ---- GRAPHS ----

if len(sessions) > 0:
    # 1. Session Duration Distribution
    plt.figure(figsize=(10, 5))
    plt.hist(durations, bins=20, alpha=0.7, color='blue', edgecolor='black')
    plt.title("Session Duration Distribution")
    plt.xlabel("Duration (seconds)")
    plt.ylabel("Frequency")
    plt.grid(True, alpha=0.3)
    plt.savefig("session_duration_dist.png")
    print("[*] Graph saved: session_duration_dist.png")
    
    # 2. Commands per Session
    plt.figure(figsize=(10, 5))
    plt.hist(commands, bins=range(min(commands), max(commands) + 2, 1), alpha=0.7, color='green', edgecolor='black')
    plt.title("Commands per Session Distribution")
    plt.xlabel("Number of Commands")
    plt.ylabel("Frequency")
    plt.grid(True, alpha=0.3)
    plt.xticks(range(min(commands), max(commands) + 1))
    plt.savefig("commands_dist.png")
    print("[*] Graph saved: commands_dist.png")

# ---- TRAINING REWARD CURVE (Mock or from Log if available) ----
# We can try to parse training rewards from stdout logs if we saved them, 
# or simpler, we can't reconstruct exact training curve from cowrie.json unless we logged it.
# But I can check if 'brain.log' or similar exists, or just use the q_table values to show something?
# Or maybe the user wants me to simulated/plot based on what I saw in demo_simulation?

# User said: "Store episode reward list. Then: plt.plot(episode_rewards)"
# This implies I should have modified the training loop to save this or dump it.
# Since I already ran training in demo_simulation.py --train, and it printed to stdout.
# I didn't save it to a file.
# BUT, `demo_simulation.py` is the one that generates the reward curve graph.
# I should Modify `demo_simulation.py` to generate the graph as requested in Phase 3.

print("[*] Evaluation script complete.")
