import json
import os
import time
from collections import defaultdict

# =====================================================
# RL CONFIGURATION (Display Only)
# =====================================================

ACTIONS = {
    0: "normal_response",
    1: "add_delay",
    2: "inject_fake_file",
    3: "fake_error",
    4: "escalate_deception",
    5: "terminate_session"
}

# =====================================================
# MAIN MONITOR
# =====================================================

def monitor_log():

    # Locate log file relative to this script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, "../../../"))
    log_path = os.path.join(project_root, "var/log/cowrie/cowrie.json")

    print("\n=================================================")
    print(" LIVE ADAPTIVE CONTROLLER :: RL MONITOR MODE")
    print("=================================================\n")
    print(f"[*] Monitoring log file: {log_path}")

    while not os.path.exists(log_path):
        time.sleep(1)

    # Track session data for context
    session_data = defaultdict(lambda: {"commands": 0})

    with open(log_path, "r") as f:
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            try:
                data = json.loads(line)
            except:
                continue

            event_id = data.get("eventid")
            session = data.get("session")

            # 1. COMMAND INPUT
            if event_id == "cowrie.command.input":
                command = data.get("input")
                print(f"[ACTIVITY] {session}: '{command}'")
                session_data[session]["commands"] += 1

            # 2. RL ACTION SELECTED (Source of Truth)
            elif event_id == "cowrie.rl.action":
                action_idx = data.get("action")
                state = data.get("state", "unknown")
                action_name = ACTIONS.get(action_idx, "unknown")
                
                print(f"   [RL AGENT] State:{state} -> Action:{action_name} ({action_idx})")

            # 3. RL UPDATE (Reward & Q-Value)
            elif event_id == "cowrie.rl.update":
                state = data.get("state")
                action = data.get("action")
                reward = data.get("reward")
                q_new = data.get("q_new")
                
                print(f"   [RL REWARD] R={reward}")
                print(f"   [RL UPDATE] S:{state} A:{action} Q-New:{q_new:.2f}")

            # 4. HONEYTOKEN TRIGGERED
            elif event_id == "cowrie.honeytoken.triggered":
                token = data.get("token")
                print(f"   [!!!] HONEYTOKEN TRIGGERED: {token}")


# =====================================================
# RUN
# =====================================================

if __name__ == "__main__":
    try:
        monitor_log()
    except KeyboardInterrupt:
        print("\n[!] Controller stopped.")


