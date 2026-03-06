"""
Live Dashboard - Monitor attacks and RL decisions in real time
"""
import os
import time
import json
from datetime import datetime

LOG_PATH = "var/log/cowrie/cowrie.json"

def clear():
    os.system('clear')

def read_logs():
    sessions = {}
    rl_actions = {"normal_response": 0, "add_delay": 0, "inject_fake_file": 0,
                  "fake_error": 0, "escalate_deception": 0, "terminate_session": 0}
    total_commands = 0
    bait_hits = 0

    if not os.path.exists(LOG_PATH):
        return sessions, rl_actions, total_commands, bait_hits

    with open(LOG_PATH, "r") as f:
        for line in f:
            try:
                e = json.loads(line)
                sid = e.get("session", "unknown")
                event = e.get("eventid", "")

                if sid not in sessions:
                    sessions[sid] = {
                        "src_ip": e.get("src_ip", "unknown"),
                        "commands": [],
                        "duration": 0,
                        "login_time": e.get("timestamp", "")
                    }

                if event == "cowrie.command.input":
                    cmd = e.get("input", "")
                    sessions[sid]["commands"].append(cmd)
                    total_commands += 1
                    bait_words = ["credentials", "passwords", "backup", "aws", "private_key"]
                    if any(b in cmd.lower() for b in bait_words):
                        bait_hits += 1

                if event == "cowrie.session.closed":
                    sessions[sid]["duration"] = float(e.get("duration", 0) or 0)

                if event == "cowrie.rl.action":
                    action_idx = e.get("action", 0)
                    action_names = list(rl_actions.keys())
                    if 0 <= action_idx < len(action_names):
                        rl_actions[action_names[action_idx]] += 1

            except:
                pass

    return sessions, rl_actions, total_commands, bait_hits

def display():
    clear()
    sessions, rl_actions, total_commands, bait_hits = read_logs()

    active = [s for s in sessions.values() if s["duration"] == 0]
    closed = [s for s in sessions.values() if s["duration"] > 0]
    avg_duration = sum(s["duration"] for s in closed) / max(len(closed), 1)

    print("=" * 65)
    print("      🍯 ADAPTIVE SSH HONEYPOT - LIVE DASHBOARD")
    print(f"      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    print(f"\n📊 SESSION STATS")
    print(f"   Total Sessions   : {len(sessions)}")
    print(f"   Active Now       : {len(active)}")
    print(f"   Closed           : {len(closed)}")
    print(f"   Avg Duration     : {avg_duration:.1f}s")
    print(f"   Total Commands   : {total_commands}")
    print(f"   Bait File Hits   : {bait_hits} 🎣")

    print(f"\n🤖 RL AGENT ACTIONS")
    total_actions = max(sum(rl_actions.values()), 1)
    for action, count in rl_actions.items():
        pct = count / total_actions * 100
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        print(f"   {action:<22} {bar} {count:>3} ({pct:.0f}%)")

    print(f"\n🔥 RECENT SESSIONS")
    recent = sorted(sessions.values(), key=lambda x: x["login_time"], reverse=True)[:5]
    for s in recent:
        status = "🟢 ACTIVE" if s["duration"] == 0 else f"⚫ {s['duration']:.1f}s"
        cmds = len(s["commands"])
        ip = s["src_ip"]
        last_cmd = s["commands"][-1] if s["commands"] else "none"
        print(f"   {ip:<18} {status:<15} {cmds:>3} cmds  Last: {last_cmd[:25]}")

    print("\n" + "=" * 65)
    print("  Press Ctrl+C to exit  |  Refreshing every 5s")
    print("=" * 65)

def run_dashboard(refresh=5):
    print("[DASHBOARD] Starting... Press Ctrl+C to stop")
    try:
        while True:
            display()
            time.sleep(refresh)
    except KeyboardInterrupt:
        print("\n[DASHBOARD] Stopped.")

if __name__ == "__main__":
    run_dashboard()
