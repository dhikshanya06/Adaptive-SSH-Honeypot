import os
import time
import json
from datetime import datetime

def clear():
    os.system('clear')

def read_latest_logs(log_path, lines=50):
    try:
        with open(log_path, 'r') as f:
            all_lines = f.readlines()
            return all_lines[-lines:]
    except:
        return []

def parse_log_line(line):
    try:
        return json.loads(line)
    except:
        return None

def get_risk_bar(level):
    bars = int(level * 10)
    return "█" * bars + "░" * (10 - bars)

def display_dashboard(log_path):
    sessions = {}
    bait_files = []
    total_commands = 0
    last_command = ""
    last_action = ""
    total_reward = 0

    clear()
    print("\033[1;31m")  # Red bold
    print("╔══════════════════════════════════════════════════════════╗")
    print("║         🔴  ADAPTIVE HONEYPOT LIVE DASHBOARD  🔴         ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print("\033[0m")

    logs = read_latest_logs(log_path)

    for line in logs:
        data = parse_log_line(line)
        if not data:
            continue

        event = data.get('eventid', '')
        src = data.get('src_ip', 'unknown')
        timestamp = data.get('timestamp', '')

        if event == 'cowrie.login.success':
            if src not in sessions:
                sessions[src] = {
                    'login_time': timestamp,
                    'commands': [],
                    'username': data.get('username', 'unknown')
                }

        elif event == 'cowrie.command.input':
            cmd = data.get('input', '')
            total_commands += 1
            last_command = cmd
            if src in sessions:
                sessions[src]['commands'].append(cmd)

            # Detect bait keywords
            for keyword in ['database', 'password', 'backup', 'config']:
                if keyword in cmd.lower():
                    bait_file = f"/home/admin/{keyword}_file"
                    if bait_file not in bait_files:
                        bait_files.append(bait_file)

        elif event == 'cowrie.rl.action':
            action_map = {0: 'STANDARD', 1: 'TEMPTING 🎯', 2: 'FAKE ERROR ⚠️'}
            last_action = action_map.get(data.get('action', 0), 'UNKNOWN')

        elif event == 'cowrie.rl.update':
            total_reward += data.get('reward', 0)

    # Display active sessions
    print(f"\033[1;33m  ACTIVE SESSIONS: {len(sessions)}\033[0m")
    print(f"  {'─'*55}")

    if sessions:
        for ip, info in sessions.items():
            cmds = info['commands']
            skill = "EXPERT 🔴" if len(cmds) > 10 else "INTERMEDIATE 🟡" if len(cmds) > 5 else "SCRIPT KIDDIE 🟢"
            risk = min(len(cmds) / 15.0, 1.0)

            print(f"\033[1;36m  Attacker IP    :\033[0m {ip}")
            print(f"\033[1;36m  Username       :\033[0m {info['username']}")
            print(f"\033[1;36m  Skill Level    :\033[0m {skill}")
            print(f"\033[1;36m  Commands Typed :\033[0m {len(cmds)}")
            print(f"\033[1;36m  Risk Level     :\033[0m {get_risk_bar(risk)}")
            print()
    else:
        print("  No active sessions yet. Waiting for attackers...")

    print(f"  {'─'*55}")
    print(f"\033[1;33m  HONEYPOT STATISTICS\033[0m")
    print(f"  {'─'*55}")
    print(f"\033[1;36m  Total Commands  :\033[0m {total_commands}")
    print(f"\033[1;36m  Last Command    :\033[0m {last_command}")
    print(f"\033[1;36m  RL Last Action  :\033[0m {last_action}")
    print(f"\033[1;36m  Total Reward    :\033[0m {total_reward}")
    print()

    print(f"\033[1;33m  BAIT FILES PLANTED\033[0m")
    print(f"  {'─'*55}")
    if bait_files:
        for f in bait_files:
            print(f"  \033[1;32m✅ {f}\033[0m")
    else:
        print("  No bait files planted yet")

    print()
    print(f"\033[1;33m  RL AGENT ACTIONS LEGEND\033[0m")
    print(f"  {'─'*55}")
    print(f"  Action 0 = STANDARD   → Normal terminal response")
    print(f"  Action 1 = TEMPTING   → Hints at valuable data")
    print(f"  Action 2 = FAKE ERROR → Looks like misconfiguration")
    print()
    print(f"\033[1;31m  Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m")
    print(f"  Press Ctrl+C to stop")

def run_dashboard():
    log_path = os.path.expanduser(
        "~/Adaptive-SSH-Honeypot/var/log/cowrie/cowrie.json"
    )
    print(f"Looking for logs at: {log_path}")
    while True:
        try:
            display_dashboard(log_path)
            time.sleep(3)
        except KeyboardInterrupt:
            print("\n\033[1;32mDashboard stopped.\033[0m")
            break
        except Exception as e:
            print(f"Dashboard error: {e}")
            time.sleep(3)

if __name__ == "__main__":
    run_dashboard()
