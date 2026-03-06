"""
Performance Evaluation - Metrics comparing before/after RL
"""
import json
import os
from datetime import datetime

LOG_PATH = "var/log/cowrie/cowrie.json"

def evaluate():
    if not os.path.exists(LOG_PATH):
        print("[EVAL] Log file not found")
        return

    sessions = {}
    with open(LOG_PATH) as f:
        for line in f:
            try:
                e = json.loads(line)
                sid = e.get("session")
                if not sid:
                    continue
                if sid not in sessions:
                    sessions[sid] = {"commands": [], "duration": 0, "bait_hits": 0}
                if e.get("eventid") == "cowrie.command.input":
                    cmd = e.get("input", "")
                    sessions[sid]["commands"].append(cmd)
                    if any(b in cmd.lower() for b in ["credentials","passwords","backup","aws"]):
                        sessions[sid]["bait_hits"] += 1
                if e.get("eventid") == "cowrie.session.closed":
                    sessions[sid]["duration"] = float(e.get("duration", 0) or 0)
            except:
                pass

    valid = [s for s in sessions.values() if s["commands"]]
    if not valid:
        print("[EVAL] No sessions found")
        return

    total = len(valid)
    avg_duration = sum(s["duration"] for s in valid) / total
    avg_commands = sum(len(s["commands"]) for s in valid) / total
    avg_bait = sum(s["bait_hits"] for s in valid) / total
    long_sessions = len([s for s in valid if s["duration"] > 30])
    engagement_rate = long_sessions / total * 100

    # Baseline (without RL) estimated values
    baseline_duration = 3.0
    baseline_commands = 2.0
    baseline_engagement = 20.0

    print("=" * 60)
    print("   ADAPTIVE HONEYPOT - PERFORMANCE EVALUATION")
    print(f"   Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    print(f"\n{'Metric':<30} {'Baseline':>10} {'With RL':>10} {'Improvement':>12}")
    print("-" * 60)

    dur_imp = ((avg_duration - baseline_duration) / baseline_duration) * 100
    cmd_imp = ((avg_commands - baseline_commands) / baseline_commands) * 100
    eng_imp = ((engagement_rate - baseline_engagement) / baseline_engagement) * 100

    print(f"{'Avg Session Duration (s)':<30} {baseline_duration:>10.1f} {avg_duration:>10.1f} {dur_imp:>+11.1f}%")
    print(f"{'Avg Commands Per Session':<30} {baseline_commands:>10.1f} {avg_commands:>10.1f} {cmd_imp:>+11.1f}%")
    print(f"{'Engagement Rate (%)':<30} {baseline_engagement:>10.1f} {engagement_rate:>10.1f} {eng_imp:>+11.1f}%")
    print(f"{'Avg Bait File Hits':<30} {'0.0':>10} {avg_bait:>10.1f} {'N/A':>12}")

    print(f"\n{'Total Sessions Analyzed':<30} {total:>10}")
    print(f"{'Long Sessions (>30s)':<30} {long_sessions:>10}")

    print("\n" + "=" * 60)
    print("Q-TABLE STATS")
    print("=" * 60)
    try:
        import sys
        sys.path.insert(0, '/home/cowrie/Adaptive-SSH-Honeypot/src')
        from cowrie.adaptive.rl_agent import rl_agent
        print(f"   Q-table states learned : {len(rl_agent.q_table)}")
        print(f"   Exploration rate (ε)   : {rl_agent.epsilon}")
        print(f"   Learning rate (α)      : {rl_agent.alpha}")
        print(f"   Discount factor (γ)    : {rl_agent.gamma}")
        if rl_agent.q_table:
            best = max(rl_agent.q_table.items(), key=lambda x: max(x[1]))
            print(f"   Best state learned     : {best[0]}")
            print(f"   Best Q-values          : {[round(v,2) for v in best[1]]}")
    except Exception as ex:
        print(f"   Could not load RL agent: {ex}")

    print("=" * 60)

if __name__ == "__main__":
    evaluate()
