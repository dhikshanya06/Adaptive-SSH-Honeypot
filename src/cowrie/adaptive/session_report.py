import json
import os
from datetime import datetime

def generate_report():
    log_file = "var/log/cowrie/cowrie.json"
    if not os.path.exists(log_file):
        print("[REPORT] Log file not found")
        return

    sessions = {}
    with open(log_file) as f:
        for line in f:
            try:
                e = json.loads(line)
                sid = e.get("session")
                if not sid:
                    continue
                if sid not in sessions:
                    sessions[sid] = {
                        "src_ip": e.get("src_ip", "unknown"),
                        "commands": [],
                        "duration": 0,
                        "skill_level": "UNKNOWN",
                        "timestamp": e.get("timestamp", "")
                    }
                if e.get("eventid") == "cowrie.command.input":
                    sessions[sid]["commands"].append(e.get("input", ""))
                if e.get("eventid") == "cowrie.session.closed":
                    sessions[sid]["duration"] = float(e.get("duration", 0) or 0)
                if e.get("eventid") == "cowrie.login.success":
                    sessions[sid]["src_ip"] = e.get("src_ip", "unknown")
            except:
                pass

    expert_cmds = ["nmap","tcpdump","strace","gdb","metasploit","iptables","/proc/","ptrace"]
    intermediate_cmds = ["netstat","find / -perm","cat /etc/shadow","sudo -l","crontab",
                         "wget","curl","chmod +x","base64","python -c","perl -e"]
    kiddie_cmds = ["whoami","id","uname","ls","pwd","echo","hostname"]

    for sid, info in sessions.items():
        cmds_str = " ".join(info["commands"]).lower()
        if any(c in cmds_str for c in expert_cmds):
            info["skill_level"] = "EXPERT"
        elif any(c in cmds_str for c in intermediate_cmds):
            info["skill_level"] = "INTERMEDIATE"
        elif info["commands"]:
            info["skill_level"] = "SCRIPT_KIDDIE"

    valid = [s for s in sessions.values() if s["skill_level"] != "UNKNOWN"]
    valid.sort(key=lambda x: x["duration"], reverse=True)

    skill_emoji = {
        "EXPERT": "🔴 EXPERT",
        "INTERMEDIATE": "🟡 INTERMEDIATE",
        "SCRIPT_KIDDIE": "🟢 SCRIPT KIDDIE"
    }

    os.makedirs("var/log/cowrie/reports", exist_ok=True)
    report_file = f"var/log/cowrie/reports/attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    lines = []
    lines.append("=" * 60)
    lines.append("       ADAPTIVE SSH HONEYPOT - ATTACK REPORT")
    lines.append(f"       Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)
    lines.append(f"\nTotal Sessions Analyzed: {len(valid)}")

    skill_counts = {"EXPERT": 0, "INTERMEDIATE": 0, "SCRIPT_KIDDIE": 0}
    for s in valid:
        skill_counts[s["skill_level"]] = skill_counts.get(s["skill_level"], 0) + 1

    lines.append(f"🔴 Expert Attackers:       {skill_counts['EXPERT']}")
    lines.append(f"🟡 Intermediate Attackers: {skill_counts['INTERMEDIATE']}")
    lines.append(f"🟢 Script Kiddies:         {skill_counts['SCRIPT_KIDDIE']}")
    lines.append("\n" + "=" * 60)
    lines.append("TOP SESSIONS BY DURATION")
    lines.append("=" * 60)

    for i, s in enumerate(valid[:10]):
        lines.append(f"\n[{i+1}] IP: {s['src_ip']}")
        lines.append(f"    Skill: {skill_emoji.get(s['skill_level'], s['skill_level'])}")
        lines.append(f"    Duration: {s['duration']:.1f}s")
        lines.append(f"    Commands ({len(s['commands'])}):")
        for cmd in s['commands'][:5]:
            lines.append(f"      $ {cmd}")
        if len(s['commands']) > 5:
            lines.append(f"      ... and {len(s['commands'])-5} more")

    report_text = "\n".join(lines)
    with open(report_file, "w") as f:
        f.write(report_text)

    print(report_text)
    print(f"\n[REPORT] Saved to {report_file}")
    return report_file

if __name__ == "__main__":
    generate_report()
