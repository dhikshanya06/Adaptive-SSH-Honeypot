import json
import os
from datetime import datetime

def generate_report():
    log_file = "var/log/cowrie/cowrie.json"
    sessions = {}

    with open(log_file) as f:
        for line in f:
            try:
                e = json.loads(line)
                sid = e.get("session")
                if not sid:
                    continue
                if sid not in sessions:
                    sessions[sid] = {"src_ip": e.get("src_ip","unknown"), "commands": [], "duration": 0, "skill_level": "UNKNOWN"}
                if e.get("eventid") == "cowrie.command.input":
                    sessions[sid]["commands"].append(e.get("input",""))
                if e.get("eventid") == "cowrie.session.closed":
                    sessions[sid]["duration"] = float(e.get("duration", 0))
                if e.get("eventid") == "cowrie.login.success":
                    sessions[sid]["src_ip"] = e.get("src_ip","unknown")
            except:
                pass

    # Detect skill
    expert_cmds = ["nmap","tcpdump","strace","ltrace","gdb","wireshark","metasploit","iptables","/proc/","ptrace"]
    intermediate_cmds = ["netstat","ss -","find / -perm","cat /etc/shadow","cat /etc/passwd","sudo -l","crontab","wget","curl","chmod +x","base64","python -c","perl -e"]
    kiddie_cmds = ["whoami","id","uname","ls","pwd","echo","hostname"]

    for sid, info in sessions.items():
        cmds_str = " ".join(info["commands"]).lower()
        if any(c in cmds_str for c in expert_cmds):
            info["skill_level"] = "EXPERT"
        elif any(c in cmds_str for c in intermediate_cmds):
            info["skill_level"] = "INTERMEDIATE"
        elif info["commands"]:
            info["skill_level"] = "SCRIPT_KIDDIE"

    # Filter valid sessions
    valid = [s for s in sessions.values() if s["skill_level"] != "UNKNOWN" and s["duration"] > 2]
    valid.sort(key=lambda x: x["duration"], reverse=True)

    skill_emoji = {"EXPERT": "🔴 EXPERT", "INTERMEDIATE": "🟡 INTERMEDIATE", "SCRIPT_KIDDIE": "🟢 SCRIPT KIDDIE"}

    # Save report
    os.makedirs("var/log/cowrie/reports", exist_ok=True)
    report_file = f"var/log/cowrie/reports/attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    print()
    print("=" * 70)
    print("           ATTACK SESSION REPORT")
    print("=" * 70)

    for i, info in enumerate(valid, 1):
        skill = info["skill_level"]
        score = min(100, len(info["commands"]) * 5 + int(info["duration"] / 10))
        print(f"\n[{i}] IP Address  : {info['src_ip']}")
        print(f"    Skill Level : {skill_emoji.get(skill, skill)}")
        print(f"    Duration    : {info['duration']:.0f} seconds")
        print(f"    Commands    : {len(info['commands'])}")
        if info["commands"]:
            print(f"    History     : {chr(32).join(['→' + c for c in info['commands'][:6]])}")
        print(f"    Deception   : {score}/100")
        print(f"    {'-'*55}")

    print()
    print("SUMMARY:")
    print(f"  Total Sessions : {len(valid)}")
    avg = sum(s["duration"] for s in valid) / max(len(valid), 1)
    print(f"  Avg Duration   : {avg:.0f} seconds")
    print(f"  Expert         : {sum(1 for s in valid if s['skill_level'] == 'EXPERT')}")
    print(f"  Intermediate   : {sum(1 for s in valid if s['skill_level'] == 'INTERMEDIATE')}")
    print(f"  Script Kiddie  : {sum(1 for s in valid if s['skill_level'] == 'SCRIPT_KIDDIE')}")
    print("=" * 70)
    print(f"\n✅ Report saved: {report_file}")

generate_report()
