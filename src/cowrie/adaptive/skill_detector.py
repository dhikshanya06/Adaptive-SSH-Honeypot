import json
import os
from datetime import datetime

SKILL_SIGNATURES = {
    'EXPERT': [
        'strace', 'ltrace', 'gdb', 'tcpdump', 'wireshark',
        'iptables', 'nmap', 'metasploit', 'msfconsole',
        '/proc/', 'ptrace', 'objdump', 'readelf'
    ],
    'INTERMEDIATE': [
        'netstat', 'ss -', 'find / -perm', 'cat /etc/shadow',
        'cat /etc/passwd', 'sudo -l', 'crontab', 'wget', 'curl',
        'chmod +x', 'base64', 'python -c', 'perl -e'
    ],
    'SCRIPT_KIDDIE': [
        'whoami', 'id', 'uname', 'ls', 'pwd', 'echo',
        'cat /etc/issue', 'hostname'
    ]
}

class SkillDetector:
    def __init__(self):
        self.session_commands = {}
        self.session_skills = {}
        self.alert_log = os.path.expanduser(
            "~/Adaptive-SSH-Honeypot/var/log/cowrie/skill_alerts.log"
        )

    def analyze_command(self, session_id, command):
        if session_id not in self.session_commands:
            self.session_commands[session_id] = []
        
        self.session_commands[session_id].append(command)
        skill = self._detect_skill(session_id)
        
        # Alert on skill upgrade
        old_skill = self.session_skills.get(session_id, 'UNKNOWN')
        if skill != old_skill:
            self.session_skills[session_id] = skill
            self._log_alert(session_id, skill, command)
        
        return skill

    def _detect_skill(self, session_id):
        commands = ' '.join(self.session_commands[session_id]).lower()
        
        for sig in SKILL_SIGNATURES['EXPERT']:
            if sig.lower() in commands:
                return 'EXPERT'
        
        for sig in SKILL_SIGNATURES['INTERMEDIATE']:
            if sig.lower() in commands:
                return 'INTERMEDIATE'
        
        return 'SCRIPT_KIDDIE'

    def _log_alert(self, session_id, skill, trigger_command):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alert = (
            f"[{timestamp}] SKILL DETECTED: {skill} | "
            f"Session: {session_id} | "
            f"Triggered by: {trigger_command}\n"
        )
        print(f"\n🚨 ALERT: {alert}", flush=True)
        try:
            os.makedirs(os.path.dirname(self.alert_log), exist_ok=True)
            with open(self.alert_log, 'a') as f:
                f.write(alert)
        except Exception as e:
            print(f"Alert log error: {e}")

skill_detector = SkillDetector()


if __name__ == "__main__":
    import json
    log_file = "var/log/cowrie/cowrie.json"
    detector = SkillDetector()
    sessions = {}
    session_commands_map = {}

    try:
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get('eventid') == 'cowrie.command.input':
                        sid = event.get('session', 'unknown')
                        cmd = event.get('input', '')
                        src_ip = event.get('src_ip', 'unknown')
                        sessions[sid] = src_ip
                        if sid not in session_commands_map:
                            session_commands_map[sid] = []
                        session_commands_map[sid].append(cmd)
                        detector.analyze_command(sid, cmd)
                except:
                    pass
    except Exception as e:
        print(f"Error reading log: {e}")

    print()
    print("=" * 70)
    print("           ATTACKER SKILL DETECTION REPORT")
    print("=" * 70)

    skill_order = {'EXPERT': 0, 'INTERMEDIATE': 1, 'SCRIPT_KIDDIE': 2}
    skill_emoji = {'EXPERT': '🔴 EXPERT', 'INTERMEDIATE': '🟡 INTERMEDIATE', 'SCRIPT_KIDDIE': '🟢 SCRIPT KIDDIE'}

    filtered = {sid: skill for sid, skill in detector.session_skills.items() if skill != 'UNKNOWN'}
    sorted_sessions = sorted(filtered.items(), key=lambda x: skill_order.get(x[1], 99))

    for i, (sid, skill) in enumerate(sorted_sessions, 1):
        ip = sessions.get(sid, 'unknown')
        cmds = session_commands_map.get(sid, [])
        print(f"\n[{i}] Session  : {sid[:12]}...")
        print(f"    IP       : {ip}")
        print(f"    Skill    : {skill_emoji.get(skill, skill)}")
        print(f"    Commands : {len(cmds)}")
        print(f"    History  : {' → '.join(cmds[:8])}")
        print(f"    {'-'*60}")

    print()
    print("SUMMARY:")
    for skill in ['EXPERT', 'INTERMEDIATE', 'SCRIPT_KIDDIE']:
        count = sum(1 for s in filtered.values() if s == skill)
        print(f"  {skill_emoji.get(skill, skill)}: {count} session(s)")
    print("=" * 70)
