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
