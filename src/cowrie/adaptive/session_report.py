import json
import os
from datetime import datetime

def generate_report(log_path=None, output_dir=None):
    if log_path is None:
        log_path = os.path.expanduser(
            "~/Adaptive-SSH-Honeypot/var/log/cowrie/cowrie.json"
        )
    if output_dir is None:
        output_dir = os.path.expanduser(
            "~/Adaptive-SSH-Honeypot/var/log/cowrie/reports"
        )

    os.makedirs(output_dir, exist_ok=True)

    sessions = {}
    
    try:
        with open(log_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    event = data.get('eventid', '')
                    session = data.get('session', 'unknown')
                    src_ip = data.get('src_ip', 'unknown')

                    if session not in sessions:
                        sessions[session] = {
                            'src_ip': src_ip,
                            'start_time': data.get('timestamp', ''),
                            'end_time': '',
                            'username': '',
                            'commands': [],
                            'duration': 0,
                            'skill_level': 'UNKNOWN',
                            'rl_actions': [],
                            'total_reward': 0,
                            'downloads': []
                        }

                    if event == 'cowrie.login.success':
                        sessions[session]['username'] = data.get('username', '')

                    elif event == 'cowrie.command.input':
                        cmd = data.get('input', '')
                        sessions[session]['commands'].append(cmd)

                    elif event == 'cowrie.session.closed':
                        sessions[session]['duration'] = data.get('duration', 0)
                        sessions[session]['end_time'] = data.get('timestamp', '')

                    elif event == 'cowrie.session.file_download':
                        sessions[session]['downloads'].append(
                            data.get('url', 'unknown')
                        )

                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"Log file not found: {log_path}")
        return

    # Determine skill level
    expert_commands = ['iptables', 'tcpdump', 'strace', 'gdb', 'ltrace']
    intermediate_commands = ['netstat', 'ss', 'find', 'grep', 'cat /etc/shadow']
    
    for sid, info in sessions.items():
        cmds = ' '.join(info['commands']).lower()
        if any(c in cmds for c in expert_commands):
            info['skill_level'] = 'EXPERT 🔴'
        elif any(c in cmds for c in intermediate_commands):
            info['skill_level'] = 'INTERMEDIATE 🟡'
        elif len(info['commands']) > 0:
            info['skill_level'] = 'SCRIPT KIDDIE 🟢'

    # Generate report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = os.path.join(output_dir, f"attack_report_{timestamp}.txt")

    with open(report_file, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("   ADAPTIVE HONEYPOT - ATTACK SESSION REPORT\n")
        f.write(f"   Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"TOTAL SESSIONS CAPTURED: {len(sessions)}\n\n")

        for i, (sid, info) in enumerate(sessions.items(), 1):
            f.write(f"{'─' * 60}\n")
            f.write(f"SESSION {i}\n")
            f.write(f"{'─' * 60}\n")
            f.write(f"Session ID    : {sid}\n")
            f.write(f"Attacker IP   : {info['src_ip']}\n")
            f.write(f"Username      : {info['username']}\n")
            f.write(f"Skill Level   : {info['skill_level']}\n")
            f.write(f"Start Time    : {info['start_time']}\n")
            f.write(f"End Time      : {info['end_time']}\n")
            f.write(f"Duration      : {info['duration']:.1f} seconds\n")
            f.write(f"Commands Typed: {len(info['commands'])}\n")

            if info['downloads']:
                f.write(f"\nFILES DOWNLOADED:\n")
                for d in info['downloads']:
                    f.write(f"  → {d}\n")

            f.write(f"\nCOMMAND HISTORY:\n")
            for j, cmd in enumerate(info['commands'], 1):
                f.write(f"  [{j:02d}] {cmd}\n")

            # Deception score
            score = min(100, len(info['commands']) * 5 + info['duration'])
            f.write(f"\nDECEPTION SCORE: {score:.0f}/100\n")
            if score > 75:
                verdict = "EXCELLENT - Attacker was fully deceived!"
            elif score > 50:
                verdict = "GOOD - Attacker stayed engaged"
            elif score > 25:
                verdict = "FAIR - Partial engagement achieved"
            else:
                verdict = "POOR - Attacker left quickly"
            f.write(f"VERDICT       : {verdict}\n\n")

        f.write("=" * 60 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 60 + "\n")

    print(f"\n✅ Report saved: {report_file}")
    print(f"   Sessions: {len(sessions)}")
    
    # Also print summary to screen
    print("\n" + "=" * 60)
    print("ATTACK SUMMARY")
    print("=" * 60)
    for sid, info in sessions.items():
        print(f"IP: {info['src_ip']} | Skill: {info['skill_level']} | "
              f"Commands: {len(info['commands'])} | "
              f"Duration: {info['duration']:.0f}s")
    
    return report_file

if __name__ == "__main__":
    generate_report()
