import sys
import os

# Add src to path
sys.path.append(os.path.abspath("src"))

from cowrie.adaptive.rl_agent import rl_agent

class MockProtocol:
    def __init__(self):
        self.cmd_count = 0
        self._rl_action = 0 # Normal response

class MockCommand:
    def __init__(self, cmd, args, protocol):
        self.command_name = cmd
        self.args = args
        self.protocol = protocol

def test_reward():
    print("Testing Reward Logic...")
    proto = MockProtocol()
    
    # 1. Test Base Reward (Commands 1-9)
    print("\n--- Phase 1: Base Reward ---")
    for i in range(1, 10):
        proto.cmd_count = i
        cmd = MockCommand("ls", [], proto)
        reward = rl_agent.compute_reward(cmd)
        expected = 1
        print(f"Cmd {i}: Reward={reward} (Expected {expected})")
        if reward != expected:
            print("FAIL")
            return

    # 2. Test Threshold Bonus (Command 11) -> Threshold is 10
    # Command 10 is <= 10, so no bonus yet?
    # Logic: if session_length > 10.
    # So at 11, it should trigger.
    
    print("\n--- Phase 2: Threshold Trigger ---")
    proto.cmd_count = 10
    cmd = MockCommand("ls", [], proto)
    reward = rl_agent.compute_reward(cmd)
    print(f"Cmd 10: Reward={reward} (Expected 1)")
    if reward != 1: print("FAIL"); return

    proto.cmd_count = 11
    cmd = MockCommand("ls", [], proto)
    reward = rl_agent.compute_reward(cmd)
    # Expected: 1 (Content) + 5 (Bonus) = 6
    print(f"Cmd 11: Reward={reward} (Expected 6)")
    if reward != 6: 
        print(f"FAIL: Flag set? {getattr(proto, 'threshold_bonus_given', 'N/A')}")
        return

    # 3. Test One-Time Constraint (Command 12)
    print("\n--- Phase 3: One-Time Bonus Check ---")
    proto.cmd_count = 12
    cmd = MockCommand("ls", [], proto)
    reward = rl_agent.compute_reward(cmd)
    # Expected: 1 (Base only, bonus already given)
    print(f"Cmd 12: Reward={reward} (Expected 1)")
    if reward != 1: 
        print(f"FAIL: Bonus repeated! Flag: {getattr(proto, 'threshold_bonus_given', 'N/A')}")
        return

    # 4. Test Honeytoken
    print("\n--- Phase 4: Honeytoken ---")
    proto.cmd_count = 13
    cmd = MockCommand("cat", ["backup_credentials.txt"], proto)
    reward = rl_agent.compute_reward(cmd)
    # Expected: 1 (Base) + 3 (Honeytoken) = 4
    print(f"Cmd 13 (Honeytoken): Reward={reward} (Expected 4)")
    if reward != 4: print("FAIL"); return

    print("\nSUCCESS: All reward logic tests passed.")

if __name__ == "__main__":
    test_reward()
