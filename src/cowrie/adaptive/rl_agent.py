import random
import pickle
import os
import numpy as np # Keeping numpy for q-table operations if needed, or using pure python as requested? 
# User code used pure python lists for q-table values in select_action. 
# "self.q_table[state] = [0] * len(self.actions)"
# I will stick to the user's provided code structure for compliance.

class RLAgent:
    def __init__(self):
        self.q_table = {}
        self.alpha = 0.1
        self.gamma = 0.9
        self.epsilon = 0.2
        self.current_action = {}
        
        self.actions = [
            "normal_response",
            "add_delay",
            "inject_fake_file",
            "fake_error",
            "escalate_deception",
            "terminate_session"
        ]
        
        # Persistence path
        self.model_path = "q_table.pkl"
        self.load_model()

    def select_action(self, state):
        # Convert state to tuple if it isn't already (user example uses tuple)
        if state not in self.q_table:
            self.q_table[state] = [0.0] * len(self.actions)

        if random.random() < self.epsilon:
            action = random.randint(0, len(self.actions) - 1)
        else:
            # Find index of max value
            values = self.q_table[state]
            action = values.index(max(values))
            
        # Emit structured event for JSON log
        try:
            from twisted.python import log
            log.msg(eventid='cowrie.rl.action', 
                   action=action, 
                   state=str(state), 
                   message=f"RL Action Selected: {action}")
        except ImportError:
            pass

        print(f"[RL] Action selected: {action}", flush=True)
        return action

    def update(self, state, action, reward, next_state):
        if next_state not in self.q_table:
            self.q_table[next_state] = [0.0] * len(self.actions)

        old_value = self.q_table[state][action]
        next_max = max(self.q_table[next_state])

        new_value = old_value + self.alpha * (reward + self.gamma * next_max - old_value)
        self.q_table[state][action] = new_value
        
        print(f"   [RL UPDATE] S:{state} A:{action} R:{reward} Q-New:{new_value:.2f}", flush=True)
        
        # Emit structured event for JSON log
        try:
            from twisted.python import log
            log.msg(eventid='cowrie.rl.update', 
                   state=str(state), 
                   action=action, 
                   reward=reward, 
                   q_new=new_value,
                   message=f"RL Update: S:{state} A:{action} R:{reward} Q:{new_value:.2f}")
        except ImportError:
            pass
            
        self.save_model()

    # Reuse existing state extraction logic or use simple placeholder?
    # User said: "Simple state example state = (0, 0, 0, 0)" in command.py step.
    # But I should probably keep the robust extract_state I wrote earlier if I can, 
    # OR follow the user's instruction to "Keep rl_agent.py" but then they gave specific code to "Add this at top".
    # User said: "Modify rl_agent.py (Final Runtime Version)... You must define... Add this at top... Add select_action... Add update..."
    # I should probably preserve `extract_state` and `compute_reward` from previous step if they are compatible,
    # otherwise the agent will be dumb. 
    # However, the user instruction "Simple state example state = (0, 0, 0, 0)" in command.py implies I might just use dummy state for now?
    # No, "Simple state example" was likely just for the *snippet*.
    # I will keep `extract_state` and `compute_reward` to ensure it actually works intelligently.
    # But I will update them to use the new action list size/semantics if needed.

    # ---------------------------
    # STATE EXTRACTION (Preserved)
    # ---------------------------
    def extract_state(self, command_instance):
        """
        Extracts state from the command instance.
        """
        cmd = command_instance.command_name.lower()
        args = command_instance.args
        full_cmd = cmd + " " + " ".join(args)
        
        category = 0
        if cmd.startswith("ls") or cmd.startswith("pwd"): category = 0
        elif "cat" in full_cmd or "aws" in full_cmd: category = 1
        elif "sudo" in full_cmd or "chmod" in full_cmd: category = 2
        elif "rm" in full_cmd or "wget" in full_cmd: category = 3
            
        honeytokens = [".aws_backup_keys.txt", "db_admin_passwords.txt", "root_private_key.pem", "backup_credentials.txt"]
        honeytoken_flag = 1 if any(t in full_cmd for t in honeytokens) else 0
                
        if not hasattr(command_instance.protocol, 'cmd_count'):
            command_instance.protocol.cmd_count = 0
        command_instance.protocol.cmd_count += 1
        count = command_instance.protocol.cmd_count
        
        bucket = 0
        if count < 5: bucket = 0
        elif count < 15: bucket = 1
        else: bucket = 2
            
        risk = category
        if honeytoken_flag: risk = 3
            
        return (category, honeytoken_flag, bucket, risk)

    def compute_reward(self, command_instance):
        """
        Compute reward based on session duration and action effectiveness.
        Goal: Maximize session duration.
        """
        try:
            # 1. Base Reward
            reward = 1
            
            # 2. Extract context
            cmd = command_instance.command_name.lower()
            args = command_instance.args
            full_cmd = cmd + " " + " ".join(args)
            
            # Get session info
            if not hasattr(command_instance.protocol, 'cmd_count'):
                command_instance.protocol.cmd_count = 0
            session_length = command_instance.protocol.cmd_count
            
            # Honeytoken check
            honeytokens = [".aws_backup_keys.txt", "db_admin_passwords.txt", "root_private_key.pem", "backup_credentials.txt"]
            honeytoken_flag = any(t in full_cmd for t in honeytokens)

            # Get the action that was taken for this command
            action = getattr(command_instance.protocol, '_rl_action', 0)

            # 3. Long Session Bonus (Once per threshold)
            # User request: +5 if session > threshold once
            THRESHOLD = 10
            
            # Check if bonus already given
            bonus_given = getattr(command_instance.protocol, 'threshold_bonus_given', False)
            
            if session_length > THRESHOLD and not bonus_given:
                reward += 5
                command_instance.protocol.threshold_bonus_given = True
                print(f"[RL] Threshold Bonus (+5) awarded for session > {THRESHOLD}")

            # 4. Honeytoken Bonus
            if honeytoken_flag:
                reward += 3 # User requested +3 instead of +5

            # 5. Penalties
            # Strong penalty for early termination (Action 5)
            if action == 5 and session_length < 10:
                reward -= 15
                
            # Small penalty for fake_error (Action 3) to discourage overuse
            if action == 3:
                reward -= 1
                
            print(f"[RL] Computed Reward: {reward} (Length: {session_length}, Action: {action})")
            return reward

        except Exception as e:
            print(f"[RL ERROR] Reward computation failed: {e}")
            return 0

    # ---------------------------
    # PERSISTENCE
    # ---------------------------
    def save_model(self):
        try:
            with open(self.model_path, "wb") as f:
                pickle.dump(self.q_table, f)
        except Exception as e:
            print(f"[RL] Save failed: {e}")

    def load_model(self):
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    self.q_table = pickle.load(f)
                print("[RL] Model loaded.")
            except:
                print("[RL] Model load failed.")

# Global instance
rl_agent = RLAgent()
