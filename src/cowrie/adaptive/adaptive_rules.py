
import time
from cowrie.adaptive.command_categorizer import CommandCategorizer

class AdaptiveRulesEngine:
    _instance = None
    _session_state = {} # session_id -> {command_counts: {}, total_commands: 0}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AdaptiveRulesEngine, cls).__new__(cls)
            cls._instance.categorizer = CommandCategorizer()
        return cls._instance

    def get_adaptive_behavior(self, session_id, command, args=None):
        """
        Determines the adaptive behavior (delay, block, modify) for a command.
        """
        # Initialize session state if needed
        if session_id not in self._session_state:
            self._session_state[session_id] = {
                "command_counts": {},
                "total_commands": 0
            }
            
        state = self._session_state[session_id]
        
        # Update counts
        if command not in state["command_counts"]:
            state["command_counts"][command] = 0
        state["command_counts"][command] += 1
        state["total_commands"] += 1
        
        count = state["command_counts"][command]
        category = self.categorizer.categorize_command(command)
        
        # Logic for Delay
        delay = 0.0
        policy = "NORMAL"
        block = False
        error_msg = None
        
        # 1. Category-based Base Delay
        if category in ["privilege_escalation", "download", "scanning"]:
            delay += 2.0
            policy = "AGGRESSIVE"
            
        # 2. Key Command Repetition Delay
        if count > 2 and category != "general":
            delay += 1.0 * (count - 2) # Incremental delay for spamming bad commands
            
        # 3. Global Fatigue Delay (Simulate system load or annoy attacker)
        if state["total_commands"] > 15:
            delay += 0.5
            
        # 4. Cap Delay to avoid timeout/disconnect issues
        if delay > 10.0:
            delay = 10.0
            
        return {
            "category": category,
            "count": count,
            "policy": policy,
            "delay": delay,
            "block": block,
            "error_message": error_msg
        }

