import os

class PolicyEngine:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PolicyEngine, cls).__new__(cls)
            cls._instance.policies = {} # session_id -> policy_data
            cls._instance.policy_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../../../var/lib/cowrie/session_policies.json")
            cls._instance._load_policies()
        return cls._instance

    def _load_policies(self):
        import json
        import os
        if os.path.exists(self.policy_file):
            try:
                with open(self.policy_file, 'r') as f:
                    self.policies = json.load(f)
            except Exception as e:
                print(f"Error loading policies: {e}")

    def save_policies(self):
        import json
        import os
        try:
            os.makedirs(os.path.dirname(self.policy_file), exist_ok=True)
            with open(self.policy_file, 'w') as f:
                json.dump(self.policies, f, indent=2)
        except Exception as e:
            print(f"Error saving policies: {e}")

    def update_policy(self, session_id, policy_data):
        """
        Updates the policy for a specific session.
        policy_data example: {"intent": "credential_access", "risk": "high", "policy": "aggressive_deception"}
        """
        # Map risk to numeric level for comparison
        risk_map = {"low": 1, "medium": 2, "high": 3, "critical": 4, "very high": 4}
        new_risk = policy_data.get("risk", "low").lower()
        new_level = risk_map.get(new_risk, 1)

        # Get existing policy
        existing_policy = self.get_policy(session_id)
        current_risk = existing_policy.get("risk", "low").lower()
        current_level = risk_map.get(current_risk, 1)

        # HIGH WATERMARK LOGIC: Only upgrade, never downgrade if already High/Critical
        if current_level >= 3 and new_level < current_level:
            # Keep the higher risk level
            policy_data["risk"] = current_risk
            policy_data["policy"] = existing_policy.get("policy", "aggressive_deception")
            policy_data["level"] = current_level
            # print(f"   [POLICY] Maintaining HIGH/CRITICAL risk (Level {current_level}) for session {session_id}")
        else:
            policy_data["level"] = new_level
            
        self.policies[session_id] = policy_data
        self.save_policies()
        
    def get_policy(self, session_id):
        """
        Retrieves the current policy for a session.
        Returns default if not found.
        """
        return self.policies.get(session_id, {
                "intent": "unknown",
                "risk": "low",
                "policy": "passive_monitoring"
            })

    def should_block_command(self, session_id, command):
        """
        Example of policy enforcement logic.
        """
        policy = self.get_policy(session_id)
        if policy['policy'] == 'aggressive_deception':
            if command.strip() in ['wget', 'curl', 'scp']:
                return True # Block downloads in aggressive mode
        return False
        
