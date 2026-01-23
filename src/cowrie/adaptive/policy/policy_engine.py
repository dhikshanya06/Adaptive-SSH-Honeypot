
class PolicyEngine:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PolicyEngine, cls).__new__(cls)
            cls._instance.policies = {} # session_id -> policy_data
        return cls._instance

    def update_policy(self, session_id, policy_data):
        """
        Updates the policy for a specific session.
        policy_data example: {"intent": "credential_access", "risk": "high", "policy": "aggressive_deception"}
        """
        self.policies[session_id] = policy_data
        # In a real async system, this might trigger a callback or db update
        
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
