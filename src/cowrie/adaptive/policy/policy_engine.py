class PolicyEngine:
    def __init__(self):
        pass
    def get_policy(self, session_id):
        return {"level": 1, "action": "standard"}
    def update_policy(self, session_id, action):
        pass