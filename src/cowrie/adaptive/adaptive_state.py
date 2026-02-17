class AdaptiveState:
    def __init__(self):
        self.session_flags = {}

    def set_action(self, session_id, action):
        self.session_flags[session_id] = action

    def get_action(self, session_id):
        return self.session_flags.get(session_id, 0)

adaptive_state = AdaptiveState()
