def increase_suspicion(session_id, amount=1):
    pass

def get_suspicion(session_id):
    return 0

class SessionTracker:
    def __init__(self):
        self.sessions = {}
    def track(self, session_id):
        if session_id not in self.sessions:
            self.sessions[session_id] = {"suspicion": 0, "commands": []}
    def add_command(self, session_id, command):
        self.track(session_id)
        self.sessions[session_id]["commands"].append(command)
session_tracker = SessionTracker()