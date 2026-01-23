
# DUMMY SESSION TRACKER
# Restored to satisfy imports in legacy command files
# The real logic is handled by live_adaptive_controller.py

class SessionTracker:
    _instance = None
    
    def __init__(self):
        self.state = {
            "command_counts": {}
        }

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = SessionTracker()
        return cls._instance

    def record_command(self, session_id, command, category):
        # Return a dummy state to keep command files happy
        # counts default to 1 so usage checks (e.g. if count < 3) don't crash
        return {
            "command_counts": {
                command: 1
            }
        }
