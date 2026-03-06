import logging

class AdaptiveLogger:
    def __init__(self):
        self.logger = logging.getLogger('cowrie.adaptive')
    
    def log_adaptation(self, session_id=None, command_name=None, interaction_level=None, reason=None):
        self.logger.info(f"[ADAPTIVE] session={session_id} cmd={command_name} level={interaction_level} reason={reason}")
    
    def info(self, msg):
        self.logger.info(msg)

_adaptive_logger = AdaptiveLogger()

def get_adaptive_logger(name='cowrie.adaptive'):
    return _adaptive_logger

def log_event(event_type, data):
    _adaptive_logger.info(f"[ADAPTIVE] {event_type}: {data}")
