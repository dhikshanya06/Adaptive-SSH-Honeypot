import logging

def get_adaptive_command_logger(name='cowrie.adaptive.commands'):
    return logging.getLogger(name)

def get_command_logger(name='cowrie.adaptive.commands'):
    return logging.getLogger(name)

def log_command(session_id, command, response):
    logger = get_adaptive_command_logger()
    logger.info(f"[CMD] session={session_id} cmd={command}")
