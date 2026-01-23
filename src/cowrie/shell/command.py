# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains code to run a command
"""

from __future__ import annotations

import shlex
from typing import Any, TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable

from twisted.internet import error
from twisted.python import failure, log
from cowrie.core.config import CowrieConfig

# Import adaptive components (with error handling for optional dependency)
try:
    from cowrie.adaptive.adaptive_logger import get_adaptive_logger
    from cowrie.adaptive.adaptive_command_logger import get_adaptive_command_logger
    from cowrie.adaptive.adaptive_rules import AdaptiveRulesEngine
    from cowrie.adaptive.command_categorizer import CommandCategorizer
    _ADAPTIVE_AVAILABLE = True
except ImportError as e:
    _ADAPTIVE_AVAILABLE = False
    log.msg(f"[ADAPTIVE] Adaptive components not available: {e}")
    def get_adaptive_logger():
        return None
    def get_adaptive_command_logger():
        return None


class HoneyPotCommand:
    """
    This is the super class for all commands in cowrie/commands
    """

    def __init__(self, protocol, *args):
        self.protocol = protocol
        self.args = list(args)
        self.environ = self.protocol.cmdstack[-1].environ
        self.fs = self.protocol.fs
        self.data: bytes = b""  # output data
        self.input_data: None | (
            bytes
        ) = None  # used to store STDIN data passed via PIPE
        pp: Any = getattr(self.protocol, "pp", None)
        self.writefn: Callable[[bytes], None]
        self.errorWritefn: Callable[[bytes], None]
        if pp and hasattr(pp, "write_stdout") and hasattr(pp, "write_stderr"):
            self.writefn = cast("Callable[[bytes], None]", pp.write_stdout)
            self.errorWritefn = cast("Callable[[bytes], None]", pp.write_stderr)
        else:
            self.writefn = cast("Callable[[bytes], None]", self.protocol.pp.outReceived)
            self.errorWritefn = cast(
                "Callable[[bytes], None]", self.protocol.pp.errReceived
            )
        
        # Initialize adaptive components
        self.adaptive_behavior = None
        self.adaptive_output_modifier = None
        self.command_name = self.__class__.__name__.replace('Command_', '').lower()
        
        self.interaction_level = self.get_interaction_level()
        
        # Log adaptation event for this command (after level is determined)
        if _ADAPTIVE_AVAILABLE:
            logger = get_adaptive_logger()
            if logger:
                session_id = getattr(self.protocol, 'session_id', None) or getattr(self.protocol, 'sessionno', 'unknown')
                logger.log_adaptation(
                    session_id=session_id,
                    command_name=self.command_name,
                    interaction_level=self.interaction_level,
                    reason=f"Command executed with interaction level {self.interaction_level}"
                )

    def get_interaction_level(self) -> int:
        """
        Reads the current session's interaction level from the shared policy file.
        Uses CowrieConfig to determine the correct state_path, resolving it relative
        to the project root (where etc/cowrie.cfg is located).
        """
        import json
        import os
        from os.path import abspath, dirname, join
        
        # Get state_path from config (typically "var/lib/cowrie")
        state_path = CowrieConfig.get("honeypot", "state_path", fallback="var/lib/cowrie")
        
        # Resolve project root: go up from src/cowrie/shell/command.py (3 levels up)
        # This matches the logic used in config.py: root is 3 levels up from src/cowrie/core/config.py
        current_file = abspath(__file__)  # src/cowrie/shell/command.py
        project_root = abspath(join(current_file, '..', '..', '..'))  # Go up to project root
        
        # Construct absolute path to policy file
        if os.path.isabs(state_path):
            policy_file = join(state_path, "session_policies.json")
        else:
            policy_file = join(project_root, state_path, "session_policies.json")
            
        if os.path.exists(policy_file):
            try:
                with open(policy_file, 'r') as f:
                    policies = json.load(f)
                    # Get session_id from protocol, fallback to sessionno if not available
                    session_id = getattr(self.protocol, 'session_id', None)
                    if session_id is None:
                        session_id = getattr(self.protocol, 'sessionno', 'unknown')
                    level = policies.get(str(session_id), {}).get('level', 1)
                    
                    # Log policy read event
                    if _ADAPTIVE_LOGGING_AVAILABLE:
                        logger = get_adaptive_logger()
                        if logger:
                            logger.log_policy_read(session_id, level, policy_file)
                    
                    log.msg(f"[ADAPTIVE] Session {session_id}: Using interaction level {level} from policy file")
                    return level
            except (json.JSONDecodeError, IOError, OSError) as e:
                log.msg(f"[ADAPTIVE] Error reading policy file {policy_file}: {e}")
        else:
            # Policy file doesn't exist yet (first command in session) - use default level 1
            log.msg(f"[ADAPTIVE] Policy file not found at {policy_file}, using default level 1")
        
        return 1

    def write(self, data: str) -> None:
        """
        Write a string to the user on stdout, filtered by interaction level and adaptive rules.
        """
        # Apply adaptive output modification if needed
        if self.adaptive_output_modifier and isinstance(data, str):
            data = self.adaptive_output_modifier(data)
        
        # if self.interaction_level == 0:
        #    # Stealth: Don't write anything or very limited
        #    return
        self.writefn(data.encode("utf8"))

    def writeBytes(self, data: bytes) -> None:
        """
        Like write() but input is bytes, filtered by interaction level and adaptive rules.
        """
        # Apply adaptive output modification if needed
        if self.adaptive_output_modifier:
            try:
                data_str = data.decode('utf-8')
                modified_str = self.adaptive_output_modifier(data_str)
                data = modified_str.encode('utf-8')
            except UnicodeDecodeError:
                pass  # If can't decode, skip modification
        
        # if self.interaction_level == 0:
        #    return
        self.writefn(data)

    def errorWrite(self, data: str) -> None:
        """
        Write errors to the user on stderr
        """
        self.errorWritefn(data.encode("utf8"))

    def check_arguments(self, application, args):
        files = []
        for arg in args:
            path = self.fs.resolve_path(arg, self.protocol.cwd)
            if self.fs.isdir(path):
                self.errorWrite(
                    f"{application}: error reading `{arg}': Is a directory\n"
                )
                continue
            files.append(path)
        return files

    def set_input_data(self, data: bytes) -> None:
        self.input_data = data

    def start(self) -> None:
        """
        Start command execution with adaptive behavior applied (Non-blocking).
        """
        # Initialize blocked flag
        self._blocked_by_adaptive = False
        
        # Calculate delay and determine output modifiers
        delay = self._apply_adaptive_behavior()
        
        # Check if command was blocked immediately
        if self._blocked_by_adaptive:
            self.exit()
            return
            
        if delay > 0:
            # Schedule execution
            from twisted.internet import reactor
            reactor.callLater(delay, self.execute)
        else:
            # Execute immediately
            self.execute()

    def execute(self) -> None:
        """
        Actual execution logic, called possibly after a delay.
        """
        # Execute the command
        self.call()
        self.exit()
    
    def _apply_adaptive_behavior(self) -> float:
        """
        Apply adaptive behavior rules. Returns the calculated delay (float).
        """
        delay = 0.0
        
        if not _ADAPTIVE_AVAILABLE:
            log.msg(f"[ADAPTIVE] Adaptive components not available for command {self.command_name}")
            return 0.0
        
        try:
            session_id = getattr(self.protocol, 'session_id', None)
            if session_id is None:
                session_id = getattr(self.protocol, 'sessionno', None)
            if session_id is None:
                session_id = 'unknown'
            
            log.msg(f"[ADAPTIVE] Processing command '{self.command_name}' for session {session_id}")
            
            # Get adaptive behavior
            rules_engine = AdaptiveRulesEngine()
            self.adaptive_behavior = rules_engine.get_adaptive_behavior(
                session_id=str(session_id),
                command=self.command_name,
                args=self.args
            )
            
            log.msg(f"[ADAPTIVE] Command '{self.command_name}' categorized as '{self.adaptive_behavior['category']}', count={self.adaptive_behavior['count']}, policy={self.adaptive_behavior['policy']}")
            
            # Log the adaptive behavior
            cmd_logger = get_adaptive_command_logger()
            if cmd_logger:
                cmd_logger.log_command(
                    session_id=str(session_id),
                    command=self.command_name,
                    category=self.adaptive_behavior['category'],
                    count=self.adaptive_behavior['count'],
                    policy=self.adaptive_behavior['policy'],
                    delay=self.adaptive_behavior.get('delay', 0),
                    blocked=self.adaptive_behavior.get('block', False),
                    args=self.args
                )
            
            # Retrieve delay
            delay = self.adaptive_behavior.get('delay', 0.0)
            if delay > 0:
                log.msg(f"[ADAPTIVE] Scheduling delay of {delay:.2f} seconds for command '{self.command_name}'")
            
            # Check if command should be blocked
            if self.adaptive_behavior.get('block', False):
                error_msg = self.adaptive_behavior.get('error_message', 'Permission denied')
                log.msg(f"[ADAPTIVE] Blocking command '{self.command_name}': {error_msg}")
                self.errorWrite(f"{self.command_name}: {error_msg}\n")
                self._blocked_by_adaptive = True
                return 0.0
            
            # Store output modifier if needed
            self.adaptive_output_modifier = self.adaptive_behavior.get('modify_output')
            if self.adaptive_output_modifier:
                log.msg(f"[ADAPTIVE] Output modifier set for command '{self.command_name}'")
            
            # Handle privilege escalation specific errors
            if self.adaptive_behavior.get('category') == 'privilege_escalation':
                error_msg = self.adaptive_behavior.get('error_message')
                if error_msg:
                    log.msg(f"[ADAPTIVE] Privilege escalation error for '{self.command_name}': {error_msg}")
                    self.errorWrite(f"{error_msg}\n")
                    self._blocked_by_adaptive = True
                    return 0.0
                    
        except Exception as e:
            import traceback
            log.msg(f"[ADAPTIVE] ERROR applying adaptive behavior for '{self.command_name}': {e}")
            log.msg(f"[ADAPTIVE] Traceback: {traceback.format_exc()}")
            # Initialize defaults to prevent errors
            self.adaptive_behavior = {'category': 'unknown_suspicious', 'count': 0, 'policy': 'NORMAL', 'delay': 0, 'block': False}
            self.adaptive_output_modifier = None
            
        return delay

    def call(self) -> None:
        self.write(f"Hello World! [{self.args!r}]\n")

    def exit(self) -> None:
        """
        Sometimes client is disconnected and command exits after. So cmdstack is gone
        """
        if (
            self.protocol
            and self.protocol.terminal
            and hasattr(self.protocol, "pp")
            and getattr(self.protocol.pp, "redirect_real_files", None)
        ):
            for real_path, virtual_path in self.protocol.pp.redirect_real_files:
                self.protocol.terminal.redirFiles.add((real_path, virtual_path))

        if len(self.protocol.cmdstack):
            try:
                self.protocol.cmdstack.remove(self)
            except ValueError:
                # Command might have been removed already
                pass

            if len(self.protocol.cmdstack):
                self.protocol.cmdstack[-1].resume()
        else:
            ret = failure.Failure(error.ProcessDone(status=""))
            # The session could be disconnected already, when his happens .transport is gone
            try:
                self.protocol.terminal.transport.processEnded(ret)
            except AttributeError:
                pass

    def handle_CTRL_C(self) -> None:
        log.msg("Received CTRL-C, exiting..")
        self.write("^C\n")
        self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(f"QUEUED INPUT: {line}")
        # FIXME: naive command parsing, see lineReceived below
        # line = "".join(line)
        self.protocol.cmdstack[0].cmdpending.append(shlex.split(line, posix=True))

    def resume(self) -> None:
        pass

    def handle_TAB(self) -> None:
        pass

    def handle_CTRL_D(self) -> None:
        pass

    def __repr__(self) -> str:
        return str(self.__class__.__name__)
