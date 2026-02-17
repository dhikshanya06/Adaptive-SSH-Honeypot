
from __future__ import annotations
import getpass
from cowrie.shell.command import HoneyPotCommand
from twisted.python import log

commands = {}

class Command_su(HoneyPotCommand):

    def start(self) -> None:
        # --- RL INTEGRATION ---
        from cowrie.adaptive.rl_agent import rl_agent
        session_id = self.protocol.sessionno
        action = rl_agent.current_action.get(session_id, 0)

        if action == 2:
            self.write("Authentication failure\n")
            self.exit()
            return

        # 3: fake_error (Authentication Failure)
        elif action == 3:
             self.errorWrite("su: Authentication failure\n")
             self.exit()
             return

        # 4: escalate_deception (Fake Root)
        elif action == 4:
             self.write("root@server:/# \n")
             self.exit()
             return

        # 5: terminate_session
        elif action == 5:
            self.protocol.transport.loseConnection()
            return
            
        # 1: add_delay
        elif action == 1:
            import time
            time.sleep(2.0)
            # Fall through

        # -------- NORMAL BEHAVIOR (Action 0) --------
        # User spec:
        # Password:
        
        self.write("Password: \n")
        # Simulating a password prompt
        self.exit()
        return

        super().start()

    def call(self) -> None:
        # High Signal Logging
        log.msg(eventid="cowrie.command.privilege", 
               format="Privilege escalation attempt identified: su")
        
        # Adaptive behavior based on interaction level
        if self.interaction_level >= 3:
            # Level 3: Highly malicious - show password prompt briefly, then fail with detailed error
            self.write("Password: ")
            self.write("\nsu: Authentication failure\n")
            self.write("su: 1 incorrect password attempt\n")
        elif self.interaction_level >= 2:
            # Level 2: Suspicious - standard authentication failure
            self.write("Password: ")
            self.write("\nsu: Authentication failure\n")
        else:
            # Level 0-1: Low interaction - immediate failure without prompt
            self.errorWrite("su: must be run from a terminal\n")

commands["/bin/su"] = Command_su
commands["su"] = Command_su
