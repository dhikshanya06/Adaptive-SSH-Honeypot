
from __future__ import annotations
import getpass
from cowrie.shell.command import HoneyPotCommand
from twisted.python import log

commands = {}

class Command_su(HoneyPotCommand):
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
