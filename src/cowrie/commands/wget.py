from __future__ import annotations

import getopt
import time
from urllib import parse

from twisted.internet import reactor
from cowrie.shell.command import HoneyPotCommand

# SAFE adaptive state (in-memory)
from cowrie.adaptive.session_tracker import SessionTracker

commands = {}


class Command_wget(HoneyPotCommand):
    """
    Adaptive fake wget (stable + visible)
    """

    def start(self) -> None:
        # --- RL INTEGRATION ---
        from cowrie.adaptive.rl_agent import rl_agent
        from twisted.python import log
        
        try:
            session_id = self.protocol.sessionno
            action = rl_agent.current_action.get(session_id, 0)
    
            # 2: inject_fake_file (Success Simulation)
            if action == 2:
                self.errorWrite("Saved to: backdoor.sh\nExecutable permission granted.\n")
                self.exit()
                return
    
            # 3: fake_error (DNS Error)
            elif action == 3:
                 self.errorWrite("wget: unable to resolve host address\n")
                 self.exit()
                 return
    
            # 4: escalate_deception (Malicious Payload)
            elif action == 4:
                 self.errorWrite("Downloaded internal_backup.sh\nSystem update required.\n")
                 self.exit()
                 return
    
            # 5: terminate_session
            elif action == 5:
                self.protocol.transport.loseConnection()
                return
                
            # 1: add_delay
            elif action == 1:
                # time is imported globally at line 4
                time.sleep(2.0)
                # Fall through to Normal Response
    
            # -------- NORMAL BEHAVIOR (Action 0) --------
            
            # Arg parsing mostly to get URL for display if needed, but spec implies static-ish output
            # "Connecting to malicious.com..." implies dynamic host extraction
            try:
                _, args = getopt.getopt(self.args, "hqO:")
            except getopt.GetoptError:
                self.errorWrite("wget: invalid option\n")
                self.exit()
                return
    
            if not args:
                self.errorWrite("wget: missing URL\n")
                self.exit()
                return
    
            url = args[0]
            if "://" not in url:
                url = f"http://{url}"
    
            parsed = parse.urlparse(url)
            host = parsed.hostname or "unknown"
            filename = "shell.sh" # Spec says shell.sh, but maybe derive from url? 
            # User spec: "Saving to: shell.sh". 
            # If user types wget http://malicious.com/shell.sh -> shell.sh
            # If user types wget http://example.com/foo -> foo?
            # User said "see read the command properly... output should display for the attacker... exactly like you did for ls.py"
            # In ls.py I used static output for Action 0 too? No, ls.py Action 0 is normal.
            # But the user spec shows:
            # Command: wget http://malicious.com/shell.sh
            # Output: ... Saving to: shell.sh
            # I should try to derive filename from URL to be "reading command properly", 
            # matching the style of the user spec.
            path = parsed.path
            if path and path != "/":
                filename = path.split("/")[-1]
            if not filename:
                filename = "index.html"

            # Strict Spec for Normal/Delay:
            # --2026-- Connecting to malicious.com...
            # HTTP request sent, awaiting response... 200 OK
            # Saving to: shell.sh
            
            self.errorWrite(f"--2026-- Connecting to {host}...\n")
            self.errorWrite("HTTP request sent, awaiting response... 200 OK\n")
            self.errorWrite(f"Saving to: {filename}\n")
            
            # Using callLater for exit to allow buffer flush
            reactor.callLater(0.1, self.exit)

        except Exception as e:
            log.msg(f"[WGET ERROR] {e}")
            self.errorWrite(f"wget: internal error\n")
            self.exit()




commands["wget"] = Command_wget
commands["/usr/bin/wget"] = Command_wget
commands["dget"] = Command_wget
commands["/usr/bin/dget"] = Command_wget

