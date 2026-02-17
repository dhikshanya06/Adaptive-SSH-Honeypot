from __future__ import annotations
import getopt

from cowrie.shell.command import HoneyPotCommand
from twisted.python import log

# Adaptive session tracker
from cowrie.adaptive.session_tracker import SessionTracker

commands = {}


class Command_sudo(HoneyPotCommand):

    def start(self) -> None:
        # --- RL INTEGRATION ---
        from cowrie.adaptive.rl_agent import rl_agent
        session_id = self.protocol.sessionno
        action = rl_agent.current_action.get(session_id, 0)

        if action == 2:
            self.errorWrite("sudo: unable to resolve host server\n")
            self.exit()
            return

        # 3: fake_error (Wrong Password)
        elif action == 3:
             self.write("[sudo] password for root: ") # Note: user spec shows prompt then error
             # User spec:
             # [sudo] password for root:
             # Sorry, try again.
             # This implies an interaction or just printing both.
             # To be simple and robust:
             self.write("Sorry, try again.\n")
             self.exit()
             return

        # 4: escalate_deception (Fake Root)
        elif action == 4:
             self.write("root@server:~# \n")
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
        # [sudo] password for root:
        
        self.write("[sudo] password for root: \n")
        # In a real sudo, it waits for input. 
        # But here we just print the prompt and exit? 
        # Or do we wait?
        # The user spec just shows the output. 
        # If I exit immediately, the user's shell will prompt again.
        # "root@svr01:~# sudo su" -> "[sudo] password for root: " -> exit -> "root@svr01:~# "
        # This looks like a failed sudo or just a prompt.
        # However, to be "exact", I will output this string.
        # If I want to simulate waiting, I need callbacks.
        # For this task "the output should display... exactly like you did for ls.py",
        # I will assume static string output is the goal.
        
        self.exit()
        return

        # ---------- ADAPTIVE STATE TRACKING ----------
        try:
            session_id = getattr(self.protocol, "sessionid", "unknown")
            tracker = SessionTracker.get_instance()
            state = tracker.record_command(
                session_id=session_id,
                command="sudo",
                category="privilege_escalation"
            )
            sudo_count = state["command_counts"]["sudo"]
        except Exception:
            sudo_count = 1
        # --------------------------------------------

        # Log privilege escalation attempt
        log.msg(
            eventid="cowrie.command.privilege",
            format="Privilege escalation attempt via sudo (count=%(count)s)",
            count=sudo_count,
        )

        # ---------- ADAPTIVE OUTPUT ----------
        if sudo_count < 3:
            # Early attempts: generic denial
            self.errorWrite("sudo: a password is required\n")
            self.exit()
            return
        else:
            # Escalated response
            self.errorWrite(
                "sudo: user is not in the sudoers file. This incident will be reported.\n"
            )
            self.exit()
            return
        # -----------------------------------


commands["sudo"] = Command_sudo

