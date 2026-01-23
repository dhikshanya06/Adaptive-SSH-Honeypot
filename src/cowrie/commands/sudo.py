from __future__ import annotations
import getopt

from cowrie.shell.command import HoneyPotCommand
from twisted.python import log

# Adaptive session tracker
from cowrie.adaptive.session_tracker import SessionTracker

commands = {}


class Command_sudo(HoneyPotCommand):

    def start(self) -> None:
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

