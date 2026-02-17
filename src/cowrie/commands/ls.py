from __future__ import annotations

import getopt
import time

from cowrie.shell.command import HoneyPotCommand
from cowrie.adaptive.rl_agent import rl_agent

commands = {}


class Command_ls(HoneyPotCommand):

    def start(self) -> None:

        session_id = self.protocol.sessionno
        action = rl_agent.current_action.get(session_id, 0)

        # =========================
        # RL ACTION OVERRIDES
        # =========================

        if action == 1:  # add_delay
            time.sleep(2)

        elif action == 2:  # inject_fake_file
            self.write("passwords.txt  backup.tar.gz  secrets.db\n")
            self.exit()
            return

        elif action == 3:  # fake_error
            self.write("ls: cannot access: Permission denied\n")
            self.exit()
            return

        elif action == 4:  # escalate_deception
            self.write("passwords.txt  admin_backup.zip  logs  database_dump.sql\n")
            self.exit()
            return

        elif action == 5:  # terminate_session
            self.protocol.transport.loseConnection()
            return

        # =========================
        # NORMAL BEHAVIOR
        # =========================

        show_hidden = False
        long_format = False

        try:
            opts, args = getopt.gnu_getopt(self.args, "al", [])
        except getopt.GetoptError:
            self.exit()
            return

        for o, _ in opts:
            if o == "-a":
                show_hidden = True
            elif o == "-l":
                long_format = True

        # Base file list
        files = ["passwords.txt"]

        # Hidden files
        hidden_files = [
            ".aptitude",
            ".aws_backup_keys.txt",
            ".bashrc",
            ".profile",
            ".ssh"
        ]

        if show_hidden:
            files = hidden_files + files

        # If long format
        if long_format:
            for f in files:
                self.write(
                    f"-rw-r--r-- 1 root root 4096 Jan 01 12:00 {f}\n"
                )
        else:
            for f in files:
                self.write(f + "  ")
            self.write("\n")

        self.exit()


commands["ls"] = Command_ls
commands["/bin/ls"] = Command_ls
commands["dir"] = Command_ls
commands["/bin/dir"] = Command_ls

