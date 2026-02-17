from __future__ import annotations

import re
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell import fs

commands = {}

MODE_REGEX = "^[0-7]{3,4}$"


class Command_chmod(HoneyPotCommand):

    def start(self) -> None:
        # --- RL INTEGRATION ---
        from cowrie.adaptive.rl_agent import rl_agent
        session_id = self.protocol.sessionno
        action = rl_agent.current_action.get(session_id, 0)

        if action == 2:
            self.write("Permission updated successfully.\n")
            self.exit()
            return

        # 3: fake_error (Operation not permitted)
        elif action == 3:
             filename = self.args[1] if len(self.args) > 1 else (self.args[0] if self.args else "file")
             self.errorWrite(f"chmod: changing permissions of {filename}: Operation not permitted\n")
             self.exit()
             return

        # 4: escalate_deception (Warning)
        elif action == 4:
             self.errorWrite("Warning: system binary modified.\n")
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
        # (no output)
        
        # We just exit silently.
        self.exit()
        return

        super().start()

    def call(self) -> None:
        if len(self.args) < 2:
            self.errorWrite("chmod: missing operand\n")
            return

        mode = self.args[0]
        files = self.args[1:]

        if not re.fullmatch(MODE_REGEX, mode):
            self.errorWrite(f"chmod: invalid mode: {mode}\n")
            return

        for name in files:
            path = self.fs.resolve_path(name, self.protocol.cwd)
            if not self.fs.exists(path):
                self.errorWrite(
                    f"chmod: cannot access '{name}': No such file\n"
                )
                continue

            f = self.fs.getfile(path)
            f[fs.A_MODE] = int(mode, 8)


commands["chmod"] = Command_chmod
commands["/bin/chmod"] = Command_chmod

