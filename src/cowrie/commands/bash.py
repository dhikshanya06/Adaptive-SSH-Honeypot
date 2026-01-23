from __future__ import annotations

from typing import TYPE_CHECKING

from twisted.internet import error
from twisted.python import failure

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.honeypot import HoneyPotShell

# Adaptive session tracking
from cowrie.adaptive.session_tracker import SessionTracker

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


class Command_sh(HoneyPotCommand):
    def start(self) -> None:
        # ================= ADAPTIVE STATE =================
        try:
            session_id = getattr(self.protocol, "sessionid", "unknown")
            tracker = SessionTracker.get_instance()
            state = tracker.record_command(
                session_id=session_id,
                command="shell",
                category="persistence"
            )
            shell_count = state["command_counts"]["shell"]
        except Exception:
            shell_count = 1
        # ==================================================

        # BLOCK excessive shell spawning
        if shell_count >= 4:
            self.errorWrite("bash: fork: Resource temporarily unavailable\n")
            self.exit()
            return

        # WARNING on suspicious behavior
        if shell_count == 3:
            self.write("bash: warning: excessive shell nesting detected\n")

        # -------- NORMAL SHELL BEHAVIOR --------
        if self.args and self.args[0].strip() == "-c":
            line = " ".join(self.args[1:])

            if (line.startswith("'") and line.endswith("'")) or (
                line.startswith('"') and line.endswith('"')
            ):
                line = line[1:-1]

            self.execute_commands(line)
            self.exit()

        elif self.input_data:
            self.execute_commands(self.input_data.decode("utf8"))
            self.exit()

        else:
            self.interactive_shell()

    def execute_commands(self, cmds: str) -> None:
        # Create a non-interactive subshell
        self.protocol.cmdstack.append(
            HoneyPotShell(self.protocol, interactive=False)
        )

        self.protocol.cmdstack[-1].lineReceived(cmds)
        self.protocol.cmdstack.pop()

    def interactive_shell(self) -> None:
        shell = HoneyPotShell(self.protocol, interactive=True)
        parentshell = self.protocol.cmdstack[-2]

        try:
            shell.environ["SHLVL"] = str(int(parentshell.environ.get("SHLVL", "0")) + 1)
        except Exception:
            shell.environ["SHLVL"] = "1"

        self.protocol.cmdstack.append(shell)
        self.protocol.cmdstack.remove(self)


commands["/bin/bash"] = Command_sh
commands["bash"] = Command_sh
commands["/bin/sh"] = Command_sh
commands["sh"] = Command_sh


class Command_exit(HoneyPotCommand):
    def call(self) -> None:
        # Remove current shell
        self.protocol.cmdstack.pop(-2)

        if len(self.protocol.cmdstack) < 2:
            stat = failure.Failure(error.ProcessDone(status=""))
            self.protocol.terminal.transport.processEnded(stat)


commands["exit"] = Command_exit
commands["logout"] = Command_exit

