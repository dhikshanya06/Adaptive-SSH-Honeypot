from __future__ import annotations

import re
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell import fs

commands = {}

MODE_REGEX = "^[0-7]{3,4}$"


class Command_chmod(HoneyPotCommand):

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

