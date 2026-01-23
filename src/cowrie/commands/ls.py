from __future__ import annotations

import getopt
import time

from twisted.internet import reactor, defer

from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_ls(HoneyPotCommand):

    def start(self) -> None:
        self.path = self.protocol.cwd
        self.showHidden = False
        self.longFormat = False

        try:
            opts, args = getopt.gnu_getopt(self.args, "al", [])
        except getopt.GetoptError:
            self.exit()
            return

        for o, _ in opts:
            if o == "-a":
                self.showHidden = True
            elif o == "-l":
                self.longFormat = True

        if args:
            self.path = self.protocol.fs.resolve_path(args[0], self.protocol.cwd)

        # Per-session ls counter
        if not hasattr(self.protocol, "_ls_count"):
            self.protocol._ls_count = 0
        self.protocol._ls_count += 1

        self.ensure_files(self.path)

        # ✅ DELAY LOGIC (VISIBLE)
        delay = 0
        if self.protocol._ls_count >= 3:
            delay = 2.5  # seconds

        d = defer.Deferred()
        reactor.callLater(delay, d.callback, None)
        d.addCallback(self.render_ls)

    # --------------------------------------------------

    def ensure_files(self, path: str) -> None:
        if path != "/root":
            return

        self._ensure_file(
            "README.txt",
            b"Internal backup server\nFor authorized maintenance only\n",
        )

        if self.protocol._ls_count >= 2:
            self._ensure_file("backup.tar.gz", b"\x00" * 512)

        if self.protocol._ls_count >= 3:
            self._ensure_file(
                "notes.txt",
                b"Backup schedule: Sunday 02:00 UTC\n",
            )

        if self.showHidden:
            self._ensure_file(
                ".db_creds",
                b"DB_USER=admin\nDB_PASS=changeme123\n",
            )

    # --------------------------------------------------

    def _ensure_file(self, name: str, content: bytes) -> None:
        fullpath = self.protocol.fs.resolve_path(name, self.protocol.cwd)
        if self.protocol.fs.exists(fullpath):
            return

        self.protocol.fs.mkfile(
            fullpath,
            self.protocol.user.uid,
            self.protocol.user.gid,
            len(content),
            33188,
        )

        f = self.protocol.fs.getfile(fullpath)
        f[fs.A_CONTENTS] = content
        f[fs.A_SIZE] = len(content)

    # --------------------------------------------------

    def render_ls(self, _ignored) -> None:
        files = self.protocol.fs.get_path(self.path)[:]

        if not self.showHidden:
            files = [f for f in files if not f[fs.A_NAME].startswith(".")]

        files.sort(key=lambda x: x[fs.A_NAME])

        if self.longFormat:
            for f in files:
                ctime = time.strftime(
                    "%Y-%m-%d %H:%M",
                    time.localtime(f[fs.A_CTIME]),
                )
                self.write(
                    f"-rw-r--r-- 1 root root {f[fs.A_SIZE]} {ctime} {f[fs.A_NAME]}\n"
                )
        else:
            for f in files:
                self.write(f"{f[fs.A_NAME]}  ")
            self.write("\n")

        self.exit()


commands["ls"] = Command_ls
commands["/bin/ls"] = Command_ls
commands["dir"] = Command_ls
commands["/bin/dir"] = Command_ls

