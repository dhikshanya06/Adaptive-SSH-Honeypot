from __future__ import annotations

import random
import re
from typing import Any, TYPE_CHECKING

from twisted.internet import defer, reactor
from twisted.internet.defer import inlineCallbacks

from cowrie.shell.command import HoneyPotCommand

# Adaptive session tracking (SAFE)
from cowrie.adaptive.session_tracker import SessionTracker

if TYPE_CHECKING:
    from collections.abc import Callable

commands = {}


class Command_faked_package_class_factory:
    @staticmethod
    def getCommand(name: str) -> Callable:
        class Command_faked_installation(HoneyPotCommand):
            def call(self) -> None:
                self.write(f"{name}: Segmentation fault\n")
                self.exit()

        return Command_faked_installation


class Command_aptget(HoneyPotCommand):
    """
    Fake apt / apt-get with adaptive behavior
    """

    packages: dict[str, dict[str, Any]]

    def start(self) -> None:
        if len(self.args) == 0:
            self.do_help()
        elif self.args[0] == "-v":
            self.do_version()
        elif self.args[0] == "install":
            self.do_install()
        elif self.args[0] == "moo":
            self.do_moo()
        else:
            self.do_locked()

    def sleep(self, t1: float, t2: float | None = None) -> defer.Deferred:
        d: defer.Deferred = defer.Deferred()
        if t2:
            t1 = random.uniform(t1, t2)
        reactor.callLater(t1, d.callback, None)
        return d

    def do_version(self) -> None:
        self.write(
            "apt 1.0.9.8.1 for amd64 compiled on Jun 10 2015 09:42:06\n"
        )
        self.exit()

    def do_help(self) -> None:
        self.write(
            "Usage: apt-get [options] command\n"
            "       apt-get [options] install pkg1 [pkg2 ...]\n"
            "Commands: update, upgrade, install, remove, moo\n"
            "This APT has Super Cow Powers.\n"
        )
        self.exit()

    @inlineCallbacks
    def do_install(self) -> None:
        # ================= ADAPTIVE STATE =================
        try:
            session_id = getattr(self.protocol, "sessionid", "unknown")
            tracker = SessionTracker.get_instance()
            state = tracker.record_command(
                session_id=session_id,
                command="apt-get",
                category="persistence"
            )
            install_count = state["command_counts"]["apt-get"]
        except Exception:
            install_count = 1
        # ==================================================

        # HARD BLOCK AFTER REPEATED ATTEMPTS
        if install_count >= 4:
            self.errorWrite(
                "E: Could not get lock /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
            )
            self.errorWrite(
                "E: Unable to acquire the dpkg frontend lock\n"
            )
            self.exit()
            return

        if len(self.args) <= 1:
            self.write(
                f"0 upgraded, 0 newly installed, 0 to remove and {random.randint(200,300)} not upgraded.\n"
            )
            self.exit()
            return

        self.packages = {}
        for pkg in self.args[1:]:
            clean = re.sub("[^A-Za-z0-9]", "", pkg)
            self.packages[clean] = {
                "version": f"{random.choice([0,1])}.{random.randint(1,40)}-{random.randint(1,10)}",
                "size": random.randint(100, 900),
            }

        totalsize = sum(self.packages[p]["size"] for p in self.packages)

        self.write("Reading package lists... Done\n")
        self.write("Building dependency tree\n")
        self.write("Reading state information... Done\n")

        if install_count == 3:
            self.write(
                "WARNING: apt-key is deprecated. Manage keyring files in trusted.gpg.d instead.\n"
            )

        self.write("The following NEW packages will be installed:\n")
        self.write("  {}\n".format(" ".join(self.packages)))
        self.write(
            f"0 upgraded, {len(self.packages)} newly installed, 0 to remove and 259 not upgraded.\n"
        )
        self.write(f"Need to get {totalsize}.2kB of archives.\n")
        self.write(
            f"After this operation, {totalsize * 2.2:.1f}kB of additional disk space will be used.\n"
        )

        i = 1
        for p in self.packages:
            self.write(
                f"Get:{i} http://ftp.debian.org stable/main {p} "
                f"{self.packages[p]['version']} [{self.packages[p]['size']}.2kB]\n"
            )
            i += 1
            if install_count >= 3:
                yield self.sleep(2, 4)
            else:
                yield self.sleep(1, 2)

        self.write(f"Fetched {totalsize}.2kB in 1s (4493B/s)\n")
        yield self.sleep(1, 2)

        self.write(
            "(Reading database ... 177887 files and directories currently installed.)\n"
        )
        yield self.sleep(1, 2)

        for p in self.packages:
            self.write(
                f"Unpacking {p} (from .../archives/{p}_{self.packages[p]['version']}_i386.deb) ...\n"
            )
            yield self.sleep(1, 2)

        self.write("Processing triggers for man-db ...\n")
        yield self.sleep(2)

        for p in self.packages:
            self.write(
                f"Setting up {p} ({self.packages[p]['version']}) ...\n"
            )
            self.fs.mkfile(
                f"/usr/bin/{p}",
                self.protocol.user.uid,
                self.protocol.user.gid,
                random.randint(10000, 90000),
                33188,
            )
            self.protocol.commands[f"/usr/bin/{p}"] = (
                Command_faked_package_class_factory.getCommand(p)
            )
            yield self.sleep(2)

        self.exit()

    def do_moo(self) -> None:
        self.write(
            "         (__)\n"
            "         (oo)\n"
            "   /------\\/\n"
            "  / |    ||\n"
            " *  /\\---/\\ \n"
            "    ~~   ~~\n"
            "....\"Have you mooed today?\"...\n"
        )
        self.exit()

    def do_locked(self) -> None:
        self.errorWrite(
            "E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)\n"
        )
        self.errorWrite(
            "E: Unable to lock the list directory\n"
        )
        self.exit()


commands["apt"] = Command_aptget
commands["apt-get"] = Command_aptget
commands["/usr/bin/apt"] = Command_aptget
commands["/usr/bin/apt-get"] = Command_aptget
commands["/bin/apt"] = Command_aptget
commands["/bin/apt-get"] = Command_aptget

