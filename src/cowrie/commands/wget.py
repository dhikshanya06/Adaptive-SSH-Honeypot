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
        # -------- ADAPTIVE STATE TRACKING --------
        try:
            session_id = getattr(self.protocol, "sessionid", "unknown")
            tracker = SessionTracker.get_instance()
            state = tracker.record_command(
                session_id=session_id,
                command="wget",
                category="payload_delivery"
            )
            wget_count = state["command_counts"]["wget"]
        except Exception:
            wget_count = 1
        # ----------------------------------------

        try:
            _, args = getopt.getopt(self.args, "hqO:")
        except getopt.GetoptError:
            self.errorWrite("wget: invalid option\n")
            reactor.callLater(0.1, self.exit)
            return

        if not args:
            self.errorWrite("wget: missing URL\n")
            reactor.callLater(0.1, self.exit)
            return

        url = args[0]
        if "://" not in url:
            url = f"http://{url}"

        parsed = parse.urlparse(url)
        host = parsed.hostname or "unknown"

        # -------- ADAPTIVE BEHAVIOR --------
        if wget_count < 3:
            # Fake success
            tm = time.strftime("%Y-%m-%d %H:%M:%S")
            self.errorWrite(f"--{tm}--  {url}\n")
            self.errorWrite(f"Resolving {host}... done.\n")
            self.errorWrite(f"Connecting to {host}... connected.\n")
            self.errorWrite("HTTP request sent, awaiting response... 200 OK\n")
            self.errorWrite("Length: 4096 (4.0K)\n")
            self.errorWrite("Saving to: 'payload.bin'\n\n")
            self.errorWrite("payload.bin 100%[==================>] 4.00K\n\n")
            self.errorWrite("'payload.bin' saved\n")
        else:
            # Escalated response
            self.errorWrite(
                "HTTP request sent, awaiting response... 403 Forbidden\n"
            )
            self.errorWrite(
                "wget: server returned error: 403 Forbidden\n"
            )
        # ----------------------------------

        # Allow output to flush safely
        reactor.callLater(0.1, self.exit)


commands["wget"] = Command_wget
commands["/usr/bin/wget"] = Command_wget
commands["dget"] = Command_wget
commands["/usr/bin/dget"] = Command_wget

