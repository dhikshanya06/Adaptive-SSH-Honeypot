from twisted.internet import reactor, defer
from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_env(HoneyPotCommand):
    """
    SAFE env command
    - Uses start(), not call()
    - Never crashes shell
    - Adaptive but controlled
    """

    def start(self) -> None:
        # Track how many times env is run
        if not hasattr(self.protocol, "_env_count"):
            self.protocol._env_count = 0
        self.protocol._env_count += 1

        delay = 0
        # Simulate slight delay for realism if count is high
        if self.protocol._env_count >= 3:
            delay = 0.5

        d = defer.Deferred()
        reactor.callLater(delay, d.callback, None)
        d.addCallback(self.render_env)

    def render_env(self, _ignored=None) -> None:
        level = self.interaction_level
        count = self.protocol._env_count

        # ---------- BASE ENV (always shown) ----------
        self.write("SHELL=/bin/bash\n")
        self.write("TERM=xterm\n")
        self.write("USER=root\n")
        self.write("LANG=en_US.UTF-8\n")
        self.write(f"PWD={self.protocol.cwd}\n")
        self.write("SHLVL=1\n")

        # ---------- STAGE 2: suspicious ----------
        if level >= 2 or count >= 2:
            self.write(
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            )
            self.write("HOME=/root\n")
            self.write("APP_ENV=production\n")

        # ---------- STAGE 3: high-risk ----------
        if level >= 3 or count >= 3:
            self.write("LOGNAME=root\n")
            self.write(
                f"SSH_CONNECTION={self.protocol.clientIP} "
                f"{self.protocol.realClientPort} 192.168.1.100 22\n"
            )
            self.write("XDG_SESSION_ID=3\n")
            self.write("XDG_RUNTIME_DIR=/run/user/0\n")

            # Fake secrets (safe deception)
            self.write("DB_HOST=10.0.0.12\n")
            self.write("DB_USER=admin\n")
            self.write("DB_PASS=********\n")
            self.write("INTERNAL_API=http://10.0.0.25/api\n")

        # ✅ ALWAYS exit cleanly
        self.exit()


commands["env"] = Command_env
commands["/usr/bin/env"] = Command_env

