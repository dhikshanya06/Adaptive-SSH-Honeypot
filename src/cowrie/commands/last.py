from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_env(HoneyPotCommand):
    """
    Adaptive env command

    Behavior:
    - First call: minimal realistic environment (recon stage)
    - Repeated calls or higher interaction level: richer environment
    - High interaction level: deceptive production-like variables
    """

    def call(self) -> None:
        # Track how many times env was executed in this session
        if not hasattr(self.protocol, "_env_count"):
            self.protocol._env_count = 0
        self.protocol._env_count += 1

        # --------------------------------------------------
        # BASE ENVIRONMENT (always shown)
        # --------------------------------------------------
        self.write("SHELL=/bin/bash\n")
        self.write(f"TERM={self.environ.get('TERM', 'xterm')}\n")
        self.write(f"USER={self.environ.get('USER', 'root')}\n")

        # --------------------------------------------------
        # STAGE 1: Initial Reconnaissance
        # --------------------------------------------------
        if self.protocol._env_count == 1 and self.interaction_level < 2:
            self.write(
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            )
            self.write(f"PWD={self.protocol.cwd}\n")
            self.write("LANG=en_US.UTF-8\n")
            self.write("SHLVL=1\n")
            self.exit()
            return

        # --------------------------------------------------
        # STAGE 2: Suspicious or Repeated Reconnaissance
        # --------------------------------------------------
        if self.interaction_level >= 2:
            self.write(
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            )
            self.write(f"PWD={self.protocol.cwd}\n")
            self.write("LANG=en_US.UTF-8\n")
            self.write("SHLVL=1\n")
            self.write(f"HOME={self.environ.get('HOME', '/root')}\n")
            self.write("APP_ENV=production\n")

        # --------------------------------------------------
        # STAGE 3: High-Risk Attacker (Deceptive Exposure)
        # --------------------------------------------------
        if self.interaction_level >= 3:
            self.write("LOGNAME=root\n")
            self.write(
                f"SSH_CONNECTION={self.protocol.clientIP} "
                f"{self.protocol.realClientPort} 192.168.1.100 22\n"
            )
            self.write("XDG_SESSION_ID=3\n")
            self.write("XDG_RUNTIME_DIR=/run/user/0\n")

            # Fake but realistic production secrets
            self.write("DB_HOST=10.0.0.12\n")
            self.write("DB_USER=admin\n")
            self.write("DB_PASS=********\n")
            self.write("AWS_REGION=us-east-1\n")
            self.write("INTERNAL_API=http://10.0.0.25/api\n")

        self.exit()


commands["/usr/bin/env"] = Command_env
commands["env"] = Command_env

