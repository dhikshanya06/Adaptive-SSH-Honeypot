from __future__ import annotations

import time
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import FileNotFound
from cowrie.adaptive.policy.policy_engine import PolicyEngine

commands = {}


class Command_cat(HoneyPotCommand):

    def call(self) -> None:
        if not self.args:
            return

        for arg in self.args:
            path = self.fs.resolve_path(arg, self.protocol.cwd)
            
            # 1. Directory Check
            if self.fs.isdir(path):
                self.errorWrite(f"cat: {arg}: Is a directory\n")
                continue

            try:
                data = self.fs.file_contents(path)
                if data:
                    self.writeBytes(data)
            except FileNotFound:
                # 2. Adaptive Handling
                fake_content = self.generate_fake_content(arg, path)
                if fake_content:
                    self.writeBytes(fake_content)
                else:
                    self.errorWrite(f"cat: {arg}: No such file or directory\n")

    def generate_fake_content(self, filename: str, fullpath: str) -> bytes | None:
        """
        Generates fake content based on session risk level.
        """
        # Get Policy
        try:
            policy_engine = PolicyEngine()
            # session_id might not be available in all contexts, handle gracefully
            session_id = getattr(self.protocol, "session_id", "unknown")
            policy = policy_engine.get_policy(session_id)
            risk = policy.get("risk", "low").lower()
        except Exception:
            risk = "low" # Default fallback

        # Risk-based Content Generation
        if risk == "high":
            # Start denying access or giving garbage
            return None
            
        # Common targets
        base_name = filename.split("/")[-1]
        
        if base_name == "passwd":
            return (
                b"root:x:0:0:root:/root:/bin/bash\n"
                b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                b"mysql:x:106:115:MySQL Server,,,:/nonexistent:/bin/false\n"
            )
            
        if "notes" in base_name or "todo" in base_name:
            return (
                b"1. Update server kernel\n"
                b"2. Backup database\n"
                b"3. Check logs for weird activity\n"
            )

        if base_name == ".bash_history":
            return (
                b"ls -la\n"
                b"sudo apt update\n"
                b"cd /var/www/html\n"
                b"nano config.php\n"
                b"exit\n"
            )

        # Generic Text File Mock (only if extension looks like text)
        if risk == "low" and (filename.endswith(".txt") or filename.endswith(".log") or filename.endswith(".conf")):
             return b"# Configuration file\n# Last modified: 2024-01-01\n"

        return None

commands["cat"] = Command_cat
commands["/bin/cat"] = Command_cat

