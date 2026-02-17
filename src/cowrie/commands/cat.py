from __future__ import annotations

import time
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import FileNotFound
from cowrie.adaptive.policy.policy_engine import PolicyEngine
from cowrie.adaptive.rl_agent import rl_agent

commands = {}


class Command_cat(HoneyPotCommand):

    def start(self) -> None:
        session_id = self.protocol.sessionno
        action = rl_agent.current_action.get(session_id, 0)

    def start(self) -> None:
        # --- RL INTEGRATION ---
        from cowrie.adaptive.rl_agent import rl_agent
        from twisted.python import log
        session_id = self.protocol.sessionno
        action = rl_agent.current_action.get(session_id, 0)

        log.msg(f"[CAT DEBUG] args: {self.args}, action: {action}")


        # 2: inject_fake_file
        if action == 2:
            self.write("AWS_ACCESS_KEY=AKIA1X2X3X4X\n")
            self.write("AWS_SECRET_KEY=abcd1234xyz\n")
            self.write("DB_PASSWORD=ProdServer@123\n")
            self.exit()
            return

        # 3: fake_error
        elif action == 3:
            filename = self.args[0] if self.args else "file"
            self.errorWrite(f"cat: {filename}: No such file or directory\n")
            self.exit()
            return

        # 4: escalate_deception
        elif action == 4:
             self.write("root_password=UltraSecure@2026\n")
             self.write("admin_token=ZXCVBNM998877\n")
             self.write("backup_location=/mnt/backups/prod\n")
             self.exit()
             return

        # 5: terminate_session
        elif action == 5:
            self.protocol.transport.loseConnection()
            return
            
        # 1: add_delay
        elif action == 1:
            from twisted.internet import reactor
            # "Binary data output..." after 2 sec delay
            # User request:
            # (2 second delay)
            # Binary data output...
            
            # Since we can't easily blocking sleep here without blocking the reactor
            # But the user *expects* a delay. 
            # We will use callLater to write the output and exit.
            
            reactor.callLater(2.0, self._write_normal_output_and_exit)
            return

        # 0: normal_response
        # User request:
        # Binary data output...
        self._write_normal_output_and_exit()

    def _write_normal_output_and_exit(self):
        # Spec from user:
        # Command: cat secrets.db
        # Action 0: Binary data output...
        
        # Check all args for the target filename just in case
        args_str = " ".join(self.args) if self.args else ""
        
        # DEBUG
        from twisted.python import log
        match = "secrets.db" in args_str
        log.msg(f"[CAT DEBUG] matches secrets.db? {match} (args_str: '{args_str}')")
        
        # If the user is targeting the specific demo file
        if match:
             self.write("Binary data output...\n")
             from twisted.internet import reactor
             reactor.callLater(0.1, self.exit)
             return

        # otherwise, fall back to standard behavior (reading from honeyfs)
        # We invoke self.call() directly to avoid re-triggering RL logic in super().start()
        # self.call() expects self.args to be set, which they are.
        try:
            self.call()
            # self.call() usually doesn't exit, we must exit after it returns?
            # 'call' loops through args.
            # After call returns, we should exit.
            self.exit()
        except Exception:
            self.exit()


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

