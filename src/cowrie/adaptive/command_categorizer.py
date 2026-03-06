class CommandCategorizer:
    def __init__(self):
        self.categories = {
            "recon": ["whoami","id","uname","hostname","ifconfig","ip"],
            "file": ["ls","cat","find","locate","grep"],
            "network": ["ss","netstat","curl","wget","ssh"],
            "escalation": ["sudo","su","chmod","chown"],
        }
    def categorize(self, command):
        cmd = command.split()[0] if command else ""
        for cat, cmds in self.categories.items():
            if cmd in cmds:
                return cat
        return "unknown"