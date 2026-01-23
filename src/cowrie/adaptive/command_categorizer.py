
class CommandCategorizer:
    """
    Categorizes commands based on their potential risk and intent.
    """
    
    CATEGORIES = {
        "reconnaissance": [
            "ls", "dir", "cd", "pwd", "whoami", "id", "uname", "cat", 
            "grep", "find", "locate", "which", "history"
        ],
        "privilege_escalation": [
            "sudo", "su", "pkexec", "doas"
        ],
        "download": [
            "wget", "curl", "scp", "ftp", "tftp", "git"
        ],
        "persistence": [
            "cron", "crontab", "rc.d", "init.d", "systemctl", "service", 
            "chkconfig", "update-rc.d"
        ],
        "scanning": [
            "nmap", "netstat", "ss", "lsof", "ping", "traceroute", "dig", "nslookup"
        ],
        "file_modification": [
            "rm", "mv", "cp", "touch", "chmod", "chown", "mkdir", "dd", "echo", "nano", "vi", "vim"
        ]
    }

    def categorize_command(self, command_name):
        """
        Returns the category of a command.
        """
        cmd = command_name.lower().strip()
        
        for category, commands in self.CATEGORIES.items():
            if cmd in commands:
                return category
                
        return "general"
