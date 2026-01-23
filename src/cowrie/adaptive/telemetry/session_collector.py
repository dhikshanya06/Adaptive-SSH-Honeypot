
import time
import json

class SessionCollector:
    def __init__(self, session_id):
        self.session_id = session_id
        self.start_time = time.time()
        self.commands = []
        self.files_accessed = set()
        self.hidden_files_accessed = set()
        self.downloads = set()
        self.urls = set()
        self.last_update = time.time()

    def add_command(self, cmd):
        """Register a command execution."""
        if cmd:
            self.commands.append(cmd)
            self.last_update = time.time()

    def add_file_access(self, filepath):
        """Register a file access attempt."""
        self.files_accessed.add(filepath)
        if filepath.startswith('.') or '/.' in filepath:
            self.hidden_files_accessed.add(filepath)

    def add_url(self, url):
        """Register a URL access (wget/curl or direct-tcpip)."""
        self.urls.add(url)

    def add_download(self, filename):
        """Register a file download."""
        self.downloads.add(filename)

    def get_summary(self):
        """Return the dictionary matching the session schema."""
        duration = time.time() - self.start_time
        summary = {
            "session_id": self.session_id,
            "timestamp_start": self.start_time,
            "timestamp_end": time.time(),
            "commands_executed": self.commands,
            "files_accessed": list(self.files_accessed),
            "hidden_files_accessed": list(self.hidden_files_accessed),
            "network_urls": list(self.urls),
            "binary_downloads": list(self.downloads),
            "command_frequency": len(self.commands) / (duration if duration > 0 else 1)
        }
        return summary
    
    def get_text_summary(self):
        """Returns a string summary suitable for LLM matching (commands + filenames)."""
        summary_parts = []
        
        # 1. Raw Command List (Always important)
        summary_parts.append(f"Commands executed: {', '.join(self.commands)}.")
        cmd_str = " ".join(self.commands).lower()

        # --- COMPREHENSIVE COMMAND DICTIONARY ---
        # Maps command prefixes/names to Rule Descriptions
        rules = {
            # Identity & Session
            "whoami": "Host identity check", "id": "User identity check", "groups": "User group enumeration",
            "last": "Login history check", "finger": "User information query", "w": "Active user check",
            
            # System Information
            "uname": "System kernel version check", "uptime": "System uptime check", "free": "Memory usage check",
            "df": "Disk space usage check", "du": "Directory space usage check", "lscpu": "CPU architecture information",
            "env": "Environment variable listing", "ulimit": "System resource limit check", 
            "lspci": "PCI hardware enumeration", "ethtool": "Network interface hardware info",
            
            # Filesystem & Navigation
            "ls": "File system observation", "dir": "File system observation", "pwd": "Current working directory check",
            "cd": "Directory navigation", "tree": "Directory structure mapping",
            "find": "Active file search", "locate": "Database file search", "which": "Executable path location",
            
            # File Manipulation & Content
            "cat": "File content reading", "head": "Reading file header", "tail": "Reading file tail",
            "grep": "Searching text within files", "awk": "Text processing", "sed": "Text stream editing",
            "tee": "Output redirection", "uniq": "Text filtering", "wc": "Word count utility",
            "tar": "Archive manipulation", "unzip": "Archive extraction", "dd": "Raw data copying/wiping",
            "cp": "File copying", "mv": "File moving/renaming", "rm": "File deletion attempt",
            "touch": "File timestamp modification", "mkdir": "Directory creation",
            
            # Network Recon & Config
            "ping": "Network reachability test", "dig": "DNS lookup", "nslookup": "DNS lookup",
            "ifconfig": "Network interface configuration", "ip": "Network configuration inspection",
            "netstat": "Network connection listing", "ss": "Socket statistics", "arp": "ARP table inspection",
            "route": "Routing table inspection", "iptables": "Firewall configuration inspection",
            
            # Transfer & External (High Risk)
            "wget": "External file download attempt", "curl": "External file download/request",
            "scp": "Secure file transfer attempt", "sftp": "Secure file transfer attempt",
            "ftpget": "FTP file download", "tftp": "TFTP file transfer", "nc": "Netcat network tool usage",
            "ssh": "Outbound SSH connection attempt", "telnet": "Outbound Telnet connection attempt",
            
            # System Management & Persistence (High/Critical)
            "sudo": "Privilege escalation attempt", "su": "User context switch attempt",
            "useradd": "User account creation attempt", "adduser": "User account creation attempt",
            "chpasswd": "Password modification attempt", "passwd": "Password modification attempt",
            "crontab": "Scheduled task modification", "service": "Service status/control",
            "systemctl": "Systemd service control", "nohup": "Process persistence execution",
            "ps": "Process list inspection", "top": "Real-time process monitoring", 
            "dmesg": "Kernel ring buffer check", "kill": "Process termination attempt",
            "sleep": "Execution delay/stalling",
            
            # Languages & Shells
            "python": "Python interpreter execution", "perl": "Perl interpreter execution",
            "gcc": "C compiler execution", "make": "Build utility execution",
            "bash": "New shell instance spawning", "sh": "Shell execution", "busybox": "Busybox multi-call binary usage",
            "php": "PHP script execution",
            
            # Package Management
            "apt": "Package management activity", "apt-get": "Package management activity", "yum": "Package management activity"
        }

        # Scan all commands against the rule dictionary
        matched_rules = set()
        for cmd in self.commands:
            base_cmd = cmd.strip().split()[0]
            # Precise match
            if base_cmd in rules:
                matched_rules.add(rules[base_cmd] + ".")
            # Fallback for busybox etc
            elif "busybox" in cmd:
                 matched_rules.add("Busybox utility usage.")

        # Add the matches to summary
        summary_parts.extend(list(matched_rules))

        # --- RISK SPECIFIC OVERRIDES (Contextual) ---
        
        # 🟢 LOW RISK (Reconnaissance)
        if "cat readme" in cmd_str:
            summary_parts.append("Non-sensitive documentation read.")

        # 🟡 MEDIUM RISK (Discovery / Credential Access)
        if any(x in cmd_str for x in ["bash_history", "/etc/passwd", "/etc/shadow", ".db_creds"]):
             summary_parts.append("Attempted to read sensitive system configuration or credential files.")
        if "find" in cmd_str and ".key" in cmd_str:
             summary_parts.append("Active search for cryptographic keys.")
        if "sudo -l" in cmd_str:
             summary_parts.append("Checking for sudo privileges.")

        # 🔴 HIGH RISK (Payload Delivery / Execution)
        if "chmod +x" in cmd_str:
            summary_parts.append("File permissions modified to enable execution.")
        if "./" in cmd_str:
            summary_parts.append("Local binary execution.")

        # 🔴🔴 CRITICAL RISK (Privilege Escalation / Persistence)
        if "sudo su" in cmd_str or "sudo -i" in cmd_str:
            summary_parts.append("Use of SUDO for root access attempt.")
        if "chmod 777" in cmd_str:
            summary_parts.append("Insecure global permission modification.")
        if "authorized_keys" in cmd_str:
            summary_parts.append("SSH key injection for persistent access.")

        # ⚫ VERY HIGH RISK (Destructive / Cover Tracks)
        if "rm -rf" in cmd_str:
            summary_parts.append("Destructive command issued to wipe data.")
        if "history -c" in cmd_str or "rm /var/log" in cmd_str:
            summary_parts.append("Attempt to clear logs and cover tracks.")
        if "shutdown" in cmd_str or "reboot" in cmd_str:
            summary_parts.append("System service disruption attempt.")

        # Join everything
        return " ".join(summary_parts)
