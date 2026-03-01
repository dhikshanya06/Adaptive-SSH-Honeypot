import os

BAIT_TRIGGERS = {
    "database": {
        "path": "/home/admin/db_backup.sql",
        "content": """-- MySQL dump, company_db
-- Date: 2024-11-15 03:22:11
CREATE TABLE users (
  id int PRIMARY KEY AUTO_INCREMENT,
  username varchar(50),
  password_hash varchar(255),
  email varchar(100)
);
INSERT INTO users VALUES
(1,'admin','$2y$10$92IXUNpkjO0rOQ5by.admin','admin@company.local'),
(2,'jsmith','$2y$10$TKh8H1.PfQx37Yg.smith','j.smith@company.local');
INSERT INTO financial_records VALUES (1,'Q3-2024',4782000.00);
"""
    },
    "password": {
        "path": "/home/admin/.credentials.txt",
        "content": """# Service Credentials - CONFIDENTIAL
[Database]
host=localhost
user=dbadmin
pass=Sup3rS3cur3DB2024!
[AWS]
access_key=AKIAIOSFODNN7EXAMPLE
secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCY
"""
    },
    "backup": {
        "path": "/var/backups/server_backup.txt",
        "content": """server_backup_2024-11-01.tar.gz
  home/admin/db_backup.sql
  home/admin/.credentials.txt
  etc/app/config.yml
"""
    }
}

class EngagementEngine:
    def __init__(self):
        self.created_files = set()
        self.cowrie_fs = os.path.expanduser("~/Adaptive-SSH-Honeypot/honeyfs")

    def check_and_plant(self, command: str):
        command_lower = command.lower()
        planted = []
        for keyword, config in BAIT_TRIGGERS.items():
            if keyword in command_lower:
                fpath = config["path"]
                if fpath not in self.created_files:
                    real_path = self.cowrie_fs + fpath
                    os.makedirs(os.path.dirname(real_path), exist_ok=True)
                    with open(real_path, 'w') as f:
                        f.write(config["content"])
                    self.created_files.add(fpath)
                    planted.append(fpath)
                    print(f"[BAIT PLANTED] {fpath}", flush=True)
        return planted

engagement_engine = EngagementEngine()
