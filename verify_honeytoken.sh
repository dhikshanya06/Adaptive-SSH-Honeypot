#!/bin/bash
# Verify Honeytoken Detection Script

echo "1. Checking if honeypot is running..."
if ! docker ps | grep -q "cowrie"; then
    echo "Honeypot is not running. Starting it..."
    docker compose -f docker/docker-compose.yml up -d
    sleep 5
fi

echo "2. Connecting to honeypot..."
echo "   (Enter password 'root' or '123456' when prompted)"

ssh -p 2222 root@localhost << 'EOF'
echo "--- BASELINE CHECK ---"
ls
echo "--- ACCESSING HONEYTOKEN ---"
cat /root/.aws_backup_keys.txt
cat /root/passwords.txt
echo "--- VERIFYING DELAY (Should pause for ~2s) ---"
time ls
EOF

echo "Verification complete."
