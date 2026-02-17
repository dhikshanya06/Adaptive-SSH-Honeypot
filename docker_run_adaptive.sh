#!/bin/bash
# Build the image from the workspace root context
# We need to be in the root of the repo so COPY src/ works
cd "$(dirname "$0")"

echo "[*] Building adaptive-brain..."
docker build -t adaptive-brain -f adaptive-brain/Dockerfile .

echo "[*] Running adaptive-brain..."
# --network host allows connecting to localhost:11434 (Ollama) on the host
# Create persistent log directory for the brain
mkdir -p var/log/adaptive-brain

# Mount the named volume from the running Cowrie container
docker run --rm --network host \
  -v docker_cowrie-var:/app/var/log/cowrie:ro \
  -v "$(pwd)/var/log/adaptive-brain:/app/var/log/adaptive-brain" \
  adaptive-brain
