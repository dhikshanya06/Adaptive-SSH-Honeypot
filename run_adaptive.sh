#!/bin/bash

# Adaptive SSH Honeypot - Quick Run Script
# Usage: ./run_adaptive.sh [train|demo|live]

VENV_PYTHON="/home/dhikshanya06/Adaptive-SSH-Honeypot/cowrie-env/bin/python"
PROJECT_ROOT="/home/dhikshanya06/Adaptive-SSH-Honeypot"

# Check if cowrie-env exists
if [ ! -f "$VENV_PYTHON" ]; then
    echo "[!] Error: Virtual environment python not found at $VENV_PYTHON"
    echo "    Please create the virtual environment first."
    exit 1
fi

MODE=${1:-demo}

echo "========================================="
echo " Adaptive SSH Honeypot (RL Edition)"
echo "========================================="
echo "Mode: $MODE"

cd "$PROJECT_ROOT"

if [ "$MODE" == "train" ]; then
    echo "[*] Starting Training Session..."
    "$VENV_PYTHON" src/cowrie/adaptive/demo_simulation.py --train

elif [ "$MODE" == "demo" ]; then
    echo "[*] Running Simulation Demo..."
    "$VENV_PYTHON" src/cowrie/adaptive/demo_simulation.py

elif [ "$MODE" == "live" ]; then
    echo "[*] Starting Live Controller..."
    echo "    Ensuring Cowrie is generating logs..."
    "$VENV_PYTHON" src/cowrie/adaptive/live_adaptive_controller.py

else
    echo "[!] Unknown mode: $MODE"
    echo "Usage: ./run_adaptive.sh [train|demo|live]"
fi
