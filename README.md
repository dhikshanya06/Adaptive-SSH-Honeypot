# 🛡️ Cloud-Deployed Adaptive SSH Honeypot
> Reinforcement Learning + LLM-Based Dynamic Response Generation on AWS EC2

Static honeypots get fingerprinted in seconds. This one learns.

---

## What It Does

- Watches every attacker command in real time
- Q-Learning agent picks the best deception action across **96 states**
- Llama 3.1 8B generates a realistic Linux shell response **within 1 second**
- Honeytoken bait files (fake AWS keys, DB passwords) detect attacker intent
- Profiles attackers as **Script Kiddie / Intermediate / Expert** automatically

---

## Results (457 Real Attack Sessions on AWS EC2)

| Metric | Static Cowrie | This System |
|---|---|---|
| Avg Session Duration | 3.0s | 8.6s (+187.1%) |
| Avg Commands / Session | 2.0 | 5.1 (+154.8%) |
| Bait File Hits | 0 | 0.5 / session |
| Attacker Profiling | None | 3-class real-time |

---

## How It Works

<img width="300" height="300" alt="image" src="https://github.com/user-attachments/assets/a32c650a-9951-4900-a7e3-1ebde7d76b7b" />


---

## Tech Stack

`Python` `Cowrie` `Q-Learning` `Llama 3.1 8B` `Groq API` `AWS EC2` `Paramiko` `stable-baselines3`

---

## Quick Start

```bash
# Clone Cowrie and this repository
git clone https://github.com/cowrie/cowrie.git
git clone https://github.com/dhikshanya06/Adaptive-SSH-Honeypot.git

# Create virtual environment and install dependencies
cd Adaptive-SSH-Honeypot
pip install -r requirements.txt

# Set Groq API key
export GROQ_API_KEY=your_api_key_here

# Apply iptables redirect (port 22 to 2222)
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Run sandbox pre-training before real attackers connect
python3 src/cowrie/adaptive/attacker_simulator.py mixed 100

# Run log-based training on accumulated sessions
python3 src/cowrie/adaptive/train_from_logs.py var/log/cowrie/cowrie.json

# Start the honeypot
bin/cowrie start

# Monitor live logs
tail -f var/log/cowrie/cowrie.json

# View dashboard and evaluation
python3 src/cowrie/adaptive/dashboard.py
python3 src/cowrie/adaptive/evaluation.py
```

---
