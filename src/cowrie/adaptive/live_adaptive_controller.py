
import json
import time
import os
import sys
import importlib.util

# --- PATH SETUP ---
# Ensure we can import from src
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../.."))
if project_root not in sys.path:
    sys.path.append(project_root)

# --- DYNAMIC IMPORTS (To match demo reliability) ---
try:
    # 1. Session Collector
    collector_path = os.path.join(project_root, "src/cowrie/adaptive/telemetry/session_collector.py")
    spec = importlib.util.spec_from_file_location("session_collector", collector_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    SessionCollector = module.SessionCollector

    # 2. Intent Reasoner
    # We use the trick to ensure it finds build_index relative to itself if needed
    reasoner_path = os.path.join(project_root, "src/cowrie/adaptive/llm/intent_reasoner.py")
    spec = importlib.util.spec_from_file_location("intent_reasoner", reasoner_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    IntentReasoner = module.IntentReasoner

    # 3. Policy Engine
    policy_path = os.path.join(project_root, "src/cowrie/adaptive/policy/policy_engine.py")
    spec = importlib.util.spec_from_file_location("policy_engine", policy_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    PolicyEngine = module.PolicyEngine

except Exception as e:
    print(f"CRITICAL IMPORT ERROR: {e}")
    sys.exit(1)

# --- PICKLE PATCH (Required for RAG loading) ---
# Ensure SimpleRAGIndex matches the class path used during saving
try:
    build_index_path = os.path.join(project_root, "src/cowrie/adaptive/rag/build_index.py")
    spec = importlib.util.spec_from_file_location("build_index", build_index_path)
    build_index_module = importlib.util.module_from_spec(spec)
    sys.modules["build_index"] = build_index_module
    spec.loader.exec_module(build_index_module)
    SimpleRAGIndex = build_index_module.SimpleRAGIndex
    
    # Inject into __main__ if needed for some unpicklers
    import builtins
    if not hasattr(builtins, "SimpleRAGIndex"):
        setattr(builtins, "SimpleRAGIndex", SimpleRAGIndex)
except Exception as e:
    print(f"Warning: Could not patch pickle environment: {e}")

# --- CONSTANTS ---
LOG_FILE = os.path.join(project_root, "var/log/cowrie/cowrie.json")
POLL_INTERVAL = 1.0

class LiveController:
    def __init__(self):
        self.reasoner = IntentReasoner()
        self.policy_engine = PolicyEngine()
        self.collectors = {} # session_id -> SessionCollector instance
        self.processed_lines = 0

    def get_collector(self, session_id):
        if session_id not in self.collectors:
            self.collectors[session_id] = SessionCollector(session_id)
        return self.collectors[session_id]

    def process_event(self, event):
        session_id = event.get('session')
        if not session_id:
            return

        collector = self.get_collector(session_id)
        analyze_needed = False

        # Parse Event Type
        event_id = event.get('eventid')
        if event_id == 'cowrie.command.input':
            cmd = event.get('input')
            collector.add_command(cmd)
            analyze_needed = True
            print(f"   [ACTIVITY] {session_id}: Command '{cmd}'")
        
        elif event_id == 'cowrie.session.file_download':
            url = event.get('url')
            collector.add_download(f"wget {url}") # Normalize for collector
            analyze_needed = True
            print(f"   [ACTIVITY] {session_id}: Download '{url}'")

        if analyze_needed:
            self.analyze(session_id, collector)

    def analyze(self, session_id, collector):
        # Get Summary
        summary_text = collector.get_text_summary()

        # Call Brain
        analysis = self.reasoner.analyze_session(summary_text) # This has the cache/overrides built-in now
        
        # Display Result
        intent = analysis.get("intent", "unknown")
        risk = analysis.get("risk", "low")
        policy = analysis.get("policy", "passive_monitoring")

        # Colorize
        risks = {
            "low": "\033[92mLOW\033[0m", 
            "medium": "\033[93mMEDIUM\033[0m", 
            "high": "\033[91mHIGH\033[0m",
            "critical": "\033[41m\033[97mCRITICAL\033[0m",
            "very high": "\033[35mVERY HIGH\033[0m"
        }
        risk_display = risks.get(risk.lower(), risk.upper())

        print(f"   [BRAIN] Intent: {intent} | Risk: {risk_display} | Policy: {policy}")

        # Update Policy Engine (which would theoretically talk to backend)
        self.policy_engine.update_policy(session_id, analysis)

        if risk.lower() in ["high", "critical", "very high"]:
             print(f"   [!!!] ACTIVE DEFENSE TRIGGERED for {session_id}")
        
    def tail_log(self):
        print(f"[*] Monitoring Log: {LOG_FILE}")
        
        if not os.path.exists(LOG_FILE):
             print(f"[!] Warning: Log file not found at {LOG_FILE}. Waiting for it to appear...")

        # Catch up to end of file
        try:
            with open(LOG_FILE, 'r') as f:
                f.seek(0, 2) # Go to end
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(POLL_INTERVAL)
                        continue
                    
                    try:
                        event = json.loads(line)
                        self.process_event(event)
                    except json.JSONDecodeError:
                        pass
        except KeyboardInterrupt:
            print("\n[*] Stopping Controller.")
        except Exception as e:
            print(f"[!] File Error: {e}")

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  LIVE ADAPTIVE CONTROLLER :: MONITORING ACTIVE SESSIONS")
    print("="*60 + "\n")
    
    controller = LiveController()
    controller.tail_log()
