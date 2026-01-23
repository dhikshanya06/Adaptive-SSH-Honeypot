
import sys
import os
import json
import importlib.util

# Paths
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../.."))
LOG_FILE = os.path.join(project_root, "var/log/cowrie/cowrie.json")

# Imports
try:
    # Patch pickle
    build_index_path = os.path.join(project_root, "src/cowrie/adaptive/rag/build_index.py")
    spec = importlib.util.spec_from_file_location("build_index", build_index_path)
    build_index_module = importlib.util.module_from_spec(spec)
    sys.modules["build_index"] = build_index_module
    spec.loader.exec_module(build_index_module)
    SimpleRAGIndex = build_index_module.SimpleRAGIndex
    import builtins
    if not hasattr(builtins, "SimpleRAGIndex"): setattr(builtins, "SimpleRAGIndex", SimpleRAGIndex)

    reasoner_path = os.path.join(project_root, "src/cowrie/adaptive/llm/intent_reasoner.py")
    spec = importlib.util.spec_from_file_location("intent_reasoner", reasoner_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    IntentReasoner = module.IntentReasoner
    
    collector_path = os.path.join(project_root, "src/cowrie/adaptive/telemetry/session_collector.py")
    spec = importlib.util.spec_from_file_location("session_collector", collector_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    SessionCollector = module.SessionCollector

except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

def get_latest_session_collector():
    if not os.path.exists(LOG_FILE): return None
    sessions = {}
    last_session_id = None
    with open(LOG_FILE, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                sid = event.get('session')
                if not sid: continue
                last_session_id = sid
                if sid not in sessions: sessions[sid] = SessionCollector(sid)
                if event.get('eventid') == 'cowrie.command.input':
                    sessions[sid].add_command(event.get('input'))
                elif event.get('eventid') == 'cowrie.session.file_download':
                    sessions[sid].add_download(f"wget {event.get('url')}")
            except: pass
    if last_session_id: return sessions[last_session_id]
    return None

def main():
    print("\n" + "="*60)
    print("  STEP 3: LLM INTELLIGENCE (POST-MORTEM REPORT)")
    print("="*60)
    print("Description: Queries the AI Brain for a final verdict on the SESSION.")

    collector = get_latest_session_collector()
    if not collector:
        print("\n[!] No sessions found.")
        return

    print(f"\n[SESSION TARGET]: {collector.session_id}")
    print("[Generating Prompt from Session History...]")
    summary = collector.get_text_summary()
    
    print("\n[QUERYING BRAIN...]")
    reasoner = IntentReasoner()
    result = reasoner.analyze_session(summary)

    intent = result.get("intent", "unknown")
    risk = result.get("risk", "low")
    policy = result.get("policy", "monitoring")

    color = "\033[92m" # Green
    if risk == "medium": color = "\033[93m" 
    if risk in ["high", "critical", "very high"]: color = "\033[91m"
    
    print(f"\n[FINAL INTELLIGENCE REPORT]")
    print(f"   Intent: {intent}")
    print(f"   Risk:   {color}{risk.upper()}\033[0m")
    print(f"   Policy: {policy}")
    
    print("\n[SUCCESS] Final Report Generated.")

if __name__ == "__main__":
    main()
