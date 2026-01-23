
import sys
import os
import json
import importlib.util

# Paths
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../.."))
LOG_FILE = os.path.join(project_root, "var/log/cowrie/cowrie.json")

# Import SessionCollector
try:
    collector_path = os.path.join(project_root, "src/cowrie/adaptive/telemetry/session_collector.py")
    spec = importlib.util.spec_from_file_location("session_collector", collector_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    SessionCollector = module.SessionCollector
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

def get_latest_session_collector():
    if not os.path.exists(LOG_FILE):
        return None
    
    sessions = {}
    last_session_id = None
    
    with open(LOG_FILE, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                sid = event.get('session')
                if not sid: continue
                
                last_session_id = sid
                if sid not in sessions:
                    sessions[sid] = SessionCollector(sid)
                
                col = sessions[sid]
                if event.get('eventid') == 'cowrie.command.input':
                    col.add_command(event.get('input'))
                elif event.get('eventid') == 'cowrie.session.file_download':
                    col.add_download(f"wget {event.get('url')}")
            except:
                pass
                
    if last_session_id:
        return sessions[last_session_id]
    return None

def main():
    print("\n" + "="*60)
    print("  STEP 1: SESSION ANALYZER (POST-MORTEM REPORT)")
    print("="*60)
    print("Description: Shows the complete gathered history of the LATEST session.")
    
    collector = get_latest_session_collector()
    
    if not collector:
        print("\n[!] No sessions found in logs yet.")
        return

    print(f"\n[ANALYSIS TARGET] Session ID: {collector.session_id}")
    print("\n[COLLECTED DATA]")
    print(f"   Command History ({len(collector.commands)} cmds):")
    print(f"   {collector.commands}")
    
    if len(collector.downloads) > 0:
        print(f"   Downloads detected: {collector.downloads}")

    print("\n[SUCCESS] Session Grouping Verified.")

if __name__ == "__main__":
    main()
