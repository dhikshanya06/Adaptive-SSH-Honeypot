
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
    print("  STEP 2: RULE-BASED ANALYZER (POST-MORTEM REPORT)")
    print("="*60)
    print("Description: Applies Semantic Rules to the full session history.")

    collector = get_latest_session_collector()
    if not collector:
        print("\n[!] No sessions found.")
        return

    print(f"\n[ANALYZING SESSION]: {collector.session_id}")
    
    # Group similar commands
    grouped_cmds = {}
    for cmd in collector.commands:
        if cmd not in grouped_cmds:
            grouped_cmds[cmd] = 0
        grouped_cmds[cmd] += 1
        
    print("\n[RULE ENGINE RESULTS (Per Command)]")
    
    for cmd, count in grouped_cmds.items():
        # Create a temp collector to analyze just this command context
        temp_col = SessionCollector("temp")
        temp_col.add_command(cmd)
        
        summary = temp_col.get_text_summary()
        tags = summary.split(". ")
        
        matches = []
        for tag in tags:
            if tag.strip() and not tag.startswith("Commands executed"):
                matches.append(tag.strip())
        
        count_str = f"(x{count})" if count > 1 else ""
        print(f"   Command: \033[94m'{cmd}' {count_str}\033[0m")
        
        if matches:
            for m in matches:
                print(f"      -> [RULE MATCH] \033[93m{m}\033[0m")
        else:
             print(f"      -> [INFO] No specific risk rule.")
        print("")

    print("[SUCCESS] Rules Applied.")

if __name__ == "__main__":
    main()
