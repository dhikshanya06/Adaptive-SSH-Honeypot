
import json
import os
import glob
from collections import defaultdict
import datetime

DATASET_DIR = "src/cowrie/adaptive/datasets/cowrie_logs"
OUTPUT_FILE = os.path.join(DATASET_DIR, "llm_examples.json")

def parse_logs():
    sessions = defaultdict(lambda: {
        "commands": [],
        "files": set(),
        "urls": set(),
        "start_time": None,
        "end_time": None
    })

    log_files = glob.glob(os.path.join(DATASET_DIR, "cowrie.json*"))
    print(f"Found {len(log_files)} log files.")

    for log_file in log_files:
        print(f"Processing {log_file}...")
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        session_id = data.get('session')
                        if not session_id:
                            continue
                        
                        event_id = data.get('eventid')
                        timestamp = data.get('timestamp') # Expecting ISO format

                        if not sessions[session_id]["start_time"]:
                            sessions[session_id]["start_time"] = timestamp
                        sessions[session_id]["end_time"] = timestamp # Update end time continuously

                        if event_id == 'cowrie.command.input':
                            cmd = data.get('input')
                            if cmd:
                                sessions[session_id]["commands"].append(cmd)
                        
                        elif event_id == 'cowrie.session.file_download':
                            url = data.get('url')
                            if url:
                                sessions[session_id]["urls"].add(url)
                            outfile = data.get('outfile')
                            if outfile:
                                sessions[session_id]["files"].add(outfile)

                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error reading {log_file}: {e}")

    # Generate Examples
    llm_examples = []
    
    for session_id, s_data in sessions.items():
        if not s_data["commands"]:
            continue # Skip empty sessions

        cmds = s_data["commands"]
        command_str = " ".join(cmds)
        
        # Simple rule-based intent labeling for the dataset
        intent = "reconnaissance" # Default
        
        cmd_text = command_str.lower()
        
        if "wget" in cmd_text or "curl" in cmd_text:
            intent = "payload_delivery"
        elif "rm " in cmd_text or "chmod" in cmd_text:
             intent = "defense_evasion" # bit simplistic but works
        elif "cat /etc/passwd" in cmd_text or "cat /etc/shadow" in cmd_text:
            intent = "credential_access"
        elif "./" in cmd_text and ("chmod +x" in cmd_text or "gcc" in cmd_text):
            intent = "local_malware_compilation"
        elif "ssh " in cmd_text or "nmap" in cmd_text:
             intent = "lateral_movement"

        # Refine intents based on combination
        if "payload_delivery" == intent and ("chmod +x" in cmd_text):
             intent = "dropper_execution"

        example = {
            "session_summary": command_str,
            "intent": intent,
            "full_details": {
                "session_id": session_id,
                "files_accessed": list(s_data["files"]),
                "urls": list(s_data["urls"]),
                "command_count": len(cmds)
            }
        }
        llm_examples.append(example)

    print(f"Generated {len(llm_examples)} examples.")
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(llm_examples, f, indent=2)
    print(f"Saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    parse_logs()
