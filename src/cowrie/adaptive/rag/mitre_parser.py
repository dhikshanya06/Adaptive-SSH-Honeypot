
import json
import os

MITRE_FILE = "src/cowrie/adaptive/datasets/mitre/enterprise-attack.json"
OUTPUT_FILE = "src/cowrie/adaptive/rag/mitre_documents.json"

def parse_mitre():
    if not os.path.exists(MITRE_FILE):
        print(f"Error: {MITRE_FILE} not found.")
        return

    with open(MITRE_FILE, 'r') as f:
        data = json.load(f)

    documents = []
    
    objects = data.get('objects', [])
    print(f"Total objects found: {len(objects)}")

    for obj in objects:
        if obj.get('type') == 'attack-pattern':
            # Extract ID
            technique_id = None
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id')
                    break
            
            if not technique_id:
                continue

            # Extract Tactics
            tactics = []
            for phase in obj.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    tactics.append(phase.get('phase_name'))
            
            doc = {
                "id": technique_id,
                "name": obj.get('name'),
                "text": obj.get('description', ''),
                "tactic": ", ".join(tactics)
            }
            documents.append(doc)

    print(f"Parsed {len(documents)} MITRE techniques.")
    
    # Save to JSON for next step
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(documents, f, indent=2)
    print(f"Saved documents to {OUTPUT_FILE}")

if __name__ == "__main__":
    parse_mitre()
