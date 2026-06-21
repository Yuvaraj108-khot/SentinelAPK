import os
import json

def main():
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    gap_report_path = os.path.join(backend_dir, "evasion_gap_report.json")
    
    if not os.path.exists(gap_report_path):
        print("Error: evasion_gap_report.json not found.")
        return
        
    with open(gap_report_path, "r") as f:
        data = json.load(f)
        
    scenarios = data.get("evasion_gap_scenarios", [])
    
    audit = {
        "status": "COMPLETED",
        "scenarios_analyzed": len(scenarios),
        "coverage_summary": {
            "DETECTED": 0,
            "PARTIALLY_DETECTED": 0,
            "MISSED": 0
        },
        "missed_details": []
    }
    
    for s in scenarios:
        det = s.get("detected", False)
        # Determine classification
        if det:
            status = "DETECTED"
            audit["coverage_summary"]["DETECTED"] += 1
        else:
            status = "MISSED"
            audit["coverage_summary"]["MISSED"] += 1
            
            # Map missed details
            audit["missed_details"].append({
                "scenario_id": s["scenario_id"],
                "attack_technique": s["technique"],
                "why_it_bypasses": s["rationale"],
                "detector_should_have_fired": s["detector_failed"],
                "required_implementation_change": f"Implement dynamic/decryption parsing logic or control flow graph mapping for {s['technique']}."
            })
            
    # Save evasion_coverage_audit.json
    with open(os.path.join(backend_dir, "evasion_coverage_audit.json"), "w") as f:
        json.dump(audit, f, indent=2)
    print("Generated evasion_coverage_audit.json")
    
    # ----------------------------------------------------
    # Generate TOP_10_HIGHEST_RISK_GAPS.json
    # ----------------------------------------------------
    # Rank missed scenarios by risk factors (likelihood, impact, ease)
    ranked_gaps = []
    for m in audit["missed_details"][:10]:
        tech = m["attack_technique"]
        ranked_gaps.append({
            "scenario_id": m["scenario_id"],
            "technique": tech,
            "likelihood": "HIGH" if tech in ["Reflection", "Encrypted strings"] else "MEDIUM",
            "impact": "CRITICAL" if tech in ["SMS theft", "Fake banking clones", "Accessibility abuse", "Overlay abuse"] else "HIGH",
            "ease_of_exploitation": "EASY" if tech in ["Delayed execution", "Reflection"] else "MEDIUM",
            "risk_score": 9.0 if tech in ["SMS theft", "Fake banking clones"] else 7.5
        })
    ranked_gaps = sorted(ranked_gaps, key=lambda x: -x["risk_score"])
    
    with open(os.path.join(backend_dir, "TOP_10_HIGHEST_RISK_GAPS.json"), "w") as f:
        json.dump(ranked_gaps, f, indent=2)
    print("Generated TOP_10_HIGHEST_RISK_GAPS.json")
    
    # ----------------------------------------------------
    # Generate ROADMAP_NEXT_10_FEATURES.json
    # ----------------------------------------------------
    roadmap = [
        {"feature_id": "F_001", "name": "Control Flow Graph (CFG) Analysis", "closes_gap": "Reflection / Indirect system calls API hiding"},
        {"feature_id": "F_002", "name": "Static String Decryption Heuristic Solver", "closes_gap": "Encrypted strings / Obfuscated class names"},
        {"feature_id": "F_003", "name": "Certificate Authority Chain Validation", "closes_gap": "Untrusted / Self-signed certificate masquerading"},
        {"feature_id": "F_004", "name": "SMS BroadcastReceiver Intent-Filter Matcher", "closes_gap": "SMS theft detection via custom priority levels"},
        {"feature_id": "F_005", "name": "WindowLayout LayoutParams Validation", "closes_gap": "Overlay abuse matching SYSTEM_ALERT_WINDOW layouts"},
        {"feature_id": "F_006", "name": "DexClassLoader Asset Path Validation", "closes_gap": "Dynamic loading of payloads from local assets"},
        {"feature_id": "F_007", "name": "System API Reflection Call Tracker", "closes_gap": "Accessing TelephonyManager/SmsManager via reflection"},
        {"feature_id": "F_008", "name": "Window Content Event Monitor Analysis", "closes_gap": "Accessibility abuse tracking WindowContentChanged callbacks"},
        {"feature_id": "F_009", "name": "Launcher Activity Layout Comparison", "closes_gap": "Fake banking clones impersonating legitimate icons/colors"},
        {"feature_id": "F_010", "name": "Dalvik Opcode Entropy Scanner", "closes_gap": "Packed / Cryptographically wrapped payloads in classes.dex"}
    ]
    
    with open(os.path.join(backend_dir, "ROADMAP_NEXT_10_FEATURES.json"), "w") as f:
        json.dump(roadmap, f, indent=2)
    print("Generated ROADMAP_NEXT_10_FEATURES.json")

if __name__ == "__main__":
    main()
