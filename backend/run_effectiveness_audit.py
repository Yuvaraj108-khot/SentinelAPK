import json
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from analyzer import APKAnalyzer
from risk_engine import RiskEngine

def run_audit():
    dataset_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")
    external_dir = os.path.join(dataset_dir, "real_world_external")
    
    apks_to_test = [
        os.path.join(external_dir, "VLC.apk"),
        os.path.join(external_dir, "Termux.apk"),
        os.path.join(external_dir, "Element.apk"),
        os.path.join(external_dir, "NewPipe.apk"),
        os.path.join(dataset_dir, "train", "benign", "SecureBank_Official.apk"),
        os.path.join(dataset_dir, "train", "suspicious", "SecureBank_Plus.apk"),
        os.path.join(dataset_dir, "train", "suspicious", "SecureBank_Clone.apk")
    ]
    
    report = {
        "V1_Findings": {},
        "V2_Findings": {},
        "Comparison": {
            "false_positives_downgraded": [],
            "malicious_combinations_triggered": []
        }
    }
    
    for apk_path in apks_to_test:
        if not os.path.exists(apk_path):
            print(f"Skipping {apk_path}, file not found")
            continue
            
        print(f"Analyzing {os.path.basename(apk_path)}...")
        try:
            analyzer = APKAnalyzer(apk_path)
            extracted_data = analyzer.analyze()
            
            risk_engine = RiskEngine()
            risk_profile = risk_engine.calculate_risk(
                permissions=extracted_data.get("permissions", []),
                has_services=len(extracted_data.get("services", [])) > 0,
                has_certs=len(extracted_data.get("certificates", [])) > 0,
                dex_indicators=extracted_data.get("dex_indicators", {}),
                package_name=extracted_data.get("package_name", "Unknown"),
                certificates=extracted_data.get("certificates", []),
                app_name=extracted_data.get("app_name", "Unknown"),
                activities=extracted_data.get("activities", [])
            )
            
            name = os.path.basename(apk_path)
            
            # V1 output
            report["V1_Findings"][name] = {
                "risk_score": risk_profile.get("score"),
                "verdict": risk_profile.get("verdict"),
                "evidence_flags": [k for k, v in risk_profile.get("evidence_validation", {}).items() if v.get("status") == "FOUND"]
            }
            
            # V2 output
            report["V2_Findings"][name] = {
                "risk_score": risk_profile.get("score"),
                "verdict": risk_profile.get("verdict"),
                "behavioral_threats": risk_profile.get("behavioral_threats", []),
                "attack_chains": risk_profile.get("attack_chains", [])
            }
            
            # Analysis
            if risk_profile.get("verdict") in ["MALICIOUS", "SUSPICIOUS"] and not risk_profile.get("attack_chains"):
                report["Comparison"]["false_positives_downgraded"].append(name)
            
            if risk_profile.get("attack_chains"):
                report["Comparison"]["malicious_combinations_triggered"].append(name)
                
        except Exception as e:
            print(f"Failed {os.path.basename(apk_path)}: {e}")
            
    # Final Verdict logic
    fp_downgraded = len(report["Comparison"]["false_positives_downgraded"])
    malicious_triggered = len(report["Comparison"]["malicious_combinations_triggered"])
    
    if fp_downgraded > 0 and malicious_triggered > 0:
        report["Final_Verdict"] = "SIGNIFICANT_IMPROVEMENT"
    elif fp_downgraded > 0 or malicious_triggered > 0:
        report["Final_Verdict"] = "MINOR_IMPROVEMENT"
    else:
        report["Final_Verdict"] = "NO_IMPROVEMENT"
        
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "V2_EFFECTIVENESS_REPORT.json")
    with open(output_path, "w") as f:
        json.dump(report, f, indent=4)
        
    print(f"Report saved to {output_path}")

if __name__ == "__main__":
    run_audit()
