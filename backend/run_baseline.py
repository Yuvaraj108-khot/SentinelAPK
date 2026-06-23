import json
import os
import sys

# Add current dir to path to import main
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# from main import analyze_apk

def generate_baseline():
    dataset_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")
    apks_to_test = [
        os.path.join(dataset_dir, "train", "benign", "SecureBank_Official.apk"),
        os.path.join(dataset_dir, "train", "suspicious", "SecureBank_Plus.apk"),
        os.path.join(dataset_dir, "train", "suspicious", "SecureBank_Clone.apk")
    ]
    
    baseline = {}
    
    for apk_path in apks_to_test:
        if not os.path.exists(apk_path):
            print(f"Error: {apk_path} not found.")
            continue
            
        print(f"Analyzing {os.path.basename(apk_path)}...")
        
        # We need to capture the dict output of the engine.
        # analyze_apk writes to PDF/JSON but also returns the risk_profile dict.
        # Wait, let's look at main.py to see how analyze_apk is defined.
        # It's an async FastAPI endpoint or a CLI command? It might be CLI.
        # Let's import the Analyzer and Risk Engine directly.
        from analyzer import APKAnalyzer
        from risk_engine import RiskEngine
        
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
        baseline[name] = {
            "risk_score": risk_profile.get("score"),
            "verdict": risk_profile.get("verdict"),
            "certificate_status": risk_profile.get("cert_findings", {}).get("status"),
            "clone_risk": risk_profile.get("clone_findings", {}).get("clone_risk"),
            "evidence_validation": risk_profile.get("evidence_validation", {}),
            "mitre": risk_profile.get("mitre_techniques", [])
        }
        
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PRE_INTEGRATION_BASELINE.json")
    with open(output_path, "w") as f:
        json.dump(baseline, f, indent=4)
        
    print(f"Baseline saved to {output_path}")

if __name__ == "__main__":
    generate_baseline()
