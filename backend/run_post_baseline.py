import json
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def generate_post_baseline():
    dataset_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")
    apks_to_test = [
        os.path.join(dataset_dir, "train", "benign", "SecureBank_Official.apk"),
        os.path.join(dataset_dir, "train", "suspicious", "SecureBank_Plus.apk"),
        os.path.join(dataset_dir, "train", "suspicious", "SecureBank_Clone.apk")
    ]
    
    post_results = {}
    
    from analyzer import APKAnalyzer
    from risk_engine import RiskEngine
    
    for apk_path in apks_to_test:
        if not os.path.exists(apk_path):
            continue
            
        print(f"Analyzing post-integration: {os.path.basename(apk_path)}...")
        
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
        post_results[name] = {
            "risk_score": risk_profile.get("score"),
            "verdict": risk_profile.get("verdict"),
            "certificate_status": risk_profile.get("cert_findings", {}).get("status"),
            "clone_risk": risk_profile.get("clone_findings", {}).get("clone_risk"),
            "evidence_validation": risk_profile.get("evidence_validation", {}),
            "mitre": risk_profile.get("mitre_techniques", []),
            "behavioral_threats": risk_profile.get("behavioral_threats", []),
            "attack_chains": risk_profile.get("attack_chains", []),
            "analysis_version": risk_profile.get("analysis_version")
        }
        
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "POST_INTEGRATION_RESULTS.json")
    with open(output_path, "w") as f:
        json.dump(post_results, f, indent=4)
        
    print(f"Post results saved to {output_path}")
    return post_results

def verify_integration(post_results):
    baseline_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PRE_INTEGRATION_BASELINE.json")
    with open(baseline_path, "r") as f:
        pre_results = json.load(f)
        
    diff_report = {}
    verdict_failed = False
    
    for app_name, pre in pre_results.items():
        post = post_results.get(app_name, {})
        
        diff_report[app_name] = {
            "risk_score_match": pre["risk_score"] == post.get("risk_score"),
            "verdict_match": pre["verdict"] == post.get("verdict"),
            "clone_risk_match": pre["clone_risk"] == post.get("clone_risk"),
            "certificate_status_match": pre["certificate_status"] == post.get("certificate_status"),
            "evidence_validation_match": pre["evidence_validation"] == post.get("evidence_validation")
        }
        
        if not all(diff_report[app_name].values()):
            verdict_failed = True

    diff_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "V1_VS_V2_DIFF_REPORT.json")
    with open(diff_path, "w") as f:
        json.dump(diff_report, f, indent=4)
        
    print("V1 vs V2 rules validation complete.")
    
    integration_report = {
        "status": "ACTIVE_IN_PIPELINE" if not verdict_failed else "INTEGRATION_FAILED",
        "diff_verification_passed": not verdict_failed
    }
    
    rep_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "V2_INTEGRATION_REPORT.json")
    with open(rep_path, "w") as f:
        json.dump(integration_report, f, indent=4)
        
    print(f"Integration Report: {integration_report['status']}")

if __name__ == "__main__":
    res = generate_post_baseline()
    verify_integration(res)
