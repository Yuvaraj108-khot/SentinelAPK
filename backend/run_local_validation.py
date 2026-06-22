import os
import json
import hashlib
import traceback
from analyzer import APKAnalyzer
from risk_engine import RiskEngine

def compute_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def run_validation():
    target_dir = os.path.join(os.path.dirname(__file__), "dataset", "real_world_external")
    
    analysis_results = []
    validation_summary = {
        "total_analyzed": 0,
        "malicious_count": 0,
        "suspicious_count": 0,
        "safe_count": 0,
        "failed_count": 0,
        "failures": []
    }
    evidence_report = []

    if not os.path.exists(target_dir):
        print(f"Directory {target_dir} does not exist.")
        return

    apk_files = [f for f in os.listdir(target_dir) if f.endswith(".apk")]
    print(f"Found {len(apk_files)} APKs to analyze.")

    for filename in apk_files:
        print(f"Analyzing {filename}...")
        filepath = os.path.join(target_dir, filename)
        sha256 = compute_sha256(filepath)
        
        try:
            analyzer = APKAnalyzer(filepath)
            metadata = analyzer.analyze()
            
            has_services = len(metadata.get("services", [])) > 0
            has_certs = len(metadata.get("certificates", [])) > 0
            
            risk_data = RiskEngine.calculate_risk(
                metadata.get("permissions", []), 
                has_services, 
                has_certs, 
                metadata.get("dex_indicators"),
                metadata.get("package_name", "Unknown"),
                metadata.get("certificates", []),
                metadata.get("app_name", "Unknown"),
                metadata.get("activities", [])
            )
            
            # Extract required fields
            verdict = risk_data.get("verdict", "UNKNOWN")
            risk_score = risk_data.get("score", 0)
            cert_status = risk_data.get("evidence_validation", {}).get("certificate_validation", {}).get("status", "UNKNOWN")
            clone_status = risk_data.get("evidence_validation", {}).get("clone_detection", {}).get("status", "UNKNOWN")
            mitre_mappings = risk_data.get("mitre_techniques", [])
            evidence = risk_data.get("evidence_validation", {})
            
            result_entry = {
                "filename": filename,
                "sha256": sha256,
                "risk_score": risk_score,
                "verdict": verdict,
                "certificate_status": cert_status,
                "clone_detection": clone_status,
                "evidence_validation": evidence,
                "mitre_mappings": mitre_mappings
            }
            analysis_results.append(result_entry)
            
            evidence_report.append({
                "filename": filename,
                "sha256": sha256,
                "evidence": evidence
            })
            
            validation_summary["total_analyzed"] += 1
            if verdict == "MALICIOUS":
                validation_summary["malicious_count"] += 1
            elif verdict == "SUSPICIOUS":
                validation_summary["suspicious_count"] += 1
            elif verdict == "SAFE":
                validation_summary["safe_count"] += 1
                
        except Exception as e:
            print(f"Error analyzing {filename}: {e}")
            validation_summary["failed_count"] += 1
            validation_summary["failures"].append({"filename": filename, "error": str(e), "traceback": traceback.format_exc()})
            
    # Write outputs
    base_dir = os.path.dirname(__file__)
    
    with open(os.path.join(base_dir, "ANALYSIS_RESULTS.json"), "w", encoding="utf-8") as f:
        json.dump(analysis_results, f, indent=4)
        
    with open(os.path.join(base_dir, "VALIDATION_SUMMARY.json"), "w", encoding="utf-8") as f:
        json.dump(validation_summary, f, indent=4)
        
    with open(os.path.join(base_dir, "EVIDENCE_REPORT.json"), "w", encoding="utf-8") as f:
        json.dump(evidence_report, f, indent=4)
        
    print("Validation complete. Reports generated.")

if __name__ == "__main__":
    run_validation()
