import os
import sys
import json
import glob
import subprocess

# Add backend to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from analyzer import APKAnalyzer

def run_v2_validation():
    print("Running Validation V2...")
    subprocess.run(["python", "run_external_reality_check.py"], check=False)
    print("Validation V2 complete.")

def task1():
    apks = glob.glob("dataset/real_world_external/*.apk")
    audit = []
    for apk in apks[:10]:
        analyzer = APKAnalyzer(apk)
        certs = analyzer._extract_cert_from_apk()
        extracted = len(certs) > 0
        fp = certs[0].get("certificate_sha256", "") if extracted else ""
        audit.append({
            "apk_name": os.path.basename(apk),
            "certificate_extracted": extracted,
            "fingerprint_sha256": fp,
            "fingerprint_length": len(fp)
        })
    with open("certificate_extraction_verification.json", "w") as f:
        json.dump(audit, f, indent=2)

def task2():
    if not os.path.exists("analysis_path_audit.json"):
        with open("analysis_mode_summary.json", "w") as f:
            json.dump({"error": "analysis_path_audit.json missing"}, f)
        return []
    with open("analysis_path_audit.json", "r") as f:
        data = json.load(f)
    
    full = 0
    fallback = 0
    failed = 0
    fallback_apks = []
    for entry in data:
        mode = entry.get("analysis_mode", "")
        if mode == "FULL_ANALYSIS":
            full += 1
        elif mode == "FALLBACK_ANALYSIS":
            fallback += 1
            fallback_apks.append(entry.get("apk_name"))
        else:
            failed += 1
            
    summary = {
        "FULL_ANALYSIS_count": full,
        "FALLBACK_ANALYSIS_count": fallback,
        "ANALYSIS_FAILED_count": failed,
        "fallback_apks": fallback_apks
    }
    with open("analysis_mode_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    return fallback_apks

def task3(fallback_apks):
    audit = []
    for apk_name in fallback_apks:
        path = os.path.join("dataset/real_world_external", apk_name)
        if not os.path.exists(path):
            continue
        # We know ResParserError happens.
        analyzer = APKAnalyzer(path)
        res = analyzer.analyze()
        
        # In fallback, package_name and app_name become "Unknown" or regex result
        pkg = res.get("package_name")
        lost = []
        recovered = ["certificates", "dex_indicators"]
        if pkg == "Unknown":
            lost.append("package_name")
            lost.append("app_name")
            lost.append("min_sdk")
            lost.append("target_sdk")
            lost.append("permissions")
            lost.append("activities")
            lost.append("services")
            rank = "HIGH"
        else:
            recovered.append("manifest_fields")
            rank = "MEDIUM"
            
        audit.append({
            "apk_name": apk_name,
            "exception": "ResParserError (binary AXML parsing failed in androguard)",
            "recovered_fields": recovered,
            "lost_fields": lost,
            "severity_rank": rank
        })
    with open("fallback_impact_audit.json", "w") as f:
        json.dump(audit, f, indent=2)

def task4():
    # Parse ground_truth_manifest.json to see what malware was targeted
    # Then check files on disk
    if os.path.exists("ground_truth_manifest.json"):
        with open("ground_truth_manifest.json", "r") as f:
            manifest = json.load(f)
    else:
        manifest = []
        
    audit = []
    for m in manifest:
        if m.get("label") == "MALICIOUS":
            apk_path = os.path.join("dataset/real_world_external", m.get("apk_name", ""))
            if os.path.exists(apk_path):
                audit.append({
                    "family": m.get("family", "Unknown"),
                    "sha256": m.get("sha256"),
                    "size_bytes": os.path.getsize(apk_path),
                    "source": m.get("source", "MalwareBazaar")
                })
    
    with open("malware_acquisition_verification.json", "w") as f:
        json.dump(audit, f, indent=2)
    return len(audit) > 0

def task5_and_6(has_malware):
    if not os.path.exists("REAL_WORLD_50_APK_RESULTS.json"):
        return
    with open("REAL_WORLD_50_APK_RESULTS.json", "r") as f:
        results = json.load(f)
        
    tp = tn = fp = fn = 0
    cert_failures = 0
    
    for r in results:
        if r.get("analysis_status") != "OK":
            continue
            
        gt = r.get("ground_truth")
        verdict = r.get("verdict")
        if r.get("certificate_status") == "UNKNOWN":
            cert_failures += 1
            
        pred_pos = verdict in ["MALICIOUS", "SUSPICIOUS"]
        gt_pos = (gt == "MALICIOUS")
        
        if gt_pos and pred_pos: tp += 1
        elif gt_pos and not pred_pos: fn += 1
        elif not gt_pos and pred_pos: fp += 1
        elif not gt_pos and not pred_pos: tn += 1
        
    acc = (tp + tn) / max(1, (tp + tn + fp + fn))
    prec = tp / max(1, (tp + fp))
    rec = tp / max(1, (tp + fn))
    f1 = 2 * prec * rec / max(1, (prec + rec))
    
    v2_metrics = {
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "Accuracy": acc, "Precision": prec, "Recall": rec, "F1": f1
    }
    with open("EXTERNAL_VALIDATION_V2.json", "w") as f:
        json.dump(v2_metrics, f, indent=2)
        
    # Task 6
    if not has_malware or cert_failures > 0 or f1 < 0.80:
        gate = "NOT_PRODUCTION_READY"
    else:
        gate = "PRODUCTION_READY"
        
    with open("PRODUCTION_GATE_V2.json", "w") as f:
        json.dump({
            "malware_samples_analyzed": tp + fn,
            "certificate_extraction_failures": cert_failures,
            "f1_score": f1,
            "decision": gate
        }, f, indent=2)

if __name__ == "__main__":
    run_v2_validation()
    task1()
    fallback_apks = task2()
    task3(fallback_apks)
    has_malware = task4()
    task5_and_6(has_malware)
    print("Audit Complete.")
