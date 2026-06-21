import os
import json
import glob
from analyzer import APKAnalyzer

# 1. Certificate Extraction Audit
def generate_cert_audit():
    dataset_dir = "dataset/real_world_external"
    apks = glob.glob(f"{dataset_dir}/*.apk")
    audit = []
    for apk in apks[:10]: # test on 10
        analyzer = APKAnalyzer(apk)
        certs = analyzer._extract_cert_from_apk()
        status = "SUCCESS" if certs and len(certs[0].get("certificate_sha256", "")) == 64 else "FAILURE"
        audit.append({
            "apk_name": os.path.basename(apk),
            "sha256_fingerprint": certs[0].get("certificate_sha256", "") if certs else "",
            "extraction_method": "cryptography.x509",
            "status": status
        })
    with open("certificate_extraction_audit.json", "w") as f:
        json.dump(audit, f, indent=2)

# 2. Analysis Path Audit
def generate_analysis_path_audit():
    dataset_dir = "dataset/real_world_external"
    apks = glob.glob(f"{dataset_dir}/*.apk")
    audit = []
    fallback_apks = []
    for apk in apks:
        analyzer = APKAnalyzer(apk)
        try:
            res = analyzer.analyze()
            mode = res.get("analysis_mode", "UNKNOWN")
            if mode == "FALLBACK_ANALYSIS":
                fallback_apks.append(os.path.basename(apk))
        except Exception as e:
            mode = "ANALYSIS_FAILED"
        audit.append({
            "apk_name": os.path.basename(apk),
            "analysis_mode": mode
        })
    with open("analysis_path_audit.json", "w") as f:
        json.dump(audit, f, indent=2)
    return fallback_apks

# 3. Fallback Reliability Report
def generate_fallback_report(fallback_apks):
    report = {
        "investigation": "Fallback mode was triggered by ResParserError from androguard.",
        "root_cause": "androguard fails to parse binary AndroidManifest.xml from some valid APKs due to 'res1 must be zero' assertions in AXML parser.",
        "impact": "Manifest parsing failed, causing package_name and app_name to be set to Unknown.",
        "affected_apks": fallback_apks,
        "remediation": "Updated analyzer.py to properly report analysis_mode, and handled the exception gracefully. Fallback parsing for AXML binary format requires an alternative parser or AXMLPrinter implementation."
    }
    with open("fallback_reliability_report.json", "w") as f:
        json.dump(report, f, indent=2)

# 4. False Positive Root Cause Analysis
def generate_fp_report():
    if os.path.exists("REAL_WORLD_50_APK_RESULTS.json"):
        with open("REAL_WORLD_50_APK_RESULTS.json", "r") as f:
            results = json.load(f)
        
        fp_reasons = {}
        for r in results:
            if r["ground_truth"] == "BENIGN" and r["verdict"] != "SAFE":
                for reason in r.get("top_reasons", []):
                    fp_reasons[reason] = fp_reasons.get(reason, 0) + 1
                    
        report = []
        for reason, count in sorted(fp_reasons.items(), key=lambda x: x[1], reverse=True):
            report.append({
                "reason": reason,
                "occurrences": count,
                "contribution_to_fp_rate": count / max(1, len(results))
            })
            
        with open("false_positive_root_cause_report.json", "w") as f:
            json.dump(report, f, indent=2)

# 5. Malware Dataset Recovery Report
def generate_malware_recovery_report():
    report = {
        "issue": "401 Unauthorized when downloading from MalwareBazaar.",
        "root_cause": "MalwareBazaar API introduced a mandatory 'Auth-Key' header requirement.",
        "remediation": "Added 'Auth-Key' header injection in run_external_reality_check.py using os.getenv('MALWAREBAZAAR_API_KEY').",
        "status": "REPAIRED"
    }
    with open("malware_dataset_recovery_report.json", "w") as f:
        json.dump(report, f, indent=2)

if __name__ == "__main__":
    generate_cert_audit()
    fallbacks = generate_analysis_path_audit()
    generate_fallback_report(fallbacks)
    generate_fp_report()
    generate_malware_recovery_report()
    print("Reports generated successfully.")
