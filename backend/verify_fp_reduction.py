import os
import json
import shutil
import hashlib
from risk_engine import RiskEngine
from analyzer import APKAnalyzer

def main():
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    vendors_file = os.path.join(backend_dir, "data", "security_vendors.json")
    backup_vendors_file = os.path.join(backend_dir, "data", "security_vendors.json.bak")
    
    # ----------------------------------------------------
    # TASK 4: security_vendor_validation.json
    # ----------------------------------------------------
    print("=== TASK 4: Running Security Vendor Validation ===")
    
    # Security app profiles to test
    security_profiles = [
        {
            "id": "bitdefender",
            "name": "Bitdefender",
            "package": "com.bitdefender.security",
            "permissions": ["android.permission.INTERNET", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
            "cert_sha256": "bc23de45fg678901"
        },
        {
            "id": "avast",
            "name": "Avast",
            "package": "com.avast.android.mobilesecurity",
            "permissions": ["android.permission.INTERNET", "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"],
            "cert_sha256": "cd34ef56gh789012"
        },
        {
            "id": "malwarebytes",
            "name": "Malwarebytes",
            "package": "org.malwarebytes.antimalware",
            "permissions": ["android.permission.INTERNET", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
            "cert_sha256": "de45fg67hi890123"
        }
    ]
    
    # 1. Run WITHOUT security vendor recognition (Before)
    if os.path.exists(vendors_file):
        shutil.move(vendors_file, backup_vendors_file)
        
    before_results = {}
    for p in security_profiles:
        certs = [{"issuer": f"CN={p['name']}", "sha256": p["cert_sha256"]}]
        risk = RiskEngine.calculate_risk(
            permissions=p["permissions"],
            has_services=True,
            has_certs=True,
            dex_indicators={},
            package_name=p["package"],
            certificates=certs,
            app_name=p["name"]
        )
        before_results[p["id"]] = risk
        
    # 2. Run WITH security vendor recognition (After)
    if os.path.exists(backup_vendors_file):
        shutil.move(backup_vendors_file, vendors_file)
        
    after_results = {}
    for p in security_profiles:
        certs = [{"issuer": f"CN={p['name']}", "sha256": p["cert_sha256"]}]
        risk = RiskEngine.calculate_risk(
            permissions=p["permissions"],
            has_services=True,
            has_certs=True,
            dex_indicators={},
            package_name=p["package"],
            certificates=certs,
            app_name=p["name"]
        )
        after_results[p["id"]] = risk
        
    # Compile validation data
    vendor_val = {
        "status": "PASS",
        "comparisons": {}
    }
    for p in security_profiles:
        b = before_results[p["id"]]
        a = after_results[p["id"]]
        print(f"Vendor {p['name']}: Before Score={b['score']} ({b['verdict']}) -> After Score={a['score']} ({a['verdict']})")
        
        vendor_val["comparisons"][p["id"]] = {
            "name": p["name"],
            "before": {"score": b["score"], "verdict": b["verdict"]},
            "after": {"score": a["score"], "verdict": a["verdict"]},
            "fp_reduced": a["verdict"] == "SAFE"
        }
        if a["verdict"] != "SAFE":
            vendor_val["status"] = "FAIL"
            
    with open(os.path.join(backend_dir, "security_vendor_validation.json"), "w") as f:
        json.dump(vendor_val, f, indent=2)
    print("Saved security_vendor_validation.json")
    
    # ----------------------------------------------------
    # TASK 5: Regression Audit
    # ----------------------------------------------------
    print("\n=== TASK 5: Running Regression Audit ===")
    
    # Trojan app profiles matching standard training dataset
    trojan_profiles = [
        {
            "id": "securebank_clone",
            "name": "SecureBank Clone",
            "package": "com.securebank.official",
            "permissions": ["android.permission.INTERNET"],
            "cert_sha256": "secureBankRepackagedMaliciousCode", # Mismatched cert
            "expected_verdicts": ["SUSPICIOUS", "MALICIOUS"]
        },
        {
            "id": "securebank_plus",
            "name": "SecureBank Plus",
            "package": "com.securebank.plus",
            "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"],
            "cert_sha256": "secureBankOverlayVerification",
            "expected_verdicts": ["SUSPICIOUS", "MALICIOUS"]
        },
        {
            "id": "fake_sbi_login",
            "name": "Yono SBI Rewards Hub",
            "package": "com.sbi.yono.rewards.hub",
            "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"],
            "cert_sha256": "SHA256:FF:EE:DD", # Untrusted
            "expected_verdicts": ["SUSPICIOUS", "MALICIOUS"]
        },
        {
            "id": "overlay_trojan",
            "name": "Flash Player Update",
            "package": "com.adobe.flash.update",
            "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.READ_SMS"],
            "cert_sha256": "SHA256:FF:EE:DD", # Untrusted
            "expected_verdicts": ["SUSPICIOUS", "MALICIOUS"]
        },
        {
            "id": "banking_cred_stealer",
            "name": "Chrome Update Service",
            "package": "com.android.chrome.services",
            "permissions": ["android.permission.INTERNET", "android.permission.READ_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
            "cert_sha256": "SHA256:FF:EE:DD", # Untrusted
            "expected_verdicts": ["SUSPICIOUS", "MALICIOUS"]
        }
    ]
    
    regression_report = {
        "status": "PASS",
        "trojans_audited": {}
    }
    
    for t in trojan_profiles:
        # Derive SHA256 bytes for mock zip if needed, but calculate_risk takes certificates list directly
        certs = [{"issuer": "CN=Android Debug", "sha256": hashlib.sha256(t["cert_sha256"].encode()).hexdigest() if len(t["cert_sha256"]) < 32 else t["cert_sha256"]}]
        
        # Run risk check
        risk = RiskEngine.calculate_risk(
            permissions=t["permissions"],
            has_services=True,
            has_certs=True,
            dex_indicators={},
            package_name=t["package"],
            certificates=certs,
            app_name=t["name"]
        )
        
        print(f"Trojan {t['name']}: Score={risk['score']} ({risk['verdict']})")
        retains = risk["verdict"] in t["expected_verdicts"]
        
        regression_report["trojans_audited"][t["id"]] = {
            "name": t["name"],
            "verdict": risk["verdict"],
            "score": risk["score"],
            "classification_retained": retains
        }
        if not retains:
            regression_report["status"] = "FAIL"
            
    with open(os.path.join(backend_dir, "false_positive_reduction_report.json"), "w") as f:
        json.dump(regression_report, f, indent=2)
    print("Saved false_positive_reduction_report.json")
    
    # ----------------------------------------------------
    # FINAL PASS CONDITION VERIFICATION
    # ----------------------------------------------------
    overall_pass = vendor_val["status"] == "PASS" and regression_report["status"] == "PASS"
    print(f"\nFinal Campaign Verdict: {'PASS' if overall_pass else 'FAIL'}")

if __name__ == "__main__":
    main()
