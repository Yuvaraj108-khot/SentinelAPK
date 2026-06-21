import os
import json
from risk_engine import RiskEngine

def run_case(permissions, dex_indicators, certificates, package_name, app_name):
    risk = RiskEngine.calculate_risk(
        permissions=permissions,
        has_services=True,
        has_certs=True,
        dex_indicators=dex_indicators,
        package_name=package_name,
        certificates=certificates,
        app_name=app_name
    )
    
    score_breakdown = {}
    for r in risk["triggered_rules"]:
        score_breakdown[r["permission"]] = r["weight"]
        
    return {
        "score": risk["score"],
        "verdict": risk["verdict"],
        "score_breakdown": score_breakdown
    }

def main():
    trusted_cert = [{"issuer": "CN=SecureBank Official", "sha256": "86f71bae47be40288086f28795563ba741a101ad98387cc934e1b68bfee539fa"}]
    untrusted_cert = [{"issuer": "CN=Android Debug", "sha256": "completely_untrusted_signature_fingerprint"}]
    
    cases = {}
    
    # Case 1: No permissions, No DEX indicators, Trusted certificate
    cases["case_1"] = run_case([], {}, trusted_cert, "com.legit.app", "Legit App")
    
    # Case 2: SYSTEM_ALERT_WINDOW only
    cases["case_2"] = run_case(["android.permission.SYSTEM_ALERT_WINDOW"], {}, trusted_cert, "com.legit.app", "Legit App")
    
    # Case 3: BIND_ACCESSIBILITY_SERVICE only
    cases["case_3"] = run_case(["android.permission.BIND_ACCESSIBILITY_SERVICE"], {}, trusted_cert, "com.legit.app", "Legit App")
    
    # Case 4: READ_SMS only
    cases["case_4"] = run_case(["android.permission.READ_SMS"], {}, trusted_cert, "com.legit.app", "Legit App")
    
    # Case 5: Runtime.exec only
    cases["case_5"] = run_case([], {"runtime_exec": True, "evidence": {"runtime_exec": {"matched_string": "exec", "source_file": "classes.dex"}}}, trusted_cert, "com.legit.app", "Legit App")
    
    # Case 6: DexClassLoader only
    cases["case_6"] = run_case([], {"dex_class_loader": True, "evidence": {"dex_class_loader": {"matched_string": "DexClassLoader", "source_file": "classes.dex"}}}, trusted_cert, "com.legit.app", "Legit App")
    
    # Case 7: UnknownCertificate only
    cases["case_7"] = run_case([], {}, untrusted_cert, "com.legit.app", "Legit App")
    
    # Case 8: Clone detection only
    cases["case_8"] = run_case([], {}, trusted_cert, "com.securebank.fake", "SecureBank Official")
    
    # Case 9: Clone + UnknownCertificate
    cases["case_9"] = run_case([], {}, untrusted_cert, "com.securebank.fake", "SecureBank Official")
    
    # Case 10: All indicators enabled
    all_dex = {
        "runtime_exec": True,
        "dex_class_loader": True,
        "evidence": {
            "runtime_exec": {"matched_string": "exec", "source_file": "classes.dex"},
            "dex_class_loader": {"matched_string": "DexClassLoader", "source_file": "classes.dex"}
        }
    }
    cases["case_10"] = run_case(
        ["android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.READ_SMS"],
        all_dex,
        untrusted_cert,
        "com.securebank.fake",
        "SecureBank Official"
    )
    
    report = {
        "matrix": cases
    }
    
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(backend_dir, "feature_sensitivity_audit.json"), "w") as f:
        json.dump(report, f, indent=2)
        
    print(json.dumps(report, indent=2))
    print("\nGenerated feature_sensitivity_audit.json")

if __name__ == "__main__":
    main()
