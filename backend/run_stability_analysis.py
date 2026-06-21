import os
import json
import hashlib
from risk_engine import RiskEngine

def get_cert_hash(raw_text: str) -> str:
    return hashlib.sha256(raw_text.encode()).hexdigest()

def analyze_app(name, package, permissions, cert_sha256, app_label):
    certs = [{"issuer": "CN=Android Debug", "sha256": cert_sha256}]
    if name == "SecureBank Official":
        certs[0]["issuer"] = "CN=SecureBank Official, O=SecureBank, C=US"
        
    risk = RiskEngine.calculate_risk(
        permissions=permissions,
        has_services=True,
        has_certs=True,
        dex_indicators={},
        package_name=package,
        certificates=certs,
        app_name=app_label
    )
    return risk

def get_verdict(score):
    if score >= 70:
        return "MALICIOUS"
    elif score >= 35:
        return "SUSPICIOUS"
    else:
        return "SAFE"

def main():
    # Boundaries
    # SAFE -> SUSPICIOUS = 35 (Note: risk_engine has SAFE if score < 35, SUSPICIOUS if score >= 35)
    # SUSPICIOUS -> MALICIOUS = 65 (Note: risk_engine has SUSPICIOUS if score < 70, MALICIOUS if score >= 70, let's use the user's defined boundaries: 35 and 65)
    
    profiles = {
        "Bitdefender": {
            "package": "com.bitdefender.security",
            "permissions": ["android.permission.INTERNET", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
            "cert_sha256": "bc23de45fg678901",
            "label": "Bitdefender Mobile Security"
        },
        "Avast": {
            "package": "com.avast.android.mobilesecurity",
            "permissions": ["android.permission.INTERNET", "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"],
            "cert_sha256": "cd34ef56gh789012",
            "label": "Avast Antivirus & Security"
        },
        "Malwarebytes": {
            "package": "org.malwarebytes.antimalware",
            "permissions": ["android.permission.INTERNET", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
            "cert_sha256": "de45fg67hi890123",
            "label": "Malwarebytes Mobile Security"
        },
        "SecureBank Official": {
            "package": "com.securebank.official",
            "permissions": ["android.permission.INTERNET"],
            "cert_sha256": "86f71bae47be40288086f28795563ba741a101ad98387cc934e1b68bfee539fa",
            "label": "SecureBank Official"
        },
        "SecureBank Plus": {
            "package": "com.securebank.plus",
            "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"],
            "cert_sha256": get_cert_hash("secureBankOverlayVerification"),
            "label": "SecureBank Plus"
        },
        "SecureBank Clone": {
            "package": "com.securebank.official",
            "permissions": ["android.permission.INTERNET"],
            "cert_sha256": get_cert_hash("secureBankRepackagedMaliciousCode"),
            "label": "SecureBank Clone"
        }
    }
    
    report = {
        "stability_analysis": {}
    }
    
    for name, p in profiles.items():
        risk = analyze_app(name, p["package"], p["permissions"], p["cert_sha256"], p["label"])
        current_score = risk["score"]
        current_verdict = get_verdict(current_score)
        
        # Calculate sensitivity score:
        # Accessibility weight +5
        # Overlay weight +5
        # Certificate weight +5
        # Memory influence +10% (we add 10 points to simulate +10% score shift if memory is active/influenced)
        sensitivity_score = current_score
        
        has_acc = "android.permission.BIND_ACCESSIBILITY_SERVICE" in p["permissions"]
        has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in p["permissions"]
        
        # In risk_engine, if it's a clone SamePkgForgery is applied (not UnknownCertificate)
        # Check certificate status
        is_untrusted = risk["cert_findings"]["status"] == "UNTRUSTED"
        
        if has_acc:
            sensitivity_score += 5
        if has_overlay:
            sensitivity_score += 5
        if is_untrusted:
            sensitivity_score += 5
            
        # Add 10 points for memory influence if lessons are active
        if len(risk["retrieved_lessons"]) > 0:
            sensitivity_score += 10
            
        sensitivity_score = min(100, sensitivity_score)
        sensitivity_verdict = get_verdict(sensitivity_score)
        
        # Flag if within 10 points of any boundary: 35 or 65
        # Meaning: |score - 35| <= 10 or |score - 65| <= 10
        near_35 = abs(current_score - 35) <= 10
        near_65 = abs(current_score - 65) <= 10
        fragile = near_35 or near_65 or (current_verdict != sensitivity_verdict)
        
        report["stability_analysis"][name.lower().replace(" ", "_")] = {
            "current_score": current_score,
            "current_verdict": current_verdict,
            "sensitivity_score": sensitivity_score,
            "sensitivity_verdict": sensitivity_verdict,
            "stable": not fragile,
            "boundary_warning": fragile,
            "distance_to_35": abs(current_score - 35),
            "distance_to_65": abs(current_score - 65)
        }
        
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(backend_dir, "threshold_stability_report.json"), "w") as f:
        json.dump(report, f, indent=2)
        
    print(json.dumps(report, indent=2))
    print("\nGenerated threshold_stability_report.json")

if __name__ == "__main__":
    main()
