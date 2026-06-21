import sys
import os

# Set backend directory on path
sys.path.append(os.path.dirname(__file__))

from risk_engine import RiskEngine
from llm_client import LLMClient

def test_risk_calculations():
    print("Testing Risk Calculations...")
    
    # 1. Test Malicious App Permissions
    permissions = [
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.INTERNET"
    ]
    
    risk_result = RiskEngine.calculate_risk(permissions, has_services=True, has_certs=True)
    print(f"Calculated Score: {risk_result['score']}/100")
    print(f"Verdict: {risk_result['verdict']}")
    print(f"Confidence: {risk_result['confidence']}%")
    print(f"Severity: {risk_result['severity']}")
    
    assert risk_result['score'] >= 65
    assert risk_result['verdict'] in ["SUSPICIOUS", "MALICIOUS"]
    assert risk_result['confidence'] >= 90
    print("Test passed successfully!\n")

def test_llm_fallback():
    print("Testing Explainable AI Heuristics Fallback...")
    
    metadata = {
        "app_name": "Test Banking App Overlay",
        "package_name": "com.fraud.overlay.bank",
        "permissions": [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.INTERNET"
        ]
    }
    
    risk_result = RiskEngine.calculate_risk(metadata["permissions"], has_services=True, has_certs=True)
    
    llm_client = LLMClient()
    ai_result = llm_client.analyze_apk(metadata, risk_result)
    
    print("AI Analysis Output:")
    print(f"Suspicious Permissions Rationale: {ai_result.get('suspicious_permissions_rationale')}")
    print(f"OTP Interception: {ai_result.get('otp_theft_capability')}")
    print(f"Accessibility Abuse: {ai_result.get('accessibility_abuse')}")
    print(f"Impersonation Risk: {ai_result.get('impersonation_risk')}")
    print(f"Data Exfiltration: {ai_result.get('data_exfiltration')}")
    print(f"Verdict Reasoning: {ai_result.get('verdict_reasoning')}")
    
    assert "ACCESSIBILITY" in ai_result.get('accessibility_abuse').upper()
    print("AI Fallback passed successfully!\n")

if __name__ == "__main__":
    try:
        test_risk_calculations()
        test_llm_fallback()
        print("All local checks passed!")
    except Exception as e:
        print(f"Test failure: {e}")
        sys.exit(1)
