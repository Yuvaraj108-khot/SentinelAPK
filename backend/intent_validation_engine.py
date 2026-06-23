from typing import Dict, Any, List

class IntentValidationEngine:
    """
    Validates whether extracted evidence actually supports malicious intent.
    Addresses the flaw where capabilities alone (like SMS) are treated as malware signatures.
    """
    
    @staticmethod
    def evaluate(evidence_validation: Dict[str, Any]) -> Dict[str, Any]:
        intent = "BENIGN"
        confidence = 0.5
        supporting_evidence = []
        
        # Check for explicit credential collection or phishing indicators
        overlay_evidence = evidence_validation.get("overlay", {})
        sms_evidence = evidence_validation.get("sms", {})
        
        # If we just see basic permission tags, that's capability, not intent.
        # But if we see specific code strings related to parsing OTPs from SMS providers
        # or injecting webviews for banking, that's malicious intent.
        
        has_suspicious_sms_regex = False
        if sms_evidence.get("status") == "FOUND" and "regex" in str(sms_evidence.get("matched_string", "")).lower():
            has_suspicious_sms_regex = True
            
        has_phishing_overlay = False
        if overlay_evidence.get("status") == "FOUND" and "phishing" in str(overlay_evidence.get("matched_string", "")).lower():
            has_phishing_overlay = True

        if has_suspicious_sms_regex or has_phishing_overlay:
            intent = "MALICIOUS"
            confidence = 0.9
            if has_suspicious_sms_regex:
                supporting_evidence.append("Explicit SMS OTP extraction regex detected in code.")
            if has_phishing_overlay:
                supporting_evidence.append("Overlay evidence points to phishing payload rather than generic window.")
        else:
            intent = "BENIGN_CAPABILITY"
            confidence = 0.8
            supporting_evidence.append("Capabilities detected but no explicit malicious payload or extraction logic found.")
            
        return {
            "intent": intent,
            "confidence": confidence,
            "supporting_evidence": supporting_evidence
        }
