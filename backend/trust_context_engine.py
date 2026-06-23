from typing import Dict, Any, List

class TrustContextEngine:
    """
    Evaluates the broader context of an application to distinguish LEGITIMATE_USE from MALICIOUS_USE.
    Mitigates false positives caused by capability-correlation by injecting trust metadata.
    """
    
    @staticmethod
    def evaluate(package_name: str, 
                 cert_status: str, 
                 clone_indicators: Dict[str, Any], 
                 app_category: str, 
                 behavioral_threats: List[Dict[str, Any]], 
                 attack_chains: List[Dict[str, Any]]) -> Dict[str, Any]:
        
        # Default fallback
        trust_context = "UNKNOWN"
        confidence = 0.5
        reasoning = []
        
        # 1. Establish App Category Context
        category_map = {
            "media_player": ["org.videolan.vlc", "org.schabi.newpipe"],
            "terminal": ["com.termux"],
            "messaging": ["im.vector.app", "org.thoughtcrime.securesms"],
            "banking": ["com.securebank.official"]
        }
        
        inferred_category = app_category
        for cat, pkgs in category_map.items():
            if package_name in pkgs:
                inferred_category = cat
                break
                
        # 2. Evaluate Trust based on Context
        is_clone = clone_indicators.get("is_clone", False)
        
        if inferred_category in ["media_player", "terminal", "messaging"]:
            if cert_status in ["TRUSTED", "KNOWN_GOOD"] and not is_clone:
                trust_context = "LEGITIMATE_USE"
                confidence = 0.9
                reasoning.append(f"Capabilities align with expected behavior for {inferred_category} category.")
                reasoning.append("Certificate is trusted and no clone indicators detected.")
            else:
                trust_context = "SUSPICIOUS_USE"
                confidence = 0.7
                reasoning.append(f"App claims to be {inferred_category} but lacks trusted signing.")
                
        elif is_clone or cert_status in ["UNTRUSTED", "UNKNOWN"]:
            if len(attack_chains) > 0 or len(behavioral_threats) > 0:
                trust_context = "MALICIOUS_USE"
                confidence = 0.95
                reasoning.append("Untrusted certificate or clone indicators combined with dangerous behavioral threats.")
                
        if trust_context == "UNKNOWN":
            reasoning.append("Insufficient context to override capability analysis.")
            
        return {
            "trust_context": trust_context,
            "confidence": confidence,
            "reasoning": reasoning
        }
