import json
from typing import Dict, Any, List

class BehaviorCorrelationEngine:
    """
    Evaluates evidence against combinations to reduce capability-based false positives.
    """
    
    @staticmethod
    def evaluate(metadata: Dict[str, Any], evidence_validation: Dict[str, Any], clone_findings: Dict[str, Any], cert_findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        correlated_threats = []
        
        # Helper to check if evidence is FOUND
        def has_ev(key: str) -> bool:
            return evidence_validation.get(key, {}).get("status") == "FOUND"

        # 1. Banking Impersonation
        if clone_findings.get("is_clone") and cert_findings.get("status") in ["UNTRUSTED", "UNKNOWN"]:
            if has_ev("overlay"):
                correlated_threats.append({
                    "threat": "Banking Impersonation Overlay",
                    "severity": "CRITICAL",
                    "components": ["Clone", "Untrusted Cert", "Overlay"]
                })
        
        # 2. OTP Interception
        if has_ev("sms") and has_ev("accessibility"):
            # If it also has internet
            if "android.permission.INTERNET" in metadata.get("permissions", []):
                correlated_threats.append({
                    "threat": "OTP Interception & Exfiltration",
                    "severity": "CRITICAL",
                    "components": ["SMS", "Accessibility", "Internet"]
                })
                
        # 3. Execution / Dropper
        if has_ev("dynamic_loading") and has_ev("runtime_exec"):
            correlated_threats.append({
                "threat": "Hidden Payload Dropper",
                "severity": "HIGH",
                "components": ["DexClassLoader", "Runtime.exec"]
            })
            
        return correlated_threats
