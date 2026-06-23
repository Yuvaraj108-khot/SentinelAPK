from typing import Dict, Any, List

class AttackChainEngine:
    
    @staticmethod
    def build_chains(correlated_threats: List[Dict[str, Any]], evidence_validation: Dict[str, Any]) -> Dict[str, Any]:
        chains = []
        contributors = []
        
        for threat in correlated_threats:
            if threat["threat"] == "Banking Impersonation Overlay":
                chains.append({
                    "name": "Credential Theft via Overlay",
                    "steps": [
                        "Initial Access (Clone Install)",
                        "Privilege Escalation (Overlay Grant)",
                        "Collection (Phishing Screen)",
                        "Exfiltration (Network Post)"
                    ],
                    "confidence": 0.95
                })
                contributors.extend(threat["components"])
                
            elif threat["threat"] == "OTP Interception & Exfiltration":
                chains.append({
                    "name": "SMS to OTP Interception",
                    "steps": [
                        "Initial Access (Permissions Granted)",
                        "Collection (Parses OTP Regex via SMS/Accessibility)",
                        "Exfiltration (Forwards to C2)"
                    ],
                    "confidence": 0.90
                })
                contributors.extend(threat["components"])
                
            elif threat["threat"] == "Hidden Payload Dropper":
                chains.append({
                    "name": "Dropper Execution",
                    "steps": [
                        "Initial Access (Install)",
                        "Execution (Runtime.exec / DexClassLoader)",
                        "Defense Evasion (Hiding Payload)"
                    ],
                    "confidence": 0.85
                })
                contributors.extend(threat["components"])

        # Determine confidence
        confidence = 0.0
        if chains:
            confidence = max(chain["confidence"] for chain in chains)
            
        return {
            "attack_chains": chains,
            "risk_contributors": list(set(contributors)),
            "confidence": confidence
        }
