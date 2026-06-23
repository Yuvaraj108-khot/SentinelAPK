import json
from behavior_correlation_engine import BehaviorCorrelationEngine
from attack_chain_engine import AttackChainEngine

def run_synthetic_tests():
    test_cases = [
        {"name": "Overlay Only", "evidence": {"overlay": True}},
        {"name": "Impersonation", "evidence": {"overlay": True, "accessibility": True, "clone_detection": True}},
        {"name": "Dropper", "evidence": {"runtime_exec": True, "dynamic_loading": True}},
        {"name": "Safe", "evidence": {"overlay": False, "accessibility": False}}
    ]

    print("--- V2 ENGINE SYNTHETIC TEST ---")
    
    for case in test_cases:
        print(f"\nEvaluating: {case['name']}")
        
        # Transform synthetic evidence into the format expected by the engine
        evidence_validation = {}
        for k, v in case['evidence'].items():
            evidence_validation[k] = {"status": "FOUND" if v else "UNKNOWN"}
            
        clone_findings = {"is_clone": case['evidence'].get("clone_detection", False)}
        cert_findings = {"status": "UNTRUSTED"} if clone_findings["is_clone"] else {"status": "TRUSTED"}
        
        # We simulate the INTERNET permission being present for all tests so OTP test triggers if sms+acc present
        metadata = {"permissions": ["android.permission.INTERNET"]}

        correlated = BehaviorCorrelationEngine.evaluate(
            metadata, evidence_validation, clone_findings, cert_findings
        )
        
        chains = AttackChainEngine.build_chains(correlated, evidence_validation)
        
        print("Correlated Threats:")
        print(json.dumps(correlated, indent=2))
        print("Attack Chains:")
        print(json.dumps(chains, indent=2))

if __name__ == "__main__":
    run_synthetic_tests()
