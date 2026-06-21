import json
import os
from collections import defaultdict

def main():
    with open("REAL_WORLD_50_APK_RESULTS.json", "r") as f:
        results = json.load(f)

    fps = [r for r in results if r.get("ground_truth") == "BENIGN" and r.get("verdict") in ("SUSPICIOUS", "MALICIOUS")]

    detailed_fps = []
    detector_counts = defaultdict(int)
    detector_scores = defaultdict(int)
    evidence_patterns = defaultdict(int)

    for fp in fps:
        triggered = fp.get("triggered_rules", [])
        evidence = fp.get("evidence_validation", {})
        
        # Analyze root cause
        root_cause = "Combination of heuristics pushed score over threshold."
        recommended_fix = "Adjust weights or require multiple high-confidence indicators."
        
        if len(triggered) == 1:
            root_cause = f"Single rule ({triggered[0]['permission']}) caused false positive."
        
        # Look for the primary driver
        primary_driver = None
        max_weight = -1
        for rule in triggered:
            detector = rule.get("permission", "Unknown")
            weight = rule.get("weight", 0)
            desc = rule.get("description", "")
            
            detector_counts[detector] += 1
            detector_scores[detector] += weight
            evidence_patterns[desc] += 1
            
            if weight > max_weight:
                max_weight = weight
                primary_driver = detector

        if primary_driver == "UnknownCertificate":
            root_cause = "Legitimate open-source or indie app signed with a certificate not in the trusted allowlist."
            recommended_fix = "Implement trust-on-first-use (TOFU) or reduce UnknownCertificate penalty for open-source apps."
        elif primary_driver == "Reflection" or primary_driver == "Accessibility":
            root_cause = "App legitimately uses Accessibility API (e.g., for automation, accessibility features, or password managers)."
            recommended_fix = "Contextualize Accessibility usage; do not penalize heavily unless combined with overlay or SMS sending."
        elif primary_driver == "DexClassLoader":
            root_cause = "App dynamically loads code (common in plugins, large apps, or specific libraries)."
            recommended_fix = "Reduce penalty for standard class loaders unless loading from external untrusted storage."

        detailed_fps.append({
            "apk_name": fp.get("apk_name"),
            "package_name": fp.get("package_name"),
            "score": fp.get("risk_score"),
            "verdict": fp.get("verdict"),
            "ground_truth": "BENIGN",
            "triggered_rules": triggered,
            "score_breakdown": {rule.get("permission", "Unknown"): rule.get("weight", 0) for rule in triggered},
            "evidence": evidence,
            "root_cause": root_cause,
            "recommended_fix": recommended_fix
        })

    with open("FALSE_POSITIVE_ANALYSIS.json", "w") as f:
        json.dump(detailed_fps, f, indent=2)

    # Ranking
    ranking = []
    for detector, count in sorted(detector_counts.items(), key=lambda x: x[1], reverse=True):
        ranking.append({
            "detector": detector,
            "count": count,
            "total_score_contribution": detector_scores[detector],
            "most_frequent_evidence": sorted(
                [k for k in evidence_patterns.keys() if (
                    (detector == "UnknownCertificate" and "certificate" in k.lower()) or
                    (detector == "Reflection" and "callbacks" in k.lower()) or
                    (detector == "DexClassLoader" and "class loading" in k.lower()) or
                    (detector == "SuspiciousUrl" and "URL" in k.lower()) or
                    (detector == "WebviewBridge" and "Javascript" in k.lower()) or
                    (detector == "RuntimeExec" and "exec" in k.lower()) or
                    (detector == "Overlay" and "overlay" in k.lower())
                )], key=lambda k: evidence_patterns[k], reverse=True
            )[:1]
        })

    with open("FALSE_POSITIVE_RANKING.json", "w") as f:
        json.dump(ranking, f, indent=2)

    # Remediation Plan
    remediation_plan = [
        {
            "target": "UnknownCertificate",
            "issue": "Penalizes all valid indie and F-Droid apps as UNTRUSTED because their signatures aren't in the hardcoded known list.",
            "action": "Lower the base penalty of UnknownCertificate. If an app has no other malicious behaviors, an unknown certificate alone should not push the risk score into SUSPICIOUS territory."
        },
        {
            "target": "Reflection / Accessibility",
            "issue": "Legitimate apps (KeePassDX, AdAway, automation tools) use performAction and onAccessibilityEvent.",
            "action": "Reduce the base score for Accessibility hooks. Only escalate risk if Accessibility is paired with Overlay Windows or SMS sending."
        },
        {
            "target": "DexClassLoader",
            "issue": "Legitimate complex apps dynamically load modules or plugins.",
            "action": "Reduce the static penalty for DexClassLoader. Require combination with malicious endpoints or unknown network activity."
        }
    ]
    with open("FALSE_POSITIVE_REMEDIATION_PLAN.json", "w") as f:
        json.dump(remediation_plan, f, indent=2)

if __name__ == "__main__":
    main()
