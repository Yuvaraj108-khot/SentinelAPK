import json
import os

def main():
    # Load the 15 FPs from FALSE_POSITIVE_ANALYSIS.json
    with open("FALSE_POSITIVE_ANALYSIS.json", "r") as f:
        fps = json.load(f)
        
    # We might need REAL_WORLD_50_APK_RESULTS.json to get actual certificate info
    with open("REAL_WORLD_50_APK_RESULTS.json", "r") as f:
        results = json.load(f)
        
    results_map = {r["apk_name"]: r for r in results}

    impact_report = []
    fps_eliminated = 0

    for fp in fps:
        apk_name = fp["apk_name"]
        r = results_map.get(apk_name, {})
        
        # Analyze certificate info
        # Look for "UnknownCertificate" rule in the triggered rules
        cert_rule = next((rule for rule in fp["triggered_rules"] if rule["permission"] == "UnknownCertificate"), None)
        score_contribution = cert_rule["weight"] if cert_rule else 0
        
        evidence = r.get("evidence_validation", {})
        
        # We know from previous audit that all 15 FPs had certificate extraction failures or were marked as UNTRUSTED
        # Actually, in V2, certificate extraction was FIXED. 
        # But wait, did V2 finish successfully and extract certificates?
        # The user's previous checkpoint had "cert=UNTRUSTED" because SentinelAPK was penalizing anything not in its hardcoded list.
        # But wait, in the V2 results, "certificate_status" is what SentinelAPK outputs.
        # Let's read what SentinelAPK actually output for certificate_status in REAL_WORLD_50_APK_RESULTS.json.
        cert_status_from_app = r.get("certificate_status", "UNKNOWN")
        
        # In our definitions:
        # If extraction was successful but not in registry, it should be UNKNOWN.
        # If extraction failed, UNTRUSTED.
        # Let's assume if score_contribution > 0, it means it triggered UnknownCertificate.
        
        apk_path = os.path.join("dataset/real_world_external", apk_name)
        fingerprint = ""
        present = False
        parse_success = False
        
        if os.path.exists(apk_path):
            from analyzer import APKAnalyzer
            analyzer = APKAnalyzer(apk_path)
            try:
                certs = analyzer._extract_cert_from_apk()
                if certs:
                    present = True
                    fingerprint = certs[0].get("certificate_sha256", "")
                    parse_success = len(fingerprint) == 64
            except Exception:
                pass
        
        new_status = ""
        if not present or not parse_success:
            new_status = "UNTRUSTED"
        elif cert_status_from_app == "TRUSTED":
            new_status = "TRUSTED"
        else:
            new_status = "UNKNOWN"
            
        # If new rule is applied: UNKNOWN = 0 score, UNTRUSTED = +10 score.
        # Current score is fp["score"]. Current contribution is score_contribution.
        new_cert_penalty = 0
        if new_status == "UNKNOWN":
            new_cert_penalty = 0
        elif new_status == "UNTRUSTED":
            new_cert_penalty = 10
            
        new_score = fp["score"] - score_contribution + new_cert_penalty
        
        would_disappear = new_score < 35  # Suspicious threshold is 35
        if would_disappear:
            fps_eliminated += 1
            
        impact_report.append({
            "apk_name": apk_name,
            "certificate_fingerprint": fingerprint,
            "certificate_present": present,
            "certificate_parse_success": parse_success,
            "certificate_status": new_status,
            "score_contribution": score_contribution,
            "new_score_contribution": new_cert_penalty,
            "new_total_score": new_score,
            "would_disappear": would_disappear
        })

    with open("UNKNOWN_CERTIFICATE_IMPACT_REPORT.json", "w") as f:
        json.dump({
            "total_false_positives": len(fps),
            "false_positives_eliminated": fps_eliminated,
            "details": impact_report
        }, f, indent=2)

    redesign_plan = {
        "issue": "SentinelAPK currently conflates UNKNOWN certificates (validly extracted but unlisted) with UNTRUSTED certificates (missing or malformed), penalizing both equally (often +10 or higher).",
        "evidence": f"Re-classifying validly extracted certificates as UNKNOWN (score 0) eliminates {fps_eliminated} out of {len(fps)} false positives.",
        "proposed_solution": [
            "1. Redefine 'certificate_status' enum to distinguish between TRUSTED, UNKNOWN, and UNTRUSTED.",
            "2. TRUSTED: Exact match in trusted registry (0 penalty).",
            "3. UNKNOWN: Successfully extracted, valid format, but not in registry (0 penalty, but flag for manual review if other heuristics trigger).",
            "4. UNTRUSTED: Extraction failed, malformed signature, or explicitly blocklisted (+10 penalty)."
        ]
    }
    
    with open("CERTIFICATE_STATUS_REDESIGN_PLAN.json", "w") as f:
        json.dump(redesign_plan, f, indent=2)

if __name__ == "__main__":
    main()
