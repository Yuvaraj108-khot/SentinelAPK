import json
import os
import subprocess
from analyzer import APKAnalyzer
import shutil

def main():
    # Load old results to get the 15 FPs
    if not os.path.exists("REAL_WORLD_50_APK_RESULTS.json"):
        print("Missing old results")
        return
        
    with open("REAL_WORLD_50_APK_RESULTS.json", "r") as f:
        old_results = json.load(f)
        
    old_fps = {r["apk_name"]: r for r in old_results if r.get("ground_truth") == "BENIGN" and r.get("verdict") in ("SUSPICIOUS", "MALICIOUS")}
    
    print(f"Running full external reality check to get new metrics...")
    # Just run it. It skips downloads, parses all 50 again.
    subprocess.run(["python", "run_external_reality_check.py"], check=True)
    
    with open("REAL_WORLD_50_APK_RESULTS.json", "r") as f:
        new_results = json.load(f)
        
    new_results_map = {r["apk_name"]: r for r in new_results}
    
    validation_report = []
    eliminated_count = 0
    post_refactor_fps = []
    
    for apk_name, old_fp in old_fps.items():
        new_res = new_results_map.get(apk_name)
        if not new_res:
            continue
            
        old_score = old_fp.get("risk_score")
        old_verdict = old_fp.get("verdict")
        new_score = new_res.get("risk_score")
        new_verdict = new_res.get("verdict")
        
        validation_report.append({
            "apk_name": apk_name,
            "old_score": old_score,
            "new_score": new_score,
            "old_verdict": old_verdict,
            "new_verdict": new_verdict
        })
        
        if new_verdict == "SAFE" and old_verdict != "SAFE":
            eliminated_count += 1
            
    # Count how many of the 50 are FPs now
    for r in new_results:
        if r.get("ground_truth") == "BENIGN" and r.get("verdict") in ("SUSPICIOUS", "MALICIOUS"):
            post_refactor_fps.append({
                "apk_name": r["apk_name"],
                "score": r["risk_score"],
                "verdict": r["verdict"],
                "top_reasons": r.get("top_reasons", [])
            })
            
    with open("CERTIFICATE_REFACTOR_VALIDATION.json", "w") as f:
        json.dump(validation_report, f, indent=2)
        
    with open("POST_REFACTOR_FALSE_POSITIVE_REPORT.json", "w") as f:
        json.dump(post_refactor_fps, f, indent=2)
        
    # Recalculate metrics
    tp = tn = fp = fn = 0
    valid = [r for r in new_results if r.get("analysis_status") == "OK"]
    
    for r in valid:
        gt = r["ground_truth"]
        verdict = r["verdict"]
        pred_pos = verdict in ("MALICIOUS", "SUSPICIOUS")
        gt_pos = gt == "MALICIOUS"
        
        if gt_pos and pred_pos: tp += 1
        elif gt_pos and not pred_pos: fn += 1
        elif not gt_pos and pred_pos: fp += 1
        elif not gt_pos and not pred_pos: tn += 1
        
    acc = (tp + tn) / max(1, (tp + tn + fp + fn))
    prec = tp / max(1, (tp + fp))
    rec = tp / max(1, (tp + fn))
    f1 = 2 * prec * rec / max(1, (prec + rec))
    
    with open("UPDATED_EXTERNAL_METRICS.json", "w") as f:
        json.dump({
            "TP": tp,
            "TN": tn,
            "FP": fp,
            "FN": fn,
            "Accuracy": round(acc, 4),
            "Precision": round(prec, 4),
            "Recall": round(rec, 4),
            "F1": round(f1, 4),
            "false_positives_eliminated": eliminated_count
        }, f, indent=2)
        
    print(f"Validation complete. Eliminated {eliminated_count} false positives.")

if __name__ == "__main__":
    main()
