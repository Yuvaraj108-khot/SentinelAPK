import os
import json
import glob

runs_dir = r"c:\Users\YUVARAJ KHOT\my files\Desktop\project\SentinelAPK\backend\data\runs"
run_files = glob.glob(os.path.join(runs_dir, "*.json"))

print(f"Auditing {len(run_files)} runs:")

for rf in run_files:
    with open(rf, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            run_id = data.get("run_id", os.path.basename(rf))
            
            # Count evaluation mode occurrence in predictions
            predictions = data.get("predictions", [])
            evaluation_modes = [p.get("evaluation_mode") for p in predictions]
            metadata_modes_count = sum(1 for m in evaluation_modes if m == "METADATA")
            
            # Count composition
            dataset_comp = data.get("dataset_composition", {})
            apk_samples = dataset_comp.get("apk_samples", 0)
            metadata_samples = dataset_comp.get("metadata_samples", 0)
            
            # Fallback checks if counts key exists or if predictions can categorize them
            if "counts" in data:
                counts = data["counts"]
                # If there are apk vs metadata counts
                apk_samples = counts.get("apk_samples", apk_samples)
                metadata_samples = counts.get("metadata_samples", metadata_samples)
                
            # If not explicitly marked in dataset_composition / counts, we can count based on evaluation_mode
            if len(predictions) > 0 and (apk_samples == 0 and metadata_samples == 0):
                # Count 'real_apk' or 'synthetic_apk' as apk samples
                apk_samples = sum(1 for m in evaluation_modes if m in ["real_apk", "synthetic_apk", "APK"])
                metadata_samples = sum(1 for m in evaluation_modes if m == "METADATA")
                
            print(f"- Run: {run_id}")
            print(f"  apk_samples: {apk_samples}")
            print(f"  metadata_samples: {metadata_samples}")
            
            # Identify if any prediction has evaluation_mode == METADATA
            has_metadata = "Yes" if metadata_modes_count > 0 or metadata_samples > 0 else "No"
            print(f"  evaluation_mode has METADATA: {has_metadata} ({metadata_modes_count} predictions)")
        except Exception as e:
            print(f"- Error parsing {rf}: {e}")
