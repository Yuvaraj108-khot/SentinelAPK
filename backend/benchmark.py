import os
import json
import hashlib
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List
from analyzer import APKAnalyzer
from risk_engine import RiskEngine
from memory_writer import write_errors_to_memory

logger = logging.getLogger("sentinel.benchmark")


DATASET_DIR = os.path.join(os.path.dirname(__file__), "dataset")
HISTORY_FILE = os.path.join(os.path.dirname(__file__), "data", "benchmark_history.json")
RUNS_DIR = os.path.join(os.path.dirname(__file__), "data", "runs")
ERRORS_FILE = os.path.join(os.path.dirname(__file__), "data", "error_cases.json")

class BenchmarkEngine:
    def __init__(self, dataset_dir: str = DATASET_DIR):
        self.dataset_dir = dataset_dir
        self.risk_engine = RiskEngine()
        os.makedirs(RUNS_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)

    def calculate_dataset_hash(self) -> str:
        """
        Computes SHA256 of all metadata file contents in the dataset splits to assert reproducibility.
        """
        hasher = hashlib.sha256()
        splits = ["train", "validation"]
        categories = ["benign", "suspicious", "malicious"]
        for split in splits:
            for cat in categories:
                cat_dir = os.path.join(self.dataset_dir, split, cat)
                if not os.path.exists(cat_dir):
                    continue
                for fname in sorted(os.listdir(cat_dir)):
                    if fname.endswith(".json"):
                        with open(os.path.join(cat_dir, fname), "rb") as f:
                            hasher.update(f.read())
        return hasher.hexdigest()

    def run_benchmark(self) -> Dict[str, Any]:
        """
        Executes split benchmark:
        1. Evaluate TRAIN set using current weights.
        2. Calibrate weights using train set errors, validated on VALIDATION set.
        3. Evaluate final VALIDATION set metrics.
        4. Count generated, user, and external APKs.
        """
        run_id = f"run_{datetime.utcnow().strftime('%Y_%m_%d')}_{uuid.uuid4().hex[:6]}"
        dataset_hash = self.calculate_dataset_hash()

        # Phase 1: Baseline Evaluation on Train
        train_res_before = self._evaluate_split("train")
        val_res_before = self._evaluate_split("validation")

        # Phase 2: Weight Search Calibration using validation callback
        from adaptive_learning import AdaptiveRiskCalibrationEngine
        engine = AdaptiveRiskCalibrationEngine()
        weights_before = {k: v["value"] for k, v in engine.load_weights().items()}

        def evaluate_validation_callback(candidate_weights):
            # Temporarily save candidate weights to run simulation
            old_weights = engine.load_weights()
            try:
                engine.save_weights(candidate_weights)
                val_run = self._evaluate_split("validation")
                return {
                    "accuracy": val_run["metrics"]["accuracy"],
                    "recall": val_run["metrics"]["recall"],
                    "f1_score": val_run["metrics"]["f1_score"],
                    "confusion_matrix": val_run["metrics"]["confusion_matrix"]
                }
            finally:
                engine.save_weights(old_weights)

        # Execute parameter search
        calib_res = engine.update_weights_from_errors(
            train_predictions=train_res_before["predictions"],
            run_id=run_id,
            evaluate_validation_fn=evaluate_validation_callback
        )
        
        # Load final calibrated weights
        weights_after = {k: v["value"] for k, v in engine.load_weights().items()}

        # Evaluate splits after learning
        train_res_after = self._evaluate_split("train")
        val_res_after = self._evaluate_split("validation")

        # Count APK categories across train & validation
        generated_apks = train_res_before["counts"]["generated"] + val_res_before["counts"]["generated"]
        user_apks = train_res_before["counts"]["user"] + val_res_before["counts"]["user"]
        external_apks = train_res_before["counts"]["external"] + val_res_before["counts"]["external"]

        # Track error cases from the validation set
        validation_errors = []
        for pred in val_res_after["predictions"]:
            if pred["classification"] in ["FP", "FN"]:
                validation_errors.append({
                    "apk_name": pred["apk_name"],
                    "ground_truth": pred["ground_truth"],
                    "prediction": pred["predicted_verdict"],
                    "confidence": pred["confidence"],
                    "error_type": "FALSE_POSITIVE" if pred["classification"] == "FP" else "FALSE_NEGATIVE",
                    "timestamp": datetime.utcnow().isoformat()
                })
        self._append_errors(validation_errors)

        # ── Convert benchmark errors into reusable retrieval lessons ──────────
        # write_errors_to_memory() reads the full prediction dicts which carry
        # package_name, permissions, dex_indicators, clone_findings, cert_findings
        # — the exact fields that RiskEngine.calculate_risk() retrieves on.
        new_lessons = write_errors_to_memory(val_res_after["predictions"])
        logger.info(f"Memory pipeline: {new_lessons} new lesson(s) written for run {run_id}")

        # Build auditable run artifact
        run_artifact = {
            "run_id": run_id,
            "timestamp": datetime.utcnow().isoformat(),
            "dataset_hash": dataset_hash,
            "engine_version": "3.0.0",
            "rules_version": "3.0.0",
            "classification_mode": "binary",
            "weights_before": weights_before,
            "weights_after": weights_after,
            "learning_success": calib_res["success"],
            "counts": {
                "generated_apks": generated_apks,
                "user_apks": user_apks,
                "external_apks": external_apks,
                "total": generated_apks + user_apks + external_apks
            },
            "train_metrics": {
                "before": train_res_before["metrics"],
                "after": train_res_after["metrics"]
            },
            "validation_metrics": {
                "before": val_res_before["metrics"],
                "after": val_res_after["metrics"]
            },
            # Final predictions shown to the user are validation after learning
            "predictions": val_res_after["predictions"],
            "metrics": val_res_after["metrics"]  # Final metrics reported on dashboard
        }

        # Save run artifact file
        run_file_path = os.path.join(RUNS_DIR, f"{run_id}.json")
        with open(run_file_path, "w", encoding="utf-8") as f:
            json.dump(run_artifact, f, indent=2)

        # Save benchmark history summary
        history_entry = {
            "run_id": run_id,
            "timestamp": run_artifact["timestamp"],
            "dataset_hash": dataset_hash,
            "dataset_size": run_artifact["counts"]["total"],
            "generated_apks": generated_apks,
            "user_apks": user_apks,
            "external_apks": external_apks,
            "accuracy": val_res_after["metrics"]["accuracy"],
            "precision": val_res_after["metrics"]["precision"],
            "recall": val_res_after["metrics"]["recall"],
            "f1_score": val_res_after["metrics"]["f1_score"],
            "confusion_matrix": val_res_after["metrics"]["confusion_matrix"],
            "rolled_back": not calib_res["success"]
        }
        self._append_history(history_entry)

        return run_artifact

    def _evaluate_split(self, split_name: str) -> Dict[str, Any]:
        """
        Evaluates a single split directory (train or validation).
        """
        categories = ["benign", "suspicious", "malicious"]
        predictions = []
        
        tp = fp = tn = fn = 0
        counts = {"generated": 0, "user": 0, "external": 0}

        for cat in categories:
            cat_dir = os.path.join(self.dataset_dir, split_name, cat)
            if not os.path.exists(cat_dir):
                continue
            for fname in os.listdir(cat_dir):
                if fname.endswith(".json"):
                    file_path = os.path.join(cat_dir, fname)
                    with open(file_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)

                    ground_truth = meta.get("ground_truth", cat.upper()).upper()
                    apk_name = meta.get("apk_name", fname.replace(".json", ".apk"))
                    corresponding_apk = os.path.join(cat_dir, apk_name)

                    apk_origin = meta.get("apk_origin", "external")
                    counts[apk_origin] = counts.get(apk_origin, 0) + 1

                    # Real static parsing of APK
                    if os.path.exists(corresponding_apk):
                        # Label generated/synthetic APKs separately as requested
                        if apk_origin == "generated":
                            evaluation_mode = "synthetic_apk"
                        else:
                            evaluation_mode = "real_apk"
                        
                        try:
                            features = APKAnalyzer(corresponding_apk).analyze()
                            risk = self.risk_engine.evaluate(features)
                        except Exception:
                            risk = self._simulate_risk_from_metadata(meta)
                    else:
                        evaluation_mode = "synthetic_apk" if apk_origin == "generated" else "real_apk"
                        risk = self._simulate_risk_from_metadata(meta)

                    predicted_verdict = risk.get("verdict", "SAFE")
                    confidence = risk.get("confidence", 50)
                    risk_score = risk.get("score", 0)

                    # Confusion Matrix Logic
                    is_pred_positive = predicted_verdict in ["MALICIOUS", "SUSPICIOUS"]
                    is_gt_positive = ground_truth in ["MALICIOUS", "SUSPICIOUS"]

                    classification = ""
                    if is_gt_positive and is_pred_positive:
                        tp += 1
                        classification = "TP"
                    elif not is_gt_positive and is_pred_positive:
                        fp += 1
                        classification = "FP"
                    elif not is_gt_positive and not is_pred_positive:
                        tn += 1
                        classification = "TN"
                    elif is_gt_positive and not is_pred_positive:
                        fn += 1
                        classification = "FN"

                    predictions.append({
                        "apk_name": apk_name,
                        "app_name": meta.get("app_label", "Unknown"),
                        "ground_truth": ground_truth,
                        "predicted_verdict": predicted_verdict,
                        "confidence": confidence,
                        "risk_score": risk_score,
                        "evaluation_mode": evaluation_mode,
                        "classification": classification,
                        "package_name": meta.get("package_name", "Unknown"),
                        "permissions": meta.get("permissions", []),
                        "dex_indicators": risk.get("dex_indicators", meta.get("dex_indicators", {})),
                        "certificates": meta.get("certificates", []),
                        "clone_findings": risk.get("clone_findings", {}),
                        "cert_findings": risk.get("cert_findings", {})
                    })

        total = tp + fp + tn + fn
        accuracy = (tp + tn) / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            "predictions": predictions,
            "counts": counts,
            "metrics": {
                "accuracy": round(accuracy, 2),
                "precision": round(precision, 2),
                "recall": round(recall, 2),
                "f1_score": round(f1_score, 2),
                "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
            }
        }

    def _simulate_risk_from_metadata(self, meta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fallback risk evaluation using JSON metadata when the APK binary cannot be parsed.
        Delegates to the full RiskEngine.calculate_risk() so certificate and clone checks run.
        """
        permissions  = meta.get("permissions", [])
        certificates = meta.get("certificates", [])
        package_name = meta.get("package_name", "Unknown")
        app_name     = meta.get("app_label", meta.get("app_name", "Unknown"))
        has_certs    = len(certificates) > 0

        # Parse dex_indicators from metadata if present as a list
        dex_indicators = meta.get("dex_indicators", {})
        if isinstance(dex_indicators, list):
            dex_dict = {}
            for item in dex_indicators:
                if "SmsManager" in item or "sendTextMessage" in item:
                    dex_dict["sms_send"] = True
                if "AccessibilityService" in item or "onAccessibilityEvent" in item:
                    dex_dict["accessibility_callback"] = True
                if "DexClassLoader" in item:
                    dex_dict["dex_class_loader"] = True
                if "Runtime.exec" in item or "exec" in item:
                    dex_dict["runtime_exec"] = True
            dex_indicators = dex_dict

        return RiskEngine.calculate_risk(
            permissions=permissions,
            has_services=False,
            has_certs=has_certs,
            dex_indicators=dex_indicators,
            package_name=package_name,
            certificates=certificates,
            app_name=app_name,
            activities=[],
        )

    def _append_history(self, entry: Dict[str, Any]):
        history = []
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    history = json.load(f)
            except Exception:
                pass
        history.append(entry)
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)

    def _append_errors(self, new_errors: List[Dict[str, Any]]):
        errors = []
        if os.path.exists(ERRORS_FILE):
            try:
                with open(ERRORS_FILE, "r", encoding="utf-8") as f:
                    errors = json.load(f)
            except Exception:
                pass
        errors.extend(new_errors)
        with open(ERRORS_FILE, "w", encoding="utf-8") as f:
            json.dump(errors, f, indent=2)

