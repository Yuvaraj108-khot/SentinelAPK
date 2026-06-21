import os
import json
import logging
import shutil
from datetime import datetime
from typing import Dict, Any, List

logger = logging.getLogger("sentinel.adaptive_learning")

WEIGHTS_FILE = os.path.join(os.path.dirname(__file__), "adaptive_weights.json")
HISTORY_FILE = os.path.join(os.path.dirname(__file__), "data", "learning_history.json")
SNAPSHOTS_DIR = os.path.join(os.path.dirname(__file__), "data", "weight_snapshots")
EXPLANATIONS_FILE = os.path.join(os.path.dirname(__file__), "data", "learning_explanations.json")

class AdaptiveRiskCalibrationEngine:
    def __init__(self, weights_file: str = WEIGHTS_FILE):
        self.weights_file = weights_file
        os.makedirs(SNAPSHOTS_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)

    def load_weights(self) -> Dict[str, Dict[str, Any]]:
        """
        Loads adaptive feature weights from JSON.
        """
        if not os.path.exists(self.weights_file):
            default_weights = {
                "READ_SMS": {"value": 20, "min": 5, "max": 50},
                "ACCESSIBILITY": {"value": 25, "min": 5, "max": 50},
                "SYSTEM_ALERT_WINDOW": {"value": 20, "min": 5, "max": 50},
                "DexClassLoader": {"value": 15, "min": 5, "max": 40},
                "Reflection": {"value": 10, "min": 2, "max": 30},
                "UnknownCertificate": {"value": 20, "min": 5, "max": 40},
                "PackageImpersonation": {"value": 25, "min": 5, "max": 50}
            }
            with open(self.weights_file, "w", encoding="utf-8") as f:
                json.dump(default_weights, f, indent=2)
            return default_weights

        with open(self.weights_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_weights(self, weights: Dict[str, Dict[str, Any]]):
        """
        Saves updated weights back to disk.
        """
        with open(self.weights_file, "w", encoding="utf-8") as f:
            json.dump(weights, f, indent=2)

    def create_snapshot(self, run_id: str) -> str:
        """
        Saves a copy of the current weights as a snapshot for safety validation.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        snapshot_name = f"snapshot_{timestamp}_{run_id}.json"
        snapshot_path = os.path.join(SNAPSHOTS_DIR, snapshot_name)
        shutil.copy2(self.weights_file, snapshot_path)
        return snapshot_path

    def rollback_snapshot(self, snapshot_path: str):
        """
        Restores weights from a snapshot.
        """
        if os.path.exists(snapshot_path):
            shutil.copy2(snapshot_path, self.weights_file)
            logger.info(f"Reverted weights to snapshot: {snapshot_path}")

    def update_weights_from_errors(
        self,
        train_predictions: List[Dict[str, Any]],
        run_id: str,
        evaluate_validation_fn,
        learning_rate: float = 0.20
    ) -> Dict[str, Any]:
        """
        Validation-Constrained Search Calibration:
        1. Run train errors to locate features contributing to mistakes.
        2. Propose weight optimization.
        3. Evaluate on validation set; accept ONLY if validation Accuracy, Recall, or F1 improves.
        """
        current_weights = self.load_weights()
        snapshot_path = self.create_snapshot(run_id)

        # Baseline metrics on validation set
        val_baseline = evaluate_validation_fn(current_weights)

        # Generate candidates from train errors
        fn_samples = [p for p in train_predictions if p.get("classification") == "FN"]
        fp_samples = [p for p in train_predictions if p.get("classification") == "FP"]

        candidate_weights = json.loads(json.dumps(current_weights))
        explanations = []
        learning_logs = []

        for feature, cfg in candidate_weights.items():
            old_val = cfg["value"]
            min_val = cfg["min"]
            max_val = cfg["max"]

            # Count occurrences in False Negatives vs False Positives
            fn_count = sum(1 for p in fn_samples if feature in self._get_active_features(p))
            fp_count = sum(1 for p in fp_samples if feature in self._get_active_features(p))

            shift = 0
            if fn_count > fp_count:
                # Missed malware -> increase weight to catch it next time
                boost = int(learning_rate * (max_val - old_val) * (fn_count / max(1, len(fn_samples))))
                boost = max(boost, 2)  # ensure meaningful change
                shift = min(old_val + boost, max_val) - old_val
            elif fp_count > fn_count:
                # False positive -> decrease weight to avoid alerts
                decrease = int(learning_rate * (old_val - min_val) * (fp_count / max(1, len(fp_samples))))
                decrease = max(decrease, 2)
                shift = max(old_val - decrease, min_val) - old_val

            if shift != 0:
                candidate_weights[feature]["value"] = old_val + shift
                reason = f"FN={fn_count}, FP={fp_count} in train set"
                log_entry = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "run_id": run_id,
                    "apk_name": "train_optimization",
                    "feature": feature,
                    "old_weight": old_val,
                    "new_weight": old_val + shift,
                    "confidence": 100,
                    "reason": reason
                }
                learning_logs.append(log_entry)
                direction = "increased" if shift > 0 else "decreased"
                explanations.append(
                    f"Weight for {feature} {direction} from {old_val} to {old_val + shift} based on train-set errors: {reason}."
                )

        # Apply candidate weights temporarily to evaluate on validation set
        val_candidate = evaluate_validation_fn(candidate_weights)

        # Verification Criteria: validation Accuracy, Recall, or F1 must improve
        success = False
        if val_candidate["accuracy"] > val_baseline["accuracy"]:
            success = True
        elif val_candidate["recall"] > val_baseline["recall"] and val_candidate["accuracy"] >= val_baseline["accuracy"]:
            success = True
        elif val_candidate["f1_score"] > val_baseline["f1_score"] and val_candidate["accuracy"] >= val_baseline["accuracy"]:
            success = True

        if success and learning_logs:
            self.save_weights(candidate_weights)
            self._write_history(learning_logs)
            self._write_explanations(explanations)
        else:
            self.rollback_snapshot(snapshot_path)
            success = False

        # Build Learning Effectiveness Report
        report_data = {
            "run_id": run_id,
            "timestamp": datetime.utcnow().isoformat(),
            "success": success,
            "before": {
                "accuracy": val_baseline["accuracy"],
                "recall": val_baseline["recall"],
                "f1_score": val_baseline["f1_score"],
                "confusion_matrix": val_baseline["confusion_matrix"]
            },
            "after": {
                "accuracy": val_candidate["accuracy"] if success else val_baseline["accuracy"],
                "recall": val_candidate["recall"] if success else val_baseline["recall"],
                "f1_score": val_candidate["f1_score"] if success else val_baseline["f1_score"],
                "confusion_matrix": val_candidate["confusion_matrix"] if success else val_baseline["confusion_matrix"]
            }
        }

        report_file = os.path.join(os.path.dirname(self.weights_file), "data", "effectiveness_report.json")
        os.makedirs(os.path.dirname(report_file), exist_ok=True)
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        return {
            "success": success,
            "report": report_data,
            "snapshot_path": snapshot_path
        }

    def _get_active_features(self, pred: Dict[str, Any]) -> List[str]:
        features = []
        permissions = pred.get("permissions", [])
        package_name = pred.get("package_name", "Unknown")
        dex_indicators = pred.get("dex_indicators", {})
        certificates = pred.get("certificates", [])

        if any(p in permissions for p in ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"]) or dex_indicators.get("sms_send") or dex_indicators.get("sms_manager"):
            features.append("READ_SMS")

        if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions or dex_indicators.get("accessibility_callback") or dex_indicators.get("accessibility_service"):
            features.append("ACCESSIBILITY")

        if "android.permission.SYSTEM_ALERT_WINDOW" in permissions or dex_indicators.get("overlay_window"):
            features.append("SYSTEM_ALERT_WINDOW")

        if dex_indicators.get("dex_class_loader"):
            features.append("DexClassLoader")
        if dex_indicators.get("accessibility_callback") or dex_indicators.get("webview_js_interface"):
            features.append("Reflection")

        # Untrusted certificate
        trusted_path = os.path.join(os.path.dirname(self.weights_file), "data", "trusted_certificates.json")
        if os.path.exists(trusted_path) and certificates:
            try:
                with open(trusted_path, "r", encoding="utf-8") as f:
                    trusted_certs = json.load(f)
                for c in certificates:
                    sha256_val = c.get("sha256", "").upper()
                    match_found = False
                    for tc in trusted_certs:
                        if sha256_val in tc.get("sha256", "").upper() or tc.get("sha256", "").upper() in sha256_val:
                            match_found = True
                            break
                    if not match_found:
                        features.append("UnknownCertificate")
                        break
            except Exception:
                pass
        elif not certificates:
            features.append("UnknownCertificate")

        # Impersonation
        banks_path = os.path.join(os.path.dirname(self.weights_file), "data", "official_banks.json")
        if os.path.exists(banks_path):
            try:
                import difflib
                with open(banks_path, "r", encoding="utf-8") as f:
                    banks = json.load(f)
                for bank in banks:
                    tgt_pkg = bank["package_name"]
                    similarity = difflib.SequenceMatcher(None, package_name, tgt_pkg).ratio()
                    if 0.5 <= similarity < 1.0:
                        features.append("PackageImpersonation")
                        break
            except Exception:
                pass

        return features

    def _write_history(self, logs: List[Dict[str, Any]]):
        history = []
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    history = json.load(f)
            except Exception:
                pass
        history.extend(logs)
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)

    def _write_explanations(self, new_explanations: List[str]):
        explanations = []
        if os.path.exists(EXPLANATIONS_FILE):
            try:
                with open(EXPLANATIONS_FILE, "r", encoding="utf-8") as f:
                    explanations = json.load(f)
            except Exception:
                pass
        explanations.extend(new_explanations)
        with open(EXPLANATIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(explanations, f, indent=2)

