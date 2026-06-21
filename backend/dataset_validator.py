import os
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger("sentinel.dataset_validator")

DATASET_DIR = os.path.join(os.path.dirname(__file__), "dataset")

class DatasetValidator:
    def __init__(self, dataset_dir: str = DATASET_DIR):
        self.dataset_dir = dataset_dir

    def validate_dataset(self) -> Dict[str, Any]:
        """
        Validates the benchmark dataset structure, checks metadata schema, 
        provenance, duplication, and computes a quality score (0-100).
        Supports split folders (train and validation).
        """
        splits = ["train", "validation"]
        categories = ["benign", "suspicious", "malicious"]
        issues: List[str] = []
        total_samples = 0
        apk_samples = 0
        metadata_samples = 0
        
        label_completions = 0
        provenance_completions = 0
        seen_apk_names = set()
        duplicate_count = 0

        # Ensure directories exist
        for split in splits:
            for category in categories:
                os.makedirs(os.path.join(self.dataset_dir, split, category), exist_ok=True)

        for split in splits:
            for category in categories:
                category_dir = os.path.join(self.dataset_dir, split, category)
                for file_name in os.listdir(category_dir):
                    if file_name.endswith(".json"):
                        total_samples += 1
                        file_path = os.path.join(category_dir, file_name)
                        
                        try:
                            with open(file_path, "r", encoding="utf-8") as f:
                                data = json.load(f)
                        except Exception as e:
                            issues.append(f"[{split}/{category}] {file_name}: Malformed JSON syntax: {e}")
                            continue

                        # Schema validation
                        apk_name = data.get("apk_name")
                        if not apk_name:
                            issues.append(f"[{split}/{category}] {file_name}: Missing required field 'apk_name'")
                        else:
                            composite_key = f"{split}/{apk_name}"
                            if composite_key in seen_apk_names:
                                duplicate_count += 1
                                issues.append(f"[{split}/{category}] {file_name}: Duplicate sample detected for 'apk_name': {apk_name}")
                            seen_apk_names.add(composite_key)

                        ground_truth = data.get("ground_truth")
                        if not ground_truth:
                            issues.append(f"[{split}/{category}] {file_name}: Missing required field 'ground_truth'")
                        elif ground_truth.upper() != category.upper():
                            issues.append(f"[{split}/{category}] {file_name}: Mismatch between ground_truth '{ground_truth}' and category '{category}'")
                        else:
                            label_completions += 1

                        # Provenance validation
                        source = data.get("source")
                        reviewed_by = data.get("reviewed_by")
                        created_at = data.get("created_at")

                        if source and reviewed_by and created_at:
                            provenance_completions += 1
                        else:
                            issues.append(f"[{split}/{category}] {file_name}: Missing provenance metadata (requires 'source', 'reviewed_by', 'created_at')")

                        # Check APK coverage
                        corresponding_apk = file_name.replace(".json", ".apk")
                        if os.path.exists(os.path.join(category_dir, corresponding_apk)):
                            apk_samples += 1
                        else:
                            metadata_samples += 1

        # Quality Score Calculation
        if total_samples > 0:
            label_score = (label_completions / total_samples) * 100
            provenance_score = (provenance_completions / total_samples) * 100
            duplicate_score = ((total_samples - duplicate_count) / total_samples) * 100
            apk_score = (apk_samples / total_samples) * 100
            
            quality_score = int((label_score + provenance_score + duplicate_score + apk_score) / 4)
        else:
            quality_score = 0

        return {
            "quality_score": quality_score,
            "total_samples": total_samples,
            "apk_samples": apk_samples,
            "metadata_samples": metadata_samples,
            "duplicate_count": duplicate_count,
            "issues": issues
        }

