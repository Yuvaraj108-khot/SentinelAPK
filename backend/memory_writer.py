"""
memory_writer.py
================
Converts benchmark classification errors (FP / FN) into structured lessons
and appends them to data/learning_memory.json.

This is the bridge between the benchmark pipeline and the risk-engine
retrieval system.  Every entry written here is queryable by
RiskEngine.calculate_risk() on the next APK upload.

Schema written to learning_memory.json:
{
  "timestamp":          "2026-06-18T...",
  "package_name":       "com.fake.app",
  "permissions":        ["android.permission.READ_SMS", ...],
  "dex_indicators":     ["sms_send", "dex_class_loader"],    # active names only
  "certificate_status": "untrusted" | "trusted" | "<issue text>",
  "clone_risk":         "LOW" | "MEDIUM" | "HIGH",
  "ground_truth":       "SUSPICIOUS",
  "predicted_verdict":  "SAFE",
  "confidence":         65,
  "error_type":         "FALSE_NEGATIVE" | "FALSE_POSITIVE",
  "lesson":             "Human-readable description of the mistake."
}
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger("sentinel.memory_writer")

MEMORY_FILE = os.path.join(os.path.dirname(__file__), "data", "learning_memory.json")

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _dex_to_list(dex: Any) -> List[str]:
    """
    Normalise dex_indicators to a sorted list of *active* indicator names.
    Handles both dict (from live analysis) and list (from metadata JSON).
    Excludes the 'suspicious_urls' key because it is a list, not a bool flag.
    """
    if isinstance(dex, dict):
        return sorted(
            k for k, v in dex.items()
            if v and k != "suspicious_urls"
        )
    if isinstance(dex, list):
        return sorted(str(x) for x in dex)
    return []


def _cert_status(cert_findings: Dict) -> str:
    """Return a short certificate status string."""
    if cert_findings.get("is_trusted"):
        return "trusted"
    issue = cert_findings.get("reputation_issue")
    return issue if issue else "untrusted"


def _build_lesson_text(pred: Dict) -> str:
    """
    Build a human-readable lesson string from a misclassified prediction.
    """
    classification = pred.get("classification", "")
    error = "FALSE_NEGATIVE" if classification == "FN" else "FALSE_POSITIVE"
    perms = pred.get("permissions", [])
    clone_risk = pred.get("clone_findings", {}).get("clone_risk", "LOW")
    cert_status = _cert_status(pred.get("cert_findings", {}))

    # Short permission labels
    high_risk = [
        p.split(".")[-1]
        for p in perms
        if any(k in p for k in ("SMS", "ACCESSIBILITY", "ALERT_WINDOW", "INSTALL_PACKAGES"))
    ]

    parts = []
    if error == "FALSE_NEGATIVE":
        parts.append(
            f"Missed: predicted {pred.get('predicted_verdict','?')} "
            f"but actual label is {pred.get('ground_truth','?')}."
        )
        parts.append("Increase suspicion for similar apps in future.")
    else:
        parts.append(
            f"Over-flagged: predicted {pred.get('predicted_verdict','?')} "
            f"but actual label is {pred.get('ground_truth','?')}."
        )
        parts.append("Reduce suspicion for similar apps in future.")

    if high_risk:
        parts.append(f"Key permissions: {', '.join(high_risk)}.")
    if clone_risk in ("HIGH", "MEDIUM"):
        parts.append(f"Clone risk was {clone_risk}.")
    if cert_status != "trusted":
        parts.append(f"Certificate: {cert_status}.")

    return " ".join(parts)


def _multi_signal_similarity(a: Dict, b: Dict) -> float:
    """
    Multi-signal similarity between two memory entries for deduplication.

    Weights:
      70% — Permissions Jaccard
      30% — DEX indicator Jaccard

    Returns a float in [0.0, 1.0].
    """
    # Permissions Jaccard
    pa = set(a.get("permissions", []))
    pb = set(b.get("permissions", []))
    union_p = pa | pb
    j_perms = len(pa & pb) / len(union_p) if union_p else 0.0

    # DEX Jaccard (both stored as lists of active names)
    da = set(a.get("dex_indicators", []))
    db = set(b.get("dex_indicators", []))
    union_d = da | db
    j_dex = len(da & db) / len(union_d) if union_d else 0.0

    return 0.7 * j_perms + 0.3 * j_dex


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _load_memory() -> List[Dict]:
    os.makedirs(os.path.dirname(MEMORY_FILE), exist_ok=True)
    if not os.path.exists(MEMORY_FILE):
        return []
    try:
        with open(MEMORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Failed to load learning_memory.json: {e}")
        return []


def _save_memory(entries: List[Dict]) -> None:
    os.makedirs(os.path.dirname(MEMORY_FILE), exist_ok=True)
    with open(MEMORY_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_errors_to_memory(predictions: List[Dict]) -> int:
    """
    Convert FP and FN benchmark predictions into learning memory lessons.

    Deduplication rule:
      If any existing entry has multi-signal similarity >= 0.85 with
      the candidate, the candidate is skipped.

    Args:
        predictions: Full prediction dicts from BenchmarkEngine._evaluate_split().
                     Must include: classification, package_name, permissions,
                     dex_indicators, clone_findings, cert_findings,
                     ground_truth, predicted_verdict, confidence.

    Returns:
        Number of new entries actually written to disk.
    """
    errors = [p for p in predictions if p.get("classification") in ("FP", "FN")]
    if not errors:
        logger.info("Memory writer: no FP/FN predictions — nothing to write.")
        return 0

    memory = _load_memory()
    written = 0

    for pred in errors:
        dex_list = _dex_to_list(pred.get("dex_indicators", {}))
        clone_findings = pred.get("clone_findings", {})
        cert_findings  = pred.get("cert_findings",  {})

        new_entry: Dict[str, Any] = {
            "timestamp":          datetime.now(timezone.utc).isoformat(),
            "package_name":       pred.get("package_name", "Unknown"),
            "permissions":        pred.get("permissions", []),
            "dex_indicators":     dex_list,
            "certificate_status": _cert_status(cert_findings),
            "clone_risk":         clone_findings.get("clone_risk", "LOW"),
            "ground_truth":       pred.get("ground_truth", ""),
            "predicted_verdict":  pred.get("predicted_verdict", ""),
            "confidence":         pred.get("confidence", 50),
            "error_type":         "FALSE_NEGATIVE" if pred["classification"] == "FN"
                                  else "FALSE_POSITIVE",
            "lesson":             _build_lesson_text(pred),
        }

        # Deduplication: skip if any stored entry is >= 0.85 similar
        is_dup = any(
            _multi_signal_similarity(new_entry, existing) >= 0.85
            for existing in memory
        )

        if is_dup:
            logger.debug(
                f"Memory writer: skipped duplicate for "
                f"{new_entry['package_name']} ({new_entry['error_type']})"
            )
        else:
            memory.append(new_entry)
            written += 1
            logger.info(
                f"Memory writer: stored lesson — "
                f"{new_entry['package_name']} | {new_entry['error_type']} | "
                f"GT={new_entry['ground_truth']}"
            )

    if written > 0:
        _save_memory(memory)
        logger.info(f"Memory writer: {written} new lesson(s) written to learning_memory.json")

    return written
