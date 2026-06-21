# SUBMISSION EVIDENCE

This document contains final hardened benchmark evaluation results, clone detection analysis, adaptive calibration logs, and identified system limitations.

---

## 1. Final Benchmark Metrics (APK-Only Run)

The final APK-only benchmark evaluation is stored in [final_apk_only_benchmark.json](file:///c:/Users/YUVARAJ%20KHOT/my%20files/Desktop/project/SentinelAPK/backend/data/final_apk_only_benchmark.json).

* **Accuracy**: 0.87
* **Precision**: 1.00
* **Recall**: 0.80
* **F1-Score**: 0.89
* **Confusion Matrix**:
  * **True Positives (TP)**: 8
  * **False Positives (FP)**: 0
  * **True Negatives (TN)**: 5
  * **False Negatives (FN)**: 2

---

## 2. Clone Detection Results

SentinelAPK identifies fake banking apps using sequence matching, package similarity, and cryptographic signature matching against [official_banks.json](file:///c:/Users/YUVARAJ%20KHOT/my%20files/Desktop/project/SentinelAPK/backend/data/official_banks.json). The official reports are tracked in [clone_detection_report.json](file:///c:/Users/YUVARAJ%20KHOT/my%20files/Desktop/project/SentinelAPK/backend/data/clone_detection_report.json):

* **Official App Target**: `com.securebank.official` (SecureBank Official)
  * Brand Similarity: 100%
  * Package Similarity: 100%
  * Certificate Match: True
  * Clone Risk Verdict: LOW

* **Malicious Spoofing Variant**: `com.securebank.plus` (SecureBank Plus)
  * Brand Similarity: 71%
  * Package Similarity: 76%
  * Certificate Match: False
  * Clone Risk Verdict: HIGH (Impersonation Detected)

* **Credential Harvesting Overlay**: `com.securebank.official` (SecureBank Clone)
  * Brand Similarity: 69%
  * Package Similarity: 100%
  * Certificate Match: False
  * Clone Risk Verdict: HIGH (Package Spoofing Detected)

---

## 3. Adaptive Calibration Results

The weights optimization pipeline is evaluated using a validation split callback. Results are recorded in [learning_effectiveness_report.json](file:///c:/Users/YUVARAJ%20KHOT/my%20files/Desktop/project/SentinelAPK/backend/data/learning_effectiveness_report.json):

* **Before Optimization**: Accuracy = 87%, Recall = 80%, F1 = 89%
* **After Candidate Optimization**: Accuracy = 87%, Recall = 80%, F1 = 89%
* **Status**: Rejected / Rolled Back (weights reverted to snapshot because the candidate parameters did not yield validation score improvement).

---

## 4. Known Limitations

* **APK Decompilation Fallback**: Androguard binary parsing is primary. If binary compilation formats are invalid or corrupt, the platform falls back to a Zip/regex text parser to reconstruct manifest permissions and scan DEX bytecodes.
* **Certificate Reputation**: Relies on a static DB hash matching scheme. Adaptive self-signing is not checked.
* **Simulated Subsystems**: The Sandbox C2 Runtime Emulator and LLM Evasive Bytecode Generation are simulated/textual strategies rather than live sandbox executions.
