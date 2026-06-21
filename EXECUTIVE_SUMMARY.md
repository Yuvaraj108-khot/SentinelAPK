# SentinelAPK: Executive Summary

SentinelAPK is an explainable AI-powered static threat intelligence platform designed to secure mobile banking applications against fraud, phishing clones, and credential overlays.

---

### 1. Problem Statement
Mobile banking customers are increasingly targeted by side-loaded applications that spoof official bank interfaces (e.g., SBI, HDFC, ICICI). These malicious applications abuse Android accessibility services, intercept SMS OTPs, and display fake overlay windows to harvest credentials. Traditional signature-based antivirus scanners often fail to detect novel, dynamically mutated variants.

### 2. Proposed Solution
SentinelAPK introduces a multi-stage static analysis pipeline combined with an adaptive calibration engine:
* **Static Parsing Pipeline**: Decompiles Android Manifests and scans DEX bytecode strings for high-risk API signatures (SMS, Accessibility, Loader executions) using primary Androguard and fallback ZIP parsers.
* **Clone Detection**: Measures app label and package name similarity ratios using sequence alignment against reference banking profiles, cross-referencing X.509 signature fingerprints to isolate phishing overlay clones.
* **Explainable AI (XAI)**: Generates clear, auditable threat explanations mapping findings to MITRE ATT&CK techniques, ensuring analysts can trace the threat chain.
* **Self-Hardening Calibration**: Shifts feature risk weights based on false positives/negatives, gated by a validation split to protect against performance regression.

---

### 3. Core Metrics & Evaluation
The system was evaluated on a 30-sample benchmark dataset (15 training samples, 15 validation samples) containing benign, suspicious, and malicious APK configurations:
* **Accuracy**: 0.87 (87%)
* **Precision**: 1.00 (100% - zero false positives on legitimate applications)
* **Recall**: 0.80 (80%)
* **F1-Score**: 0.89 (89%)

---

### 4. Stakeholder Value
* **For Banking Security Teams**: Immediate detection of clone variants spoofing official customer apps, complete with certificate alignment checks.
* **For Security Analysts**: Fully auditable risk scoring, Mitre technique mappings, and local text explanations explaining exactly why an app was flagged.
* **For Professors & Evaluators**: A reproducible, validation-gated optimization model that logs all metric deltas and rolls back changes if performance degrades.
