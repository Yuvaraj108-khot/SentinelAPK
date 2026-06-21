# SentinelAPK 5-Minute Demonstration Script

This script outlines a 5-minute live demonstration flow of the SentinelAPK platform.

---

### Step 1: Problem Statement (0:00 - 0:45)
* **Action**: Open the SentinelAPK homepage.
* **Narration**: "Mobile banking fraud in India is rising, driven by malicious overlays, accessibility abuse, and clone applications spoofing trusted brands like SBI, ICICI, and HDFC. SentinelAPK is an explainable AI threat intelligence platform designed to statically audit APK structures, detect malicious brand clones, and adaptively calibrate its classification engine based on validation errors."

### Step 2: Upload APK (0:45 - 1:15)
* **Action**: Drag and drop `fake_yono_lite.apk` or click "Decompile New APK" to upload.
* **Observation**: Point to the Stage Progress Bar at the bottom showing:
  1. Fast Triage (manifest parsing)
  2. LLM Intent Graph Analysis (bytecode indicator search)
  3. UI Deception Detection (brand comparison)
  4. Dynamic Analysis Simulation
  5. Signal Fusion & Investigation Report

### Step 3: Show Permissions & MITRE ATT&CK Matrix (1:15 - 1:45)
* **Action**: Select the "Permissions & MITRE" tab.
* **Observation**: Show the permission list and active MITRE technique blocks.
* **Narration**: "The platform parses the AndroidManifest.xml configuration. Here we see high-risk permissions such as `BIND_ACCESSIBILITY_SERVICE` and `RECEIVE_SMS` mapped directly to active MITRE ATT&CK tactics like Collection (T1636.002 - SMS Intercept) and Credential Access (T1430 - Accessibility Abuse)."

### Step 4: Show DEX Bytecode Indicators (1:45 - 2:15)
* **Action**: Select the "App Overview & Meta" tab and scroll to "DEX Bytecode Scan".
* **Observation**: Notice "Accessibility APIs" and "SMS / Telephony APIs" marked as **FOUND**.
* **Narration**: "Going beyond manifest permissions, SentinelAPK decompresses `classes.dex` to scan for binary string signatures like `SmsManager` and `onAccessibilityEvent` to confirm the presence of execution pathways for SMS interception and interface automation."

### Step 5: Show Certificate Findings & Reputation (2:15 - 2:45)
* **Action**: Scroll down in the "Overview" tab to "Certificate Details & Code Signature".
* **Observation**: Note the signature details (Issuer, Serial Key, SHA256 Fingerprint) and the status banner.
* **Narration**: "The app signature's SHA256 fingerprint is verified against a reputation database. In this case, the certificate is flagged as untrusted, indicating it is self-signed or debug-signed, typical of side-loaded banking trojans."

### Step 6: Show Clone Detection (2:45 - 3:15)
* **Action**: Look at the "Clone Impersonation Warning" banner on the "Overview" tab.
* **Observation**: Brand Similarity shows high similarity to `com.securebank.official`, but with an unrecognized signature certificate.
* **Narration**: "SentinelAPK computes string similarity ratios using sequence alignment. The application is flagged as a high-risk clone because its brand labels closely match SBI and SecureBank targets, but it is signed with a conflicting certificate."

### Step 7: Explain Risk Score & Rationale (3:15 - 3:45)
* **Action**: Point to the circular "Risk Score Gauge" and the "Why was this flagged?" flow steps.
* **Observation**: Risk Score is 83/100, Verdict is MALICIOUS. Attack chain shows 4 stages of the attack execution path.
* **Narration**: "The Risk Engine combines static permissions, DEX bytecode signatures, and certificate alignment to output a normalized score. This sample scores 83/100, resulting in a MALICIOUS verdict. The platform illustrates the exact threat chain: from SMS collection to Accessibility capture."

### Step 8: Show Benchmark Results & History (3:45 - 4:15)
* **Action**: Click the "Adaptive Calibration Lab" tab and view the "Auditable Benchmark Runs" panel.
* **Observation**: Point to the latest runs showing 87% Accuracy, 100% Precision, 80% Recall, and 89% F1-Score on the 30-sample dataset split (15 train / 15 validation).
* **Narration**: "To ensure performance consistency, SentinelAPK runs complete train/validation evaluations. The current engine scores 87% validation accuracy with 100% precision, preventing false positives on legitimate banking utilities."

### Step 9: Show Adaptive Calibration Result (4:15 - 4:45)
* **Action**: View the "Learning Effectiveness Report" and the "Attribution Learning Logs" table.
* **Observation**: Explain that candidate parameter weights are evaluated against a validation split constraint. If performance does not improve, the engine rolls back the candidate weights.
* **Narration**: "When the engine detects errors, it attempts to shift weights (e.g. READ_SMS weight). These changes are gated by the validation split; because validation performance did not improve in the latest cycle, the changes were rejected and safely rolled back to a stable snapshot."

### Step 10: Show Platform Limitations & Conclusion (4:45 - 5:00)
* **Action**: Point to the "Platform Capability Reality Check" card.
* **Narration**: "SentinelAPK clearly separates static APK parsing, certificate verification, and brand matching—which are fully implemented—from advanced dynamic sandbox simulation which remains in simulated/future scope. The platform is hardened, reproducible, and ready for deployment."
