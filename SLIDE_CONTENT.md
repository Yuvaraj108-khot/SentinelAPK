# SentinelAPK Slide Content

This document outlines the slide-by-slide content for the SentinelAPK project presentation.

---

### Slide 1: Title & Problem
* **Slide Title**: SentinelAPK: Explainable Threat Intelligence for Banking APKs
* **Bullet Points**:
  * Side-loaded banking malware targeting Indian financial platforms (SBI, HDFC, ICICI).
  * High-risk automated overlays, accessibility abuse, and SMS intercept.
  * Explainable AI (XAI) threat reports to replace black-box security scanning.
* **Speaker Notes**: "Good morning. SentinelAPK addresses the critical rise of side-loaded banking trojans in India, translating complex bytecode analysis into explainable security summaries for analysts."

### Slide 2: Threat Landscape
* **Slide Title**: How Banking Trojans Compromise Users
* **Bullet Points**:
  * **Overlay Abuse**: Draw fake windows to harvest bank credentials.
  * **Accessibility Automation**: Capture keystrokes and bypass 2FA confirmations.
  * **SMS Interception**: Silently read and exfiltrate OTP messages.
* **Speaker Notes**: "Malware like Anubis and Cerberus exploit Android's Accessibility Services and SMS APIs. By combining these, they capture logins, read OTPs, and empty bank accounts without user awareness."

### Slide 3: Architecture
* **Slide Title**: System Architecture & Dual-Agent Model
* **Bullet Points**:
  * **Backend**: FastAPI, Androguard static analyzer, and Python Risk Engine.
  * **Frontend**: Next.js single-page interactive dashboard.
  * **Dual-Agent Hardening**: Evader LLM proposes evasive variants; Analyst LLM learns to identify them.
* **Speaker Notes**: "Our system splits into a FastAPI backend executing static analysis and a Next.js interface. We also prototype a dual-agent training model where an Evader generates strategies to harden our Analyst's models."

### Slide 4: APK Analysis Pipeline
* **Slide Title**: Multi-Stage Decompilation & Static Analysis
* **Bullet Points**:
  * **Fast Triage**: Manifest extraction (`uses-permission`, package metadata).
  * **DEX Bytecode Scan**: Static indicators in `classes.dex` (`SmsManager`, `DexClassLoader`).
  * **Fallback Parser**: Raw ZIP/regex fallback parsing on corrupt binaries.
* **Speaker Notes**: "The static pipeline starts by reading permissions. To prevent evasion, it decompresses classes.dex to scan for runtime execution strings, falling back to regex ZIP parsing if standard decompilers fail."

### Slide 5: Clone Detection
* **Slide Title**: Identifying Impersonation & Spoofing
* **Bullet Points**:
  * **Sequence Matching**: Label string comparison against reference banking utilities.
  * **Signature Cross-Check**: Compare X.509 certificate fingerprints with trusted databases.
  * **Result**: Package clones with unrecognized signatures trigger a HIGH-RISK clone verdict.
* **Speaker Notes**: "Clones are detected by comparing app names and package labels against official configurations. If an app mimics SBI or ICICI Bank but has a different signing signature, it is flagged as an impersonation clone."

### Slide 6: Benchmark Results
* **Slide Title**: Reproducible Performance Evaluation
* **Bullet Points**:
  * Evaluated on a 30-sample dataset (15 train / 15 validation).
  * **Accuracy**: 87% | **Precision**: 100% (Zero False Positives)
  * **Recall**: 80% | **F1-Score**: 89%
  * **Confusion Matrix**: TP: 8 | FP: 0 | TN: 5 | FN: 2
* **Speaker Notes**: "We evaluate our static rules against a 30-sample dataset. The engine achieves 87% accuracy with 100% precision, ensuring legitimate apps are not flagged as false positives."

### Slide 7: Adaptive Calibration
* **Slide Title**: Gated Weights Calibration
* **Bullet Points**:
  * Automatic weight shifts based on classification errors.
  * **Validation Split Gating**: Updates are evaluated on validation data.
  * **Rollback Action**: If validation metrics drop, weight updates are rolled back.
* **Speaker Notes**: "If errors are detected, the optimizer adjusts permission weights. This is gated by the validation split; if validation performance drops, the engine rolls back to protect accuracy."

### Slide 8: Platform Limitations
* **Slide Title**: Current System Limitations
* **Bullet Points**:
  * **Static Fallback**: Relies on manifest structure and bytecode keywords.
  * **Simulated Sandbox**: Emulator runtime trace execution is mock-based.
  * **No Visual Processing**: Brand similarity is string-based, not layout-based.
* **Speaker Notes**: "As a research prototype, our sandbox runtime environment and evasive variant generator are simulated. Brand matching is also text-based rather than visual."

### Slide 9: Future Work
* **Slide Title**: Future Roadmap
* **Bullet Points**:
  * Integration of live emulator runtime sandbox execution.
  * Visual template matching using computer vision for overlays.
  * Compilation of Dalvik bytecode for live dual-agent training.
* **Speaker Notes**: "In the future, we will integrate a live Android Emulator to capture dynamic API calls and implement visual layout matching to detect overlay screens."

### Slide 10: Conclusion
* **Slide Title**: Hardened, Auditable Threat Intelligence
* **Bullet Points**:
  * **Accurate**: 100% Precision on core bank utilities.
  * **Traceable**: Clear MITRE ATT&CK mappings and XAI rationales.
  * **Ready**: Auditable benchmark evidence package generated.
* **Speaker Notes**: "SentinelAPK delivers a hardened, explainable static threat analysis platform that secures mobile banking ecosystems. Thank you, and I am open to your questions."
