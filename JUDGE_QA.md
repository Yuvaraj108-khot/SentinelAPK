# SentinelAPK: Cybersecurity Judge Q&A

This document compiles 25 challenging questions a security audit judge may ask, along with short and technical answers.

---

### Q1: How does the system parse APK files if androguard is missing or fails?
* **Short Answer**: It falls back to a custom zip parser that extracts `AndroidManifest.xml` and reads `classes.dex` strings directly.
* **Technical Answer**: The fallback parser in `analyzer.py` opens the APK as a standard ZIP archive, reads the raw text/xml strings of `AndroidManifest.xml` via regex to extract permissions, package names, and app labels, and parses the raw bytes of `classes.dex` to detect compiled string indicators.

### Q2: Why does the system evaluate a dataset split instead of just testing single files?
* **Short Answer**: To prevent overfitting and verify that changes do not degrade detection performance on validation samples.
* **Technical Answer**: The `BenchmarkEngine` evaluates a training split (15 samples) and gates weights updates using a validation split (15 samples) to calculate accuracy, precision, recall, and F1-score, ensuring generalization.

### Q3: What happens to candidate weight updates if the validation split score decreases?
* **Short Answer**: The candidate weight update is rejected, and the system rolls back to the previous stable snapshot.
* **Technical Answer**: In `adaptive_learning.py`, weight changes are validated using the callback function `evaluate_validation_fn`. If validation F1-score, accuracy, or recall decreases, `rolled_back` is set to `True`, and the previous parameters are restored in `adaptive_weights.json`.

### Q4: How is brand impersonation (clone detection) calculated?
* **Short Answer**: It compares the app label and package name similarity against a database of official banks.
* **Technical Answer**: The engine uses Python's `difflib.SequenceMatcher` to calculate string similarity ratios of the target's app label and package identifier against definitions in `official_banks.json`. If similarity exceeds 60% but the certificate doesn't match, it flags it as a high-risk clone.

### Q5: How does certificate validation prevent certificate spoofing?
* **Short Answer**: It compares SHA256 fingerprints of the APK's signer certificate against known official certificate hashes.
* **Technical Answer**: `RiskEngine` extracts the X.509 certificate fingerprint from the APK and checks it against `trusted_certificates.json`. If a package matches an official target but the fingerprint does not match the official record, a clone mismatch is triggered.

### Q6: What bytecode indicators do you check for in `classes.dex`?
* **Short Answer**: We check for strings indicating SMS interception, accessibility service abuse, dynamic loading, and system executions.
* **Technical Answer**: We scan `classes.dex` bytes using regex queries for `SmsManager`, `sendTextMessage`, `AccessibilityService`, `onAccessibilityEvent`, `DexClassLoader`, `Runtime.exec`, and `addJavascriptInterface`.

### Q7: Why is the precision of your model 1.0 (100%) in the benchmark runs?
* **Short Answer**: Because the risk score thresholds and rules are configured to avoid flagging legitimate applications.
* **Technical Answer**: In our benchmark evaluations, the confusion matrix shows 0 false positives (FP = 0). This is achieved because benign apps do not request high-risk permission chains (like Accessibility + SMS + System Alert) or use untrusted signatures under clone targets.

### Q8: What are the dataset splits and counts for benign, suspicious, and malicious?
* **Short Answer**: 30 total samples split equally into 15 train and 15 validation samples.
* **Technical Answer**: Both train and validation splits contain exactly 5 benign, 5 suspicious, and 5 malicious samples, verified by `dataset_validator.py`.

### Q9: Does the system perform dynamic execution of APKs in a sandbox?
* **Short Answer**: No, dynamic analysis and the runtime sandbox are currently simulated.
* **Technical Answer**: There is no live execution environment or hook manager. Real static parsing is fully implemented, while dynamic execution logs are simulated payloads mapped to threat evaluations.

### Q10: How do you prevent evasion via class and method obfuscation?
* **Short Answer**: Static indicator scans will fail under full renaming, but manifest permission combinations and untrusted certificates still flag the risk.
* **Technical Answer**: If DEX strings are obfuscated, DEX scans yield no results, but permission weights (e.g. Accessibility + System Alert) and certificate checks will still trigger high risk verdicts.

### Q11: How are risk scores computed?
* **Short Answer**: They sum active permission and bytecode weights, capped at 100.
* **Technical Answer**: `RiskEngine` aggregates the weights of active features (permissions like BIND_ACCESSIBILITY_SERVICE and indicators like SMS_SEND). The final risk score is normalized to a range of 0 to 100.

### Q12: What triggers a "SUSPICIOUS" verdict vs a "MALICIOUS" verdict?
* **Short Answer**: Scores below 35 are SAFE, scores between 35 and 70 are SUSPICIOUS, and scores 70 or above are MALICIOUS.
* **Technical Answer**: We apply static threshold ranges on the aggregated risk score: score < 35 triggers SAFE, 35 <= score < 70 triggers SUSPICIOUS, and score >= 70 triggers MALICIOUS.

### Q13: How does the Evader LLM generate mutated variants?
* **Short Answer**: It suggests strategies textually to bypass static checks. It does not compile modified APKs.
* **Technical Answer**: The Evader LLM (`evader_agent.py`) takes an APK's features and suggests obfuscation tactics or replacement permissions. It is a planning prototype that outputs structural evasion recommendations.

### Q14: How does the Analyst LLM explain findings?
* **Short Answer**: It uses Vertex API prompts, with a rule-based regex fallback engine.
* **Technical Answer**: `llm_client.py` sends metadata and risk signals to Gemini. If the API key is inactive or offline, a local rule-based explanation parser maps the active indicators to static text rationales.

### Q15: How does the system assert reproducibility of the benchmark?
* **Short Answer**: By hashing the files in the dataset splits and checking it before running.
* **Technical Answer**: `BenchmarkEngine.calculate_dataset_hash` calculates the SHA256 hash of all dataset JSON files to ensure the files have not changed.

### Q16: Why is `AndroidManifest.xml` parsed as raw text in the fallback?
* **Short Answer**: Because programmatically generated mock APKs are stored as plain text XML rather than compiled binary XML.
* **Technical Answer**: Test APKs generated for unit tests write manifest files as plaintext ZIP entries. The fallback text parser matches them using regular expressions.

### Q17: What official banking targets are present in clone detection?
* **Short Answer**: Major Indian banks (SBI, ICICI, HDFC, Axis, Paytm) and SecureBank.
* **Technical Answer**: `official_banks.json` defines target packages like `com.sbi.yonolite`, `com.icicibank.mobile`, `com.hdfcbank.smartbuy`, `com.axis.mobile`, and `com.securebank.official`.

### Q18: What is the risk contribution of `BIND_ACCESSIBILITY_SERVICE`?
* **Short Answer**: It has the highest weight contribution (typically 25) because it allows complete automation.
* **Technical Answer**: In `adaptive_weights.json`, Accessibility Service has a value of 25. This weight represents the highest single risk flag due to keystroke logging capabilities.

### Q19: How does the engine detect dropper behavior?
* **Short Answer**: By matching the `REQUEST_INSTALL_PACKAGES` permission and `DexClassLoader` strings.
* **Technical Answer**: The combination of installer permissions in the manifest and dynamic loading indicators (`DexClassLoader`) in `classes.dex` flags dropper risks.

### Q20: What are the confusion matrix results of the latest benchmark run?
* **Short Answer**: TP = 8, FP = 0, TN = 5, FN = 2.
* **Technical Answer**: The validation split evaluation yields 8 True Positives, 0 False Positives, 5 True Negatives, and 2 False Negatives, reflecting a recall of 80% and a precision of 100%.

### Q21: What are the two False Negatives in the benchmark predictions?
* **Short Answer**: Two suspicious mock overlays that did not request enough permission combos to trigger the risk threshold.
* **Technical Answer**: Legitimate overlay structures that do not request background capabilities (like network sockets) fail to exceed the threshold, resulting in False Negatives.

### Q22: Why isn't a Threat Graph visual engine present?
* **Short Answer**: Graphical visual connection nodes were classified as outside the MVP scope.
* **Technical Answer**: The threat graph remains a future development goal. Risk chains are currently outputted as sequential steps rather than node graphs.

### Q23: How are trusted certificates defined?
* **Short Answer**: By a static JSON configuration mapping official publishers to SHA256 signature hashes.
* **Technical Answer**: [trusted_certificates.json](file:///c:/Users/YUVARAJ%20KHOT/my%20files/Desktop/project/SentinelAPK/backend/data/trusted_certificates.json) maps fingerprints to publishers. If the signature is not present, it flags the app as untrusted.

### Q24: What programming languages and frameworks are used?
* **Short Answer**: Python (FastAPI, Androguard) for the backend, and TypeScript (Next.js, TailwindCSS) for the frontend.
* **Technical Answer**: The backend is built in Python 3 using FastAPI, Uvicorn, and Androguard; the frontend is a Next.js single-page application built with React and styled with TailwindCSS.

### Q25: Is this system ready for commercial deployment?
* **Short Answer**: It is ready as a static analysis staging utility, with dynamic analysis needing real sandbox integration.
* **Technical Answer**: The static pipeline, clone detection, signature verification, and calibration are hardened and complete. Production deployment requires linking to a live Android Emulator sandbox for dynamic analysis.
