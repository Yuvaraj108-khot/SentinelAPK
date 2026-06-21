# SentinelAPK: Project Claims Verification

This document audits claims regarding the capabilities of the SentinelAPK platform.

---

## Supported Claims (Evidence Verified)

The following claims are verified by project artifacts:

1. **Fallback APK Manifest Parsing**
   * *Claim*: The platform parses APK archives and extracts metadata even if binary APK formatting is corrupt.
   * *Evidence*: [analyzer.py:L108-140](file:///c:/Users/YUVARAJ%20KHOT/my%20files/Desktop/project/SentinelAPK/backend/analyzer.py#L108-L140) implements a zip-level fallback parser that reads plain text `AndroidManifest.xml` files using regex.

2. **DEX Bytecode Scan Indicators**
   * *Claim*: The platform scans decompressed `classes.dex` files for automated behavior patterns.
   * *Evidence*: [analyzer.py:L206-235](file:///c:/Users/YUVARAJ%20KHOT/my%20files/Desktop/project/SentinelAPK/backend/analyzer.py#L206-L235) scans bytes of DEX files inside the APK ZIP to locate API keywords like `SmsManager` and `AccessibilityService`.

3. **Validation Gated Weight Calibration**
   * *Claim*: Weights adjustments are rolled back if the F1-score or accuracy on the validation split decreases.
   * *Evidence*: [adaptive_learning.py:L160-205](file:///c:/Users/YUVARAJ%20KHOT/my%20files/Desktop/project/SentinelAPK/backend/adaptive_learning.py#L160-L205) compares validation metrics and rolls back changes if metrics degrade.

4. **India Banking Clone Detection**
   * *Claim*: Spoofing attempts on major Indian banks are identified using label sequence matcher ratios and signature matching.
   * *Evidence*: [risk_engine.py](file:///c:/Users/YUVARAJ%20KHOT/my%20files/Desktop/project/SentinelAPK/backend/risk_engine.py) computes similarity metrics against bank brands defined in [official_banks.json](file:///c:/Users/YUVARAJ%20KHOT/my%20files/Desktop/project/SentinelAPK/backend/data/official_banks.json).

5. **XAI Rationale Fallback Engine**
   * *Claim*: The platform provides explaining rationale of threat findings when offline.
   * *Evidence*: [llm_client.py:L120-170](file:///c:/Users/YUVARAJ%20KHOT/my%20files/Desktop/project/SentinelAPK/backend/llm_client.py#L120-L170) provides a regex local rule-based descriptor engine when connection to Vertex AI fails.

---

## Unsupported Claims (Simulated/Future Scope)

The following claims are simulated or are not implemented in the current codebase:

1. **Dynamic Sandbox Telemetry**
   * *Unsupported Claim*: The platform executes the APK inside a sandboxed Android Emulator and records live network socket traffic.
   * *Fact*: No physical emulator or dynamic analysis framework is integrated. Network and execution telemetries are mock structures.

2. **Autonomous Evasive Bytecode Generation**
   * *Unsupported Claim*: The Evader LLM automatically writes modified Dalvik bytecode to rebuild evasive APK files.
   * *Fact*: The Evader LLM (`evader_agent.py`) suggests textual evasion strategies; it does not compile Dalvik bytecode.

3. **Visual Screen Deception Checking**
   * *Unsupported Claim*: The system compares screenshot pixel layouts of APKs against reference interfaces using computer vision.
   * *Fact*: UI checking is text-based (comparing package and label similarity ratios). It does not analyze screenshots or pixel layouts.

4. **Threat Graph Visual Engine**
   * *Unsupported Claim*: Interactive graphical nodes connect threat execution points inside the frontend dashboard.
   * *Fact*: No graphical node library is implemented. Threats are rendered as a sequential list of steps.
