# False Positive Reduction Plan

## Current Problem
The engine flags legitimate applications like VLC, Termux, and Element because capability presence (like `Runtime.exec` or Accessibility) is mistakenly treated as inherent risk.

## Reduction Strategies

### 1. Behavior Correlation over Isolated Capabilities
VLC uses `Runtime.exec` for underlying binary calls. It does NOT combine this with dynamic loading, evasion techniques, and a malicious certificate. The Threat Correlation Engine will score isolated `Runtime.exec` as LOW RISK.

### 2. Evidence Traceability
We require explicit context. Does the app just have the permission, or is it actively invoking malicious methods in the DEX? `dex_behavior_analyzer.py` will differentiate between dormant permissions and active abuse.

### 3. Trust Model
Applications like Element and Termux have established, verifiable signing certificates. The new Certificate Trust Model (TRUSTED/UNKNOWN/UNTRUSTED) will buffer scores for TRUSTED entities, preventing a high risk score based on generic capabilities alone.

### 4. Attack Chain Verification
If Termux uses `Runtime.exec`, does it complete the "Dropper Attack Chain"? No. Since the chain is incomplete, the final confidence and risk score will be reduced.
