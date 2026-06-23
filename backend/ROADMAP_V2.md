# SentinelAPK V2 Roadmap

## Goal
Transform SentinelAPK from a capability-based APK scanner into a serious, evidence-driven behavioral threat analysis platform.

## Implementation Order

### 1. Architectural Foundation (Highest Impact)
- Define V2 Architecture and Data Contracts (`ARCHITECTURE_V2.md`).
- Create Evidence Traceability Schema to ensure no capability is flagged without explicit offsets and confidence levels.

### 2. Behavioral Intelligence Layer
- **Threat Correlation Engine**: Move away from isolating capabilities. Build logic to score clusters (e.g., Overlay + Accessibility + Banking Keyword).
- **Attack Chain Engine**: Map correlated clusters to actual MITRE attack chains (e.g., SMS Interception Chain, Credential Theft Chain).

### 3. Deep Analysis Capabilities
- **Real DEX Intelligence**: Implement opcode-level analysis and call graph inspection in `dex_behavior_analyzer.py`, deprecating simple substring matches for APIs.
- **Certificate Trust Model**: Build the `TRUSTED/UNKNOWN/UNTRUSTED` state machine to heavily penalize known malicious or forged certificates while remaining neutral on unknown self-signed ones.

### 4. Continuous Evaluation
- **Benchmarking Framework**: Build a robust harness (`benchmark_framework.py`) capable of running 100 benign vs 100 malware samples to constantly calculate Precision, Recall, and F1.
- **False Positive Reduction Execution**: Apply the framework iteratively to eliminate false flags on common utility apps (VLC, Element, Termux).
