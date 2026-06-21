# SentinelAPK Final Submission Report

## 1. Project Overview
SentinelAPK is a purely static, on-device Android malware detection engine driven by deterministic rules and adaptive learning without relying on cloud APIs for primary detection.

## 2. Problem Statement
Current Android security relies heavily on cloud-based telemetry which compromises privacy and fails offline. Open-source static analyzers are too slow for real-time validation.

## 3. Architecture
Static APK Analyzer -> Risk Engine -> Groq LLM Explainability.

## 4. APK Analysis Pipeline
Parses AndroidManifest and DEX bytecode locally using Androguard to extract capabilities and structural indicators.

## 5. Risk Engine
A deterministic scoring system mapping capabilities to risk weights with hard ceilings to prevent runaway scores.

## 6. Clone Detection
Cross-references package names and application labels against a known brand registry and computes Levenshtein distances to detect impersonation.

## 7. Certificate Validation
Checks certificate fingerprints against a trusted registry. Unrecognized valid certificates are scored 0 (UNKNOWN), missing/malformed certificates are scored +10 (UNTRUSTED).

## 8. Evidence Validation Registry
Strict enforcement of 'no evidence = no detection'. Every flag must tie back to specific manifest offsets or bytecode strings.

## 9. MITRE Mapping
Maps extracted evidence directly to MITRE ATT&CK Mobile techniques (e.g. T1647 SMS Collection, T1418 Overlay Abuse).

## 10. Groq Explainability Layer
Translates technical indicators and JSON outputs into human-readable security reports via fast LPU inference.

## 11. False Positive Reduction Campaign
Reduced false positives significantly by reclassifying Unknown certificates to 0 penalty, restoring trust to F-Droid and open-source applications.

## 12. Real World Validation
Validated against 29 real-world benign apps. Accuracy: 86.2%. (Malware evaluation blocked by API constraints but pipeline is ready).

## 13. Security Audits Completed
Capabilities vs Behaviors audit confirmed that overlay and reflection drove most benign false positives due to lack of behavioral context.

## 14. Current Limitations
Cannot distinguish between legitimate capability presence (e.g., VLC pip overlay) and malicious usage (e.g., tapjacking) via static analysis alone.

## 15. Future Work
Dynamic analysis integration, bytecode control-flow graph (CFG) analysis, and broader trusted certificate registries.
