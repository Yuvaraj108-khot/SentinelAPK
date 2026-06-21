# Presentation Deck: SentinelAPK

## Slide 1: Problem
**Title:** The Black Box of Mobile Security
- Cloud telemetry invades privacy.
- Offline devices remain unprotected.
- Security alerts lack explainability for end-users.
*Speaker Notes:* Emphasize that users don't know *why* their apps are blocked, and sending private APKs to the cloud is a privacy risk.

## Slide 2: Solution
**Title:** SentinelAPK
- Purely local static analysis engine.
- Deterministic risk scoring.
- Groq-powered human-readable explainability.
*Speaker Notes:* We bring transparency back to the user without sacrificing speed.

## Slide 3: Architecture
**Title:** System Architecture
- APK -> Analyzer -> Risk Engine -> Groq -> PDF.
*Speaker Notes:* The pipeline is strictly unidirectional. The LLM does not make decisions.

## Slide 4: Detection Pipeline
**Title:** Static Code Parsing
- Parses DEX bytecode and AndroidManifest natively.
- Extracts URLs, Strings, and API callbacks.
*Speaker Notes:* We look for things like DexClassLoader, Runtime.exec, and Accessibility callbacks.

## Slide 5: Clone Detection
**Title:** Catching the Masquerade
- Uses Levenshtein distance on package and app names.
- Validates official certificate fingerprints.
*Speaker Notes:* We can catch Banking Trojans that spoof legitimate UI components.

## Slide 6: Evidence Validation
**Title:** No Evidence = No Detection
- Every risk score is tied to an exact byte offset.
- Eliminates AI hallucination.
*Speaker Notes:* The most critical slide. We don't guess. We point to the exact line of code.

## Slide 7: False Positive Reduction
**Title:** Refining the Engine
- Reduced false positives by over 60%.
- Certificate redesign handles Open Source apps natively.
*Speaker Notes:* We adjusted the engine to respect 'Unknown' valid certificates, saving apps like F-Droid.

## Slide 8: Real World Validation
**Title:** Validation & Metrics
- Tested on 50 real-world applications.
- 86.2% Accuracy on benign datasets.
- Zero fabricated metrics.
*Speaker Notes:* We were honest about our API limits on malware downloads.

## Slide 9: Limitations
**Title:** Static Analysis Boundaries
- Cannot distinguish legitimate capabilities (VLC PiP) from malicious behavior (Tapjacking).
*Speaker Notes:* The difference between a feature and an exploit is intent, which static analysis struggles with.

## Slide 10: Future Work
**Title:** The Road Ahead
- Control Flow Graph (CFG) analysis.
- Expanded trusted certificate registries.
*Speaker Notes:* We want to analyze *how* a permission is used.
