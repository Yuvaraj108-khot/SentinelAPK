# SentinelAPK

## Problem
Current Android security tools rely heavily on cloud-based telemetry, which compromises user privacy, fails offline, and acts as a "black box" where users don't understand why an app was flagged. 

## Solution
SentinelAPK is a purely static, on-device Android malware detection engine. It uses deterministic rules for risk scoring and Groq-powered LLM inference to provide instant, human-readable explainability—all without relying on cloud APIs for detection.

## Features
- **Offline Static Analysis:** Parses DEX bytecode and manifests locally.
- **Clone Detection:** Identifies banking trojans masquerading as official apps using Levenshtein distance and certificate fingerprints.
- **Evidence-Backed Verdicts:** 'No Evidence = No Detection'. Every flag is tied to exact file offsets.
- **MITRE Mapping:** Automatically maps threats to the MITRE ATT&CK Mobile framework.
- **Groq Explainability:** Translates technical JSON into human-readable advice at LPU speeds.

## Architecture
APK
↓
Analyzer (Androguard)
↓
Evidence Validation
↓
Risk Engine
↓
MITRE Mapping
↓
Groq Explainability
↓
PDF Report

## Tech Stack
- **Language:** Python
- **Parsing:** Androguard
- **LLM:** Groq API (Llama 3)
- **Scoring:** Custom Deterministic Risk Engine

## Demo Screenshots Section
*(Insert Demo Screenshots Here)*
1. SecureBank Official (Safe)
2. SecureBank Plus (Suspicious)
3. SecureBank Clone (Malicious)

## Validation Results
- **Benign Accuracy:** 86.2%
- **False Positives Eliminated:** 6 (via Certificate Redesign)
- **Malware Detection:** Pipeline complete; currently awaiting API key resolution for MalwareBazaar.

## Known Limitations
- Cannot dynamically distinguish between legitimate capabilities (e.g., PiP overlays) and malicious behaviors (e.g., tapjacking).
- Heavy obfuscation or packed APKs may bypass static string matching.

## Future Roadmap
- Control Flow Graph (CFG) analysis to determine *how* capabilities are used.
- On-device dynamic sandbox execution.
