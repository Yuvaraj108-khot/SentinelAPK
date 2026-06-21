# SentinelAPK

Evidence-Driven Android APK Security Analysis Platform

Detects:
- Banking App Clones
- Certificate Forgery
- Overlay Abuse
- Dynamic Loading
- High-Risk Android Behaviors

Built with:
Next.js • FastAPI • Python • Groq • MITRE ATT&CK

## Overview

SentinelAPK is an evidence-driven Android APK security analysis platform designed to detect suspicious applications, banking clones, certificate forgery, and high-risk behaviors through static analysis.

Unlike traditional AI-based scanners, SentinelAPK follows a strict:

> No Evidence = No Detection

philosophy.

Every detection must be backed by observable evidence extracted from the APK itself.

---

## Problem Statement

Android malware continues to evolve through:

* Banking trojans
* Clone applications
* Certificate forgery
* Overlay attacks
* SMS interception
* Dynamic code loading

Most security tools provide opaque risk scores without showing the underlying evidence.

SentinelAPK was built to make Android security analysis explainable, auditable, and evidence-driven.

---

## Key Features

### APK Static Analysis

Extracts:

* Package name
* App label
* Permissions
* SDK information
* Signing certificates
* DEX indicators

### Clone Detection

Detects:

* Same-package forgery
* Brand impersonation
* Banking application clones
* Certificate mismatches

### Certificate Validation

Verifies:

* Trusted certificates
* Unknown certificates
* Untrusted certificates
* Signature mismatches

### Evidence Validation Registry

Every finding includes:

* Evidence source
* Extraction method
* Confidence
* Byte offset (where available)

### MITRE ATT&CK Mapping

Maps observed behaviors to:

* Dynamic code loading
* SMS collection
* Accessibility abuse
* Overlay abuse
* Masquerading

### Explainable Reports

Groq generates human-readable explanations from validated evidence.

Groq does NOT:

* Detect malware
* Calculate scores
* Perform clone detection
* Validate certificates

The Risk Engine remains the source of truth.

---

## Architecture

```text
APK Upload
    ↓
APK Analyzer
    ↓
Evidence Validation
    ↓
Risk Engine
    ↓
MITRE Mapping
    ↓
Groq Explainability
    ↓
PDF / JSON Reports
```

---

## Detection Pipeline

### Step 1 — APK Analysis

The analyzer extracts:

* Manifest permissions
* Application metadata
* Signing information
* DEX indicators

### Step 2 — Evidence Validation

All findings are validated against extracted evidence.

Findings without evidence are marked:

```text
UNKNOWN
```

and do not contribute to detection decisions.

### Step 3 — Risk Scoring

The Risk Engine evaluates:

* Permissions
* Clone indicators
* Certificate status
* DEX indicators
* Learning-based retrieval

### Step 4 — MITRE Mapping

Evidence-backed behaviors are mapped to relevant ATT&CK techniques.

### Step 5 — Explainability

Groq converts structured evidence into readable security reports.

---

## Demo Scenarios

### SecureBank Official

Result:

* SAFE
* Trusted Certificate
* Clone Risk LOW
* Score 0

### SecureBank Plus

Result:

* Overlay Abuse
* Package Impersonation
* Untrusted Certificate

### SecureBank Clone

Result:

* Same Package Forgery
* Certificate Mismatch
* Clone Detection FOUND
* MALICIOUS

---

## Validation Summary

Real APK Validation:

* 29 real APKs analyzed
* F-Droid packages
* GitHub releases
* Certificate extraction verified

False Positive Reduction:

* Initial False Positives: 15
* Final False Positives: 4

Accuracy:

* 86.2% on real benign validation corpus

---

## Known Limitations

Current limitations include:

* Dynamic analysis not implemented
* Runtime monitoring not implemented
* Malware corpus expansion pending AndroZoo access approval
* Behavioral intent detection is limited by static analysis

---

## Future Work

* Dynamic sandbox execution
* Runtime behavior monitoring
* Expanded malware evaluation corpus
* Behavior-aware threat correlation
* Advanced Android malware family detection

---

## Tech Stack

Frontend:

* Next.js
* React
* TypeScript
* Tailwind CSS

Backend:

* Python
* FastAPI

Security Components:

* Androguard
* Groq
* MITRE ATT&CK Mapping
* Evidence Validation Engine

---

## License

Academic Research Prototype
