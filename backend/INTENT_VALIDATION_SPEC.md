# Intent Validation Engine Specification (V3)

## Purpose
The Intent Validation Engine ensures that raw capabilities (e.g., requesting `RECEIVE_SMS` or `SYSTEM_ALERT_WINDOW`) are not automatically treated as malicious behavior. It actively seeks to prove *malicious intent* by validating whether the evidence contains active exploitation artifacts.

## Rules
- Overlay alone != Credential Theft
- SMS alone != OTP Stealer
- Accessibility alone != Fraud

## Inputs
1. `evidence_validation` (dict) - The raw evidence extracted from the APK (Manifest tags, Dex bytecodes, etc.)

## Output Schema
```json
{
    "intent": "MALICIOUS | BENIGN_CAPABILITY | BENIGN",
    "confidence": 0.0,
    "supporting_evidence": ["String explanations of the validated intent"]
}
```

## Validation Logic
Instead of checking `if permission in manifest`, the engine checks the `matched_string` and `extraction_method` of the evidence:
1. **SMS Validation**: If SMS capability is found, the engine scans the evidence string for known OTP parsing regexes or aggressive forwarding loops to C2 servers. If not found, the intent remains `BENIGN_CAPABILITY`.
2. **Overlay Validation**: If Overlay capability is found, the engine checks if the evidence points to a generic floating window (like a video player) or if it contains phishing activity structures (e.g., intercepting banking package names to display fake webviews).

## Example Scenario
**Element** (Messaging App) requests SMS permissions to handle text messages natively. V2 flagged this as an "OTP Interception" threat because it also had accessibility and internet. The V3 Intent Validation Engine examines the SMS evidence and finds it only points to standard `AndroidManifest.xml` tags without any C2 forwarding strings or explicit OTP regex extraction. It classifies the intent as `BENIGN_CAPABILITY`.
