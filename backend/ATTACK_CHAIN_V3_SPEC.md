# Attack Chain Hardening Specifications (V3)

## The Problem with V2
In SentinelAPK V2, an Attack Chain like `SMS to OTP Interception` was triggered merely by the intersection of three capabilities:
`[SMS] + [Accessibility] + [Internet] = OTP Theft Attack Chain`

This resulted in massive false positives for legitimate apps like Element, WhatsApp, or any other messaging/accessibility-enabled application.

## V3 Hardening Rule: Context + Intent

In V3, Attack Chains are no longer triggered purely by capability combinations. They mandate that the Trust Context Engine output `MALICIOUS_USE` and the Intent Validation Engine output `MALICIOUS` intent before an attack chain can be fully formed.

### Hardened Chain: OTP Theft
**New Requirement for Triggering:**
1. **Capabilities Present:** `SMS` + `Accessibility`
2. **Intent Evidence:** Explicit Credential Collection Evidence (e.g., regex matching OTPs, known C2 extraction methods).
3. **Trust Context:** `SUSPICIOUS_USE` or `MALICIOUS_USE` (e.g., lacks a legitimate category or has untrusted certificates).

If Context == `LEGITIMATE_USE` and Intent == `BENIGN_CAPABILITY`, the attack chain formulation is **ABORTED**.

### Hardened Chain: Credential Theft via Overlay
**New Requirement for Triggering:**
1. **Capabilities Present:** `Overlay`
2. **Intent Evidence:** Evidence of phishing payload structures.
3. **Trust Context:** `MALICIOUS_USE` (e.g., clone indicators present mimicking a banking app, untrusted certificate).

If Context == `LEGITIMATE_USE` (e.g., a media player like VLC using overlay for PiP), the attack chain formulation is **ABORTED**.
