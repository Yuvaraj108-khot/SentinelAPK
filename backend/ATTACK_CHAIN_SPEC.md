# Attack Chain Specification

## Philosophy
Replace independent capability scoring with structured attack chains. This context prevents false positives by ensuring the entire attack lifecycle exists.

## Target Output Structure
The Attack Chain Engine will output data in the following format:
```json
{
  "attack_chains": [
    {
      "name": "Credential Theft via Overlay",
      "steps": [
        "Initial Access (Clone Install)",
        "Privilege Escalation (Overlay Grant)",
        "Collection (Phishing Screen)",
        "Exfiltration (Network Post)"
      ],
      "confidence": 0.88
    }
  ],
  "risk_contributors": [
    "Unverified Certificate",
    "Overlay APIs",
    "Brand Impersonation"
  ],
  "confidence": 0.88
}
```

## Standard Chains

### 1. Overlay to Credential Theft
`Overlay Capability` -> `Detects Target Launch` -> `Draws Phishing Window` -> `Credential Exfiltration`

### 2. SMS to OTP Interception
`SMS Read Permission` -> `Detects Incoming Message` -> `Parses OTP Regex` -> `Forwards to C2`

### 3. Accessibility to Automated Fraud
`Accessibility Service Grant` -> `Reads View Hierarchy` -> `Auto-clicks Transfer Buttons`

### 4. Clone to Brand Impersonation
`Package Name Similarity` -> `Icon/Label Theft` -> `Trust Abuse`
