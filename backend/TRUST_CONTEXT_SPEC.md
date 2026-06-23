# Trust Context Engine Specification (V3)

## Purpose
The Trust Context Engine resolves the critical flaw of V1 and V2: Capability Correlation != Malicious Intent. It acts as an arbiter that evaluates the *context* surrounding an application's capabilities to distinguish `LEGITIMATE_USE` from `MALICIOUS_USE`.

## Inputs
1. `package_name` (str)
2. `certificate_status` (str)
3. `clone_indicators` (dict)
4. `app_category` (str)
5. `behavioral_threats` (list)
6. `attack_chains` (list)

## Output Schema
```json
{
    "trust_context": "LEGITIMATE_USE | MALICIOUS_USE | SUSPICIOUS_USE | UNKNOWN",
    "confidence": 0.0,
    "reasoning": ["String explanations of the context derivation"]
}
```

## Core Heuristics
1. **Category Entitlement**: A media player (e.g., VLC) is explicitly entitled to `SYSTEM_ALERT_WINDOW` for Picture-in-Picture logic. A terminal emulator (e.g., Termux) is entitled to `Runtime.exec`.
2. **Reputation Anchoring**: If an application is firmly anchored by a `TRUSTED` certificate and lacks `clone_indicators`, its requested capabilities are assumed to be benign features unless proven otherwise by dynamic payload execution.
3. **Malicious Context**: If an application possesses `clone_indicators` (e.g., impersonating a bank) and triggers behavioral threats, the context immediately snaps to `MALICIOUS_USE`.

## Example Processing

| Application | Input Category | Cert Status | Output Context | Reason |
| :--- | :--- | :--- | :--- | :--- |
| **VLC** | Media Player | TRUSTED | `LEGITIMATE_USE` | Overlay capability is standard for media players. Cert is trusted. |
| **Element** | Messaging Platform | TRUSTED | `LEGITIMATE_USE` | SMS access is required for messaging. Cert is trusted. |
| **SecureBank Clone** | Banking Impersonation | UNTRUSTED | `MALICIOUS_USE` | Clone indicators active alongside untrusted signing and overlay requests. |
