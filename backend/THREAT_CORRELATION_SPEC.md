# Threat Correlation Specification

## Philosophy
Capabilities are not inherently malicious; combinations of capabilities coupled with specific intent are. The engine must evolve from Capability Detection to Behavior Correlation Detection.

## Correlation Rules

### LOW RISK (Isolated Capabilities)
If these exist independently with no correlating factors, they contribute minimally to the risk score:
- **Overlay Only**: Legitimate use cases include chat heads, screen recorders.
- **Accessibility Only**: Legitimate use cases include automation tools, password managers, assistive tech.
- **Dynamic Loading Only**: Legitimate use cases include large games or plugin-based apps.
- **SMS Permission Only**: Legitimate use cases include default messaging apps, SMS backup tools.

### HIGH RISK (Correlated Combinations)
When the engine detects these combinations, the risk score is heavily escalated:

#### 1. Banking Impersonation
- **Conditions**: `Clone Detection (High Similarity)` + `Certificate Mismatch (UNTRUSTED/UNKNOWN)` + `Overlay Capability`
- **Result**: HIGH RISK. Indicates a fake app designed to draw overlays over legitimate apps.

#### 2. OTP Interception
- **Conditions**: `SMS Read/Receive` + `Accessibility Service` + `Network Communication/Exfiltration`
- **Result**: HIGH RISK. Indicates the app can silently intercept SMS messages and exfiltrate them.

#### 3. Execution / Dropper
- **Conditions**: `Dynamic Loading (DexClassLoader)` + `Runtime.exec` + `Reflection APIs`
- **Result**: HIGH RISK. Indicates the app is attempting to download and execute hidden payloads outside of static analysis view.
