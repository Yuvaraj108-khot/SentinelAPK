# DEX Evidence Extraction Roadmap (V2.5)

## Objective
Replace weak, naive byte-matching indicators with precise, verifiable DEX-level evidence extraction using cross-reference (XREF) analysis and structured Call Graphs.

## Evidence Schema
All extracted evidence will strictly adhere to the following schema to ensure high-fidelity contextual tracking:

```json
{
  "class_name": "Target API Class",
  "method_name": "Target API Method",
  "caller": "The Class/Method invoking the target API",
  "dex_offset": "Integer representation of the DEX bytecode offset",
  "evidence_type": "CROSS_REFERENCE_CALL",
  "confidence": 0.0
}
```

## Prioritized Implementation Targets

### 1. `Runtime.exec` (System Commands)
- **Target:** `Ljava/lang/Runtime;->exec` or `Ljava/lang/ProcessBuilder;->start`
- **Methodology:** Utilize DalvikVMFormat parsing to identify all direct method invocations. 
- **Goal:** Differentiate between a terminal emulator natively executing binaries versus a hidden dropper executing an illicit payload.

### 2. `DexClassLoader` (Dynamic Code Loading)
- **Target:** `Ldalvik/system/DexClassLoader;-><init>` and `Ldalvik/system/PathClassLoader;-><init>`
- **Methodology:** Extract the calling class to determine if the dynamic loading originates from the main application package or an obfuscated third-party SDK.

### 3. Accessibility APIs (Input Capture / Fraud)
- **Target:** Subclasses extending `Landroid/accessibilityservice/AccessibilityService;`
- **Methodology:** Identify the specific overridden methods (e.g., `onAccessibilityEvent`). Extract the XREFs invoking `AccessibilityNodeInfo` retrieval or automated click injections.

### 4. Reflection APIs (Obfuscation / Evasion)
- **Target:** `Ljava/lang/reflect/Method;->invoke` and `Ljava/lang/Class;->forName`
- **Methodology:** Extract call chains leading to reflection to determine if it is used for standard generic programming patterns or actively hiding malicious API invocations (like invoking `DexClassLoader` via reflection).

### 5. SMS APIs (OTP Theft / Premium SMS)
- **Target:** `Landroid/telephony/SmsManager;->sendTextMessage` and `android.provider.Telephony.SMS_RECEIVED` broadcast receivers.
- **Methodology:** Trace the data flow from `SmsMessage.getMessageBody()` to identify if the caller subsequently invokes network APIs (`HttpURLConnection`) to exfiltrate the data.

### 6. WebView APIs (Phishing / JavaScript Bridges)
- **Target:** `Landroid/webkit/WebView;->addJavascriptInterface` and `Landroid/webkit/WebView;->loadUrl`
- **Methodology:** Capture the exact class injecting the JavaScript bridge. Identify if the bridge exposes dangerous native methods (like file system access or credential retrieval) to the WebView instance.

## Call Graph Support Strategy
To increase evidence maturity, simple existence checks will be upgraded to full Call Chain mapping.
Instead of reporting:
`Runtime.exec exists`

The V2.5 engine will use bytecode parsing to report:
`MalwareLoader.start() -> PayloadManager.load() -> Runtime.exec()`

This guarantees "No Evidence = No Detection". If the call chain cannot be explicitly proven, the capability is deemed unverified.
