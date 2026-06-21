# SentinelAPK Demo Script
**Length:** 3-5 Minutes

**1. Introduce problem (0:00 - 0:45)**
"Hello! Today we're presenting SentinelAPK. The problem with modern mobile security is that it's a black box. Anti-viruses send your private APKs to the cloud, and tell you it's 'Malicious' without explaining why. We built an offline, deterministic static analysis engine augmented by Groq for explainability."

**2. Show SecureBank Official (0:45 - 1:30)**
"Let's look at a legitimate banking app. [Run Demo]. Notice the score is 0. The Risk Engine verified the certificate against our trusted registry and confirmed the package name matches exactly. No cloud API was contacted. It's completely SAFE."

**3. Show SecureBank Plus (1:30 - 2:15)**
"Now, a user downloads a 'Modded' version of the bank. [Run Demo]. Our engine flags it as Suspicious. Why? Because while the certificate is extracted (UNKNOWN status), we statically found `SYSTEM_ALERT_WINDOW` in the manifest and Accessibility callbacks in the DEX. The Groq layer translates this into a warning about potential screen-reading."

**4. Show SecureBank Clone (2:15 - 2:45)**
"Finally, a pure Banking Trojan. [Run Demo]. It's Malicious. SentinelAPK's Clone Detection caught a Same-Package Forgery: the package name matches SecureBank exactly, but the certificate fingerprint is untrusted. We caught the masquerade."

**5. Explain evidence validation (2:45 - 3:15)**
"Notice our 'No Evidence, No Detection' registry. Every single flag is tied to a specific byte offset in `classes.dex` or `AndroidManifest.xml`."

**6. Explain MITRE mapping & Groq isolation (3:15 - 4:00)**
"We map these offsets directly to MITRE ATT&CK techniques like T1418 Overlay Abuse. Groq is then fed this strict JSON. Because the LLM is isolated from decision-making, it cannot hallucinate security outcomes—it only explains them."

**7. Show generated report & Close (4:00 - 4:30)**
"Here is the final PDF report Groq generated in milliseconds. In the future, we plan to add Control Flow Graph analysis to further reduce false positives. Thank you!"
