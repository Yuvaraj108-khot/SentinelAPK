# Judge Q&A Preparation

**What makes SentinelAPK different?**
It performs purely static analysis on-device without relying on external cloud APIs, ensuring user privacy.

**Does AI make security decisions?**
No. Security decisions are made deterministically by the Risk Engine. AI (Groq) is used purely for generating human-readable explanations of the deterministic verdict.

**How is Groq used?**
Groq takes the JSON output of the Risk Engine and generates a natural language summary and mitigation advice at LPU speeds.

**How does clone detection work?**
It calculates Levenshtein distance between the analyzed app name/package name and a registry of known banking apps, combined with certificate fingerprint verification.

**How are certificates validated?**
Certificates are extracted and hashed (SHA256). The hash is checked against a trusted registry. Legitimate but unknown certs carry 0 penalty; missing/malformed certs carry a +10 penalty.

**What real-world testing was performed?**
Tested against 50 real-world applications (open-source utilities, security tools, banking apps). Achieved 86.2% accuracy on the benign dataset.

**What are current limitations?**
Static analysis struggles to differentiate between a legitimate capability (e.g., a screen reader using accessibility) and malicious intent (e.g., a keylogger using accessibility).

**What would be built next?**
Control Flow Graph (CFG) tracing to determine *how* a permission is used, rather than just *if* it is requested.
