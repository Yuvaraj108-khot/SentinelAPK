# Competitive Differentiation: Why SentinelAPK Wins

**Generic APK Scanners vs. SentinelAPK**

1. **Evidence Registry & Auditability**
   - *Generic Scanners:* Output "Suspicious" based on opaque heuristics or closed-source cloud machine learning.
   - *SentinelAPK:* Uses a strict "No Evidence = No Detection" registry. Every triggered rule points to an exact byte offset and source file (e.g., `classes.dex`, offset `8286670`).

2. **Hallucination Prevention**
   - *Generic AI Scanners:* Feed decompiled code directly into LLMs, leading to massive hallucinations and false positives.
   - *SentinelAPK:* The LLM is isolated from the decision-making process. The Risk Engine is 100% deterministic. The LLM only translates the final JSON, making hallucinations impossible.

3. **Clone Detection**
   - *Generic Scanners:* Rely on hash blacklists.
   - *SentinelAPK:* Computes Levenshtein distance on package names and enforces certificate fingerprint matching to proactively catch zero-day spoofed banking apps.

4. **MITRE Mapping**
   - *Generic Scanners:* Provide basic flags.
   - *SentinelAPK:* Automatically maps extracted evidence directly to MITRE ATT&CK Mobile techniques (e.g., T1418 Overlay Abuse).

5. **Explainability**
   - *Generic Scanners:* Target security engineers.
   - *SentinelAPK:* Uses Groq to generate instantaneous, human-readable PDF reports so end-users understand exactly *why* their device is at risk.
