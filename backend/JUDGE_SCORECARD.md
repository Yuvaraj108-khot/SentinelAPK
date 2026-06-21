# Judge Scorecard: SentinelAPK

## Scores (1-10)
- **Innovation:** 9/10 (Unique approach combining local static analysis, deterministic risk scoring, and LLM-driven explainability without cloud telemetry).
- **Technical Complexity:** 8/10 (Deep AST/DEX bytecode parsing, Levenshtein distance for clone detection, custom adaptive risk engine).
- **Security Engineering:** 9/10 (Strict 'No Evidence = No Detection' policy maps directly to extracted bytecode offsets, preventing LLM hallucination).
- **Real World Applicability:** 8/10 (Runs completely offline, preserving privacy; accuracy is high on benign sets, though lacks dynamic analysis).
- **User Experience:** 9/10 (Groq LLM translates complex bytecode flags into readable, actionable human advice).
- **Explainability:** 10/10 (Every flagged item ties to an exact offset in AndroidManifest or classes.dex, mapped to MITRE ATT&CK).
- **Validation Quality:** 7/10 (Strong benign dataset validation proving FP reduction; however, malware validation was blocked by API constraints).
- **Demo Quality:** 9/10 (Clear distinction between Official, Plus/Suspicious, and Clone scenarios).

**Overall Score:** 8.6/10

## Strengths
- Transparent, auditable security decisions.
- Completely offline primary analysis.
- Hallucination-free LLM integration (LLM only explains, it does not decide).
- Extremely fast explainability via Groq LPUs.

## Weaknesses
- Malware validation incomplete due to 401 API issues.
- Static analysis struggles to differentiate between legitimate capabilities (e.g., VLC pip overlay) and malicious behaviors (e.g., tapjacking overlays).

## Likely Judge Questions
- *How do you know the LLM isn't hallucinating the security report?* -> "The LLM is strictly fed the Evidence Validation JSON from the deterministic Risk Engine. It acts as a translator, not a decision-maker."
- *Why did you score 0.0 on Malware F1?* -> "Honesty. MalwareBazaar API keys were rejected during validation, preventing malware downloads. We chose to report 0 rather than fabricate metrics."

## Likely Judge Concerns
- False positives from accessibility services.
- Evasion via packed/obfuscated DEX files.
