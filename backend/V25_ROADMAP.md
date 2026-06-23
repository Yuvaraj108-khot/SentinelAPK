# SentinelAPK V2.5 Implementation Roadmap

## Overview
The V2.5 phase strictly focuses on maturing the static evidence gathering engine. It replaces weak indicators (like Manifest presence or raw byte matching) with structured, verifiable Dalvik bytecode Call Graphs. It adheres strictly to the rule: "No Evidence = No Detection," without relying on external trust scores or AI reasoning layers.

## Evidence Quality Improvements
The transition to V2.5 introduces a paradigm shift in evidence quality:
1. **Contextual Provenance**: Instead of reporting that `Runtime.exec` exists, the engine will extract the exact `class_name`, `method_name`, `dex_offset`, and `caller`. This provides concrete provenance for *how* and *where* a capability is invoked.
2. **Call Chain Generation**: Simple boolean checks are replaced by static call chains (`callee -> caller -> call chain`). This allows the engine to link discrete capabilities (e.g., SMS extraction leading directly to a Network socket) rather than assuming risk based on their mutual presence in the Manifest.
3. **Obfuscation Resilience**: By parsing actual method invocations instead of substring matching, the engine becomes resilient against basic string obfuscation and variable renaming techniques.

## Detector Maturity Improvements
The current `dex_behavior_analyzer.py` utilizes basic `byte_matching` strings (e.g., `b"Ljava/lang/Runtime;->exec"`), which is a primitive and highly error-prone extraction method.

The V2.5 roadmap matures the detector by implementing formal DalvikVMFormat parsing. Detectors will now natively navigate cross-references (XREFs) to map the execution flow for:
- Runtime System Executions (`Runtime.exec`)
- Dynamic Class Loaders (`DexClassLoader`)
- Accessibility Service event handling
- SMS Broadcast Receiver handling
- Reflection API invocations
- WebView JavaScript Bridges

## Expected Impact
By demanding concrete execution flows (Call Chains) instead of raw capability presence, the V2.5 engine forces a higher burden of proof before generating an evidence flag. This structurally prevents the pipeline from flagging dormant, unused, or benign implementations of sensitive APIs. The expected impact is a significantly cleaner, more deterministic, and highly verifiable evidence payload delivered to the downstream analysis layers.

---

## FINAL VERDICT

**HIGH_IMPACT**

Based solely on the massive improvements in evidence extraction quality, transitioning to structural Call Graph mapping provides a **HIGH_IMPACT** upgrade. It eliminates the fragile dependency on substring matching and drastically raises the maturity of the detection engine by requiring concrete, verifiable code paths to substantiate any claimed capability.
