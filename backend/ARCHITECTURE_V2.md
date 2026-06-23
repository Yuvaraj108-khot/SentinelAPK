# SentinelAPK V2 Architecture

## Overview
V2 introduces a multi-tiered analysis approach. Instead of static parsers directly influencing risk scores, parsers generate *Evidence*, which feeds into *Behavior Correlation*, which feeds into *Attack Chains*, which finally generate an *Explainable Threat Report*.

## Core Components

### 1. Evidence Extractors (Bottom Layer)
- **Manifest Analyzer**: Extracts permissions, components, and intent filters.
- **DexBehaviorAnalyzer**: Performs deep method reference and invocation analysis (replaces naive string matching).
- **Certificate Analyzer**: Extracts signatures and maps to the Trust Model.

### 2. Evidence Traceability Model (Middleware)
Validates that all findings conform to the V2 Evidence Schema:
```json
{
  "evidence_type": "STRING|OPCODE|API_CALL",
  "source_file": "classes.dex",
  "offset": 12044,
  "class_name": "Lcom/example/Payload;",
  "method_name": "stealData",
  "confidence": 0.95
}
```
Nothing may be classified without this evidence object.

### 3. Threat Correlation Engine (Upper Layer)
Reads the Evidence pool. Identifies when isolated capabilities form a dangerous combination. Outputs Correlated Threats.

### 4. Attack Chain Engine (Top Layer)
Takes Correlated Threats and structures them into actionable chains. Computes final Risk Score and Confidence.

### 5. Explainable Report Generator
Produces the final output answering: Why, What Evidence, Which Attack Chain, Which MITRE techniques, and What Confidence.
