# Benchmarking Framework Plan

## Goal
Measure real malware detection accuracy and verify false positive reduction in a repeatable way.

## Target Dataset
- **100 Benign APKs**: E.g., VLC, Element, Termux, NewPipe, Open-source tools.
- **100 Malware APKs**: E.g., Anubis, Cerberus, Alien, Teabot variants.

## Core Metrics
1. **Accuracy**: Overall correctness of the model.
2. **Precision**: Out of all APKs flagged malicious, how many actually were? (Measures false positives).
3. **Recall**: Out of all actual malware, how many did we catch? (Measures false negatives).
4. **F1 Score**: Harmonic mean of Precision and Recall.
5. **Confusion Matrix**: True Positives (TP), True Negatives (TN), False Positives (FP), False Negatives (FN).

## Implementation
`benchmark_framework.py` will iterate over the dataset, run the V2 engine, compare against ground truth labels, and output the matrix and metrics to JSON and Console.
