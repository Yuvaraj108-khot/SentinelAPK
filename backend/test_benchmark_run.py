import json
from benchmark import BenchmarkEngine
from dataset_validator import DatasetValidator
from improvement_tracker import ImprovementTracker

def run_test():
    print("=== STEP 1: VALIDATING DATASET ===")
    validator = DatasetValidator()
    val_report = validator.validate_dataset()
    print(json.dumps(val_report, indent=2))

    print("\n=== STEP 2: RUNNING BENCHMARK RUN 1 (BASELINE) ===")
    engine = BenchmarkEngine()
    run1 = engine.run_benchmark()
    print(f"Run ID: {run1['run_id']}")
    print(f"Dataset Hash: {run1['dataset_hash']}")
    print(f"Metrics: {json.dumps(run1['metrics'], indent=2)}")

    print("\n=== STEP 3: RUNNING BENCHMARK RUN 2 (COMPARISON) ===")
    run2 = engine.run_benchmark()
    print(f"Run ID: {run2['run_id']}")
    print(f"Metrics: {json.dumps(run2['metrics'], indent=2)}")

    print("\n=== STEP 4: TRACKING IMPROVEMENTS ===")
    tracker = ImprovementTracker()
    deltas = tracker.get_improvement_deltas()
    print(json.dumps(deltas, indent=2))

if __name__ == "__main__":
    run_test()
