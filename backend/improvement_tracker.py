import os
import json
from typing import Dict, Any

HISTORY_FILE = os.path.join(os.path.dirname(__file__), "data", "benchmark_history.json")

class ImprovementTracker:
    def __init__(self, history_file: str = HISTORY_FILE):
        self.history_file = history_file

    def get_improvement_deltas(self) -> Dict[str, Any]:
        """
        Reads historical benchmark runs to compute actual performance changes
        between the latest run and the immediately preceding run.
        """
        if not os.path.exists(self.history_file):
            return {
                "has_history": False,
                "latest_run": {},
                "previous_run": {},
                "deltas": {}
            }

        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                history = json.load(f)
        except Exception:
            return {
                "has_history": False,
                "latest_run": {},
                "previous_run": {},
                "deltas": {}
            }

        if len(history) < 1:
            return {
                "has_history": False,
                "latest_run": {},
                "previous_run": {},
                "deltas": {}
            }

        latest = history[-1]
        previous = history[-2] if len(history) >= 2 else None

        if not previous:
            return {
                "has_history": True,
                "latest_run": latest,
                "previous_run": {},
                "deltas": {
                    "accuracy_delta": 0.0,
                    "recall_delta": 0.0,
                    "f1_delta": 0.0
                }
            }

        accuracy_delta = latest.get("accuracy", 0.0) - previous.get("accuracy", 0.0)
        recall_delta = latest.get("recall", 0.0) - previous.get("recall", 0.0)
        f1_delta = latest.get("f1_score", 0.0) - previous.get("f1_score", 0.0)

        return {
            "has_history": True,
            "latest_run": latest,
            "previous_run": previous,
            "deltas": {
                "accuracy_delta": round(accuracy_delta, 2),
                "recall_delta": round(recall_delta, 2),
                "f1_delta": round(f1_delta, 2)
            }
        }
