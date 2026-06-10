import csv
import json
import os
import argparse
from pathlib import Path

import pandas as pd

from detection.evaluation_engine import EvaluationEngine
from detection.rules import FrameRuleEngine


THRESHOLDS_PATH = "packet_reader/thresholds.json"


SUMMARY_FIELDS = [
    "frame_num",
    "pmu_id",
    "stream_id",
    "frame_score",
    "normalized_score",
    "rule_severity",
    "classification",
    "final_severity",
    "confidence",
    "assessment",
    "corrupted",
    "rules_triggered",
    "cyber_score",
    "fault_score",
    "disturbance_score",
    "disturbance_raw_score",
    "suspicious_count",
    "dominant_reason",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the PMU rules engine over a decoded CSV file")
    parser.add_argument("input_csv", nargs="?", default="data/pmu_data_10min.csv", help="Decoded PMU CSV to evaluate")
    parser.add_argument("--thresholds", default=THRESHOLDS_PATH, help="Thresholds JSON path")
    parser.add_argument("--jsonl-output", help="Full JSONL output path")
    parser.add_argument("--csv-summary", help="Compact CSV summary output path")
    return parser.parse_args()


def default_output_paths(input_csv: str) -> tuple[str, str]:
    stem = Path(input_csv).stem
    return f"data/{stem}_rules_output.jsonl", f"data/{stem}_rules_summary.csv"


def main() -> None:
    args = parse_args()
    jsonl_output_path, csv_summary_path = default_output_paths(args.input_csv)
    jsonl_output_path = args.jsonl_output or jsonl_output_path
    csv_summary_path = args.csv_summary or csv_summary_path

    df = pd.read_csv(args.input_csv)
    engine = FrameRuleEngine(threshold_file=args.thresholds)
    evaluator = EvaluationEngine(args.thresholds)

    os.makedirs("data", exist_ok=True)
    history = []
    summary_rows = []
    classification_counts = {}
    rule_counts = {}

    with open(jsonl_output_path, "w", encoding="utf-8") as jsonl_file:
        for record in df.to_dict(orient="records"):
            history.append(record)
            history_df = pd.DataFrame(history[-100:])

            result = engine.evaluate_frame(record, history_df)
            evaluation = evaluator.evaluate(record, result, engine.get_stream_state(record))

            result["evaluation"] = evaluation
            result["rule_severity"] = result["severity"]
            result["classification"] = evaluation["classification"]
            result["confidence"] = evaluation["confidence"]
            result["dominant_reason"] = evaluation["dominant_reason"]
            result["severity"] = evaluation["severity"]

            jsonl_file.write(json.dumps(result, default=str) + "\n")

            classification_counts[result["classification"]] = classification_counts.get(result["classification"], 0) + 1
            for rule_id in result["rules_triggered"]:
                rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

            summary_rows.append(
                {
                    "frame_num": result["frame_num"],
                    "pmu_id": result["details"].get("pmu_id"),
                    "stream_id": result["details"].get("stream_id"),
                    "frame_score": result["frame_score"],
                    "normalized_score": result["normalized_score"],
                    "rule_severity": result["rule_severity"],
                    "classification": result["classification"],
                    "final_severity": result["severity"],
                    "confidence": result["confidence"],
                    "assessment": result["assessment"],
                    "corrupted": result["corrupted"],
                    "rules_triggered": ";".join(result["rules_triggered"]),
                    "cyber_score": result["cyber_score"],
                    "fault_score": result["fault_score"],
                    "disturbance_score": result["disturbance_score"],
                    "disturbance_raw_score": result.get("disturbance_raw_score", result["disturbance_score"]),
                    "suspicious_count": result["suspicious_count"],
                    "dominant_reason": result["dominant_reason"],
                }
            )

    with open(csv_summary_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(summary_rows)

    top_rules = sorted(rule_counts.items(), key=lambda item: item[1], reverse=True)[:10]
    print(
        json.dumps(
            {
                "input": args.input_csv,
                "frames_processed": len(summary_rows),
                "jsonl_output": jsonl_output_path,
                "csv_summary": csv_summary_path,
                "classifications": classification_counts,
                "top_rules": top_rules,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
