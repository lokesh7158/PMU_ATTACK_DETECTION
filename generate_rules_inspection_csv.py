import argparse
import csv
import json
import os
from pathlib import Path
from typing import Any, Dict

import pandas as pd

from detection.evaluation_engine import EvaluationEngine
from detection.rules import FrameRuleEngine


DEFAULT_THRESHOLDS = "packet_reader/thresholds.json"
LABEL_NAMES = {
    "0": "NORMAL",
    "1": "ATTACK",
    "2": "FAULT",
}

APPENDED_FIELDS = [
    "rules_frame_num",
    "rules_classification",
    "rules_confidence",
    "rules_final_severity",
    "rules_dominant_reason",
    "rules_triggered",
    "rules_trigger_summary",
    "rules_frame_score",
    "rules_normalized_score",
    "rules_cyber_score",
    "rules_fault_score",
    "rules_disturbance_score",
    "rules_disturbance_raw_score",
    "rules_structural_score",
    "rules_timing_score",
    "rules_replay_score",
    "rules_physics_score",
    "rules_weighted_attack_score",
    "rules_weighted_fault_score",
    "rules_assessment",
    "rules_rule_severity",
    "rules_corrupted",
    "rules_persistent_anomaly",
    "rules_persistent_fault",
    "rules_recovery_count",
    "rules_fault_count",
    "rules_suspicious_count",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a compact per-frame PMU rule inspection CSV."
    )
    parser.add_argument(
        "input_csv",
        nargs="?",
        default="pmu_data_10min_replaced_labeled.csv",
        help="Decoded labeled PMU CSV to evaluate.",
    )
    parser.add_argument(
        "--thresholds",
        default=DEFAULT_THRESHOLDS,
        help="Thresholds JSON path.",
    )
    parser.add_argument(
        "--output",
        help="Output CSV path. Defaults to data/<input_stem>_rules_inspection.csv.",
    )
    return parser.parse_args()


def default_output_path(input_csv: str) -> str:
    stem = Path(input_csv).stem
    return f"data/{stem}_rules_inspection.csv"


def label_name(value: Any) -> str:
    if pd.isna(value):
        return ""
    text = str(value).strip()
    if text.endswith(".0"):
        text = text[:-2]
    return LABEL_NAMES.get(text, text)


def clean_value(value: Any) -> Any:
    return "" if pd.isna(value) else value


def build_row(record: Dict[str, Any], result: Dict[str, Any], evaluation: Dict[str, Any]) -> Dict[str, Any]:
    row = {key: clean_value(value) for key, value in record.items()}
    category_scores = result.get("category_scores", {})
    factors = evaluation.get("contributing_factors", {})
    row.update(
        {
            "rules_frame_num": result.get("frame_num"),
            "rules_classification": evaluation.get("classification", ""),
            "rules_confidence": evaluation.get("confidence", ""),
            "rules_final_severity": evaluation.get("severity", ""),
            "rules_dominant_reason": evaluation.get("dominant_reason", ""),
            "rules_triggered": ";".join(result.get("rules_triggered", [])),
            "rules_trigger_summary": ";".join(evaluation.get("trigger_summary", [])),
            "rules_frame_score": evaluation.get("frame_score", result.get("frame_score", "")),
            "rules_normalized_score": result.get("normalized_score", ""),
            "rules_cyber_score": evaluation.get("cyber_score", result.get("cyber_score", "")),
            "rules_fault_score": evaluation.get("fault_score", result.get("fault_score", "")),
            "rules_disturbance_score": evaluation.get("disturbance_score", result.get("disturbance_score", "")),
            "rules_disturbance_raw_score": result.get("disturbance_raw_score", ""),
            "rules_structural_score": category_scores.get("structural", ""),
            "rules_timing_score": category_scores.get("timing", ""),
            "rules_replay_score": category_scores.get("replay", ""),
            "rules_physics_score": category_scores.get("physics", ""),
            "rules_weighted_attack_score": factors.get("weighted_attack_score", ""),
            "rules_weighted_fault_score": factors.get("weighted_fault_score", ""),
            "rules_assessment": result.get("assessment", ""),
            "rules_rule_severity": result.get("severity", ""),
            "rules_corrupted": result.get("corrupted", ""),
            "rules_persistent_anomaly": evaluation.get("persistent_anomaly", ""),
            "rules_persistent_fault": evaluation.get("persistent_fault", ""),
            "rules_recovery_count": factors.get("recovery_count", ""),
            "rules_fault_count": factors.get("fault_indicators_in_window", ""),
            "rules_suspicious_count": result.get("suspicious_count", ""),
        }
    )
    return row


def main() -> None:
    args = parse_args()
    output_path = args.output or default_output_path(args.input_csv)

    df = pd.read_csv(args.input_csv)
    engine = FrameRuleEngine(threshold_file=args.thresholds)
    evaluator = EvaluationEngine(args.thresholds)

    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    history = []
    rows = []
    output_fields = list(df.columns) + [field for field in APPENDED_FIELDS if field not in df.columns]
    classifications: Dict[str, int] = {}

    for record in df.to_dict(orient="records"):
        history.append(record)
        history_df = pd.DataFrame(history[-100:])

        result = engine.evaluate_frame(record, history_df)
        evaluation = evaluator.evaluate(record, result, engine.get_stream_state(record))
        rows.append(build_row(record, result, evaluation))

        classification = evaluation.get("classification", "UNKNOWN")
        classifications[classification] = classifications.get(classification, 0) + 1

    with open(output_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=output_fields)
        writer.writeheader()
        writer.writerows(rows)

    print(
        json.dumps(
            {
                "input": args.input_csv,
                "output": output_path,
                "frames_processed": len(rows),
                "classifications": classifications,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
