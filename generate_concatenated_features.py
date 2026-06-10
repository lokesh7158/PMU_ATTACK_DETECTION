import argparse
import csv
from collections import deque
from pathlib import Path

import pandas as pd

from detection.evaluation_engine import EvaluationEngine
from detection.rules import FrameRuleEngine
from feature_engineering import FeatureConcatenator
from feature_extraction import PMUFeatureExtractor


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate concatenated PMU feature + rule summary CSV")
    parser.add_argument("input_csv", help="Decoded PMU CSV input")
    parser.add_argument(
        "--output",
        help="Output CSV path. Defaults to data/<input_stem>_concatenated_features.csv",
    )
    parser.add_argument("--thresholds", default="packet_reader/thresholds.json", help="Threshold JSON path")
    parser.add_argument("--history-window", type=int, default=100, help="Rolling frame history size")
    return parser.parse_args()


def default_output_path(input_csv: str) -> str:
    input_path = Path(input_csv)
    return str(Path("data") / f"{input_path.stem}_concatenated_features.csv")


def main() -> None:
    args = parse_args()
    output_path = args.output or default_output_path(args.input_csv)

    df = pd.read_csv(args.input_csv)
    rule_engine = FrameRuleEngine(threshold_file=args.thresholds)
    evaluator = EvaluationEngine(args.thresholds)
    extractor = PMUFeatureExtractor(args.thresholds)
    concatenator = FeatureConcatenator(PMUFeatureExtractor.OUTPUT_COLUMNS)
    feature_df = extractor.extract_dataframe(df)

    history = deque(maxlen=max(args.history_window, 1))
    rows_written = 0

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=concatenator.output_columns)
        writer.writeheader()

        for record_index, record in enumerate(df.to_dict(orient="records")):
            history.append(record)
            history_df = pd.DataFrame(list(history))

            rule_result = rule_engine.evaluate_frame(record, history_df)
            evaluation = evaluator.evaluate(record, rule_result, rule_engine.get_stream_state(record))
            rule_result["evaluation"] = evaluation
            rule_result["rule_severity"] = rule_result["severity"]
            rule_result["classification"] = evaluation["classification"]
            rule_result["confidence"] = evaluation["confidence"]
            rule_result["dominant_reason"] = evaluation["dominant_reason"]
            rule_result["severity"] = evaluation["severity"]

            feature_row = feature_df.loc[record_index].reindex(PMUFeatureExtractor.OUTPUT_COLUMNS)
            writer.writerow(concatenator.concatenate(feature_row, rule_result))
            rows_written += 1

    print(f"Concatenated feature CSV written to {output_path}")
    print(f"Rows written: {rows_written}")
    print(f"Columns written: {len(concatenator.output_columns)}")


if __name__ == "__main__":
    main()
