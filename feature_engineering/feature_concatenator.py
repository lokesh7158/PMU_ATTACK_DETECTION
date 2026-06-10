"""Concatenate existing PMU features with selected rule summary fields."""

from __future__ import annotations

import csv
import os
from collections import OrderedDict
from typing import Any, Dict, Iterable, Mapping, Sequence

try:
    import pandas as pd
except ImportError:  # pragma: no cover - pandas is already required by feature extraction.
    pd = None


RULE_SUMMARY_FIELDS = [
    "frame_score",
    "normalized_score",
    "fault_score",
    "cyber_score",
    "disturbance_score",
    "structural_score",
    "timing_score",
    "replay_score",
    "physics_score",
    "hard_rule_count",
    "soft_rule_count",
    "frames_per_second",
]


class FeatureConcatenator:
    """Build final ML rows from feature-extractor output plus rule summaries."""

    def __init__(self, feature_columns: Sequence[str]):
        self.feature_columns = list(feature_columns)
        self.output_columns = self.feature_columns + RULE_SUMMARY_FIELDS

    def concatenate(
        self,
        feature_row: Mapping[str, Any],
        rule_result: Mapping[str, Any],
    ) -> OrderedDict:
        row = OrderedDict()
        feature_values = self._as_mapping(feature_row)
        for column in self.feature_columns:
            row[column] = self._number(feature_values.get(column, 0.0))

        rule_summary = self.rule_summary(rule_result)
        for column in RULE_SUMMARY_FIELDS:
            row[column] = rule_summary[column]
        return row

    def rule_summary(self, rule_result: Mapping[str, Any]) -> Dict[str, float]:
        categories = self._as_mapping(rule_result.get("category_scores", {}))
        ml_features = self._as_mapping(rule_result.get("ml_features", {}))
        windowed_stats = self._as_mapping(rule_result.get("windowed_stats", {}))

        return {
            "frame_score": self._number(rule_result.get("frame_score")),
            "normalized_score": self._number(rule_result.get("normalized_score")),
            "fault_score": self._number(rule_result.get("fault_score")),
            "cyber_score": self._number(rule_result.get("cyber_score")),
            "disturbance_score": self._number(rule_result.get("disturbance_score")),
            "structural_score": self._number(categories.get("structural")),
            "timing_score": self._number(categories.get("timing")),
            "replay_score": self._number(categories.get("replay")),
            "physics_score": self._number(categories.get("physics")),
            "hard_rule_count": self._number(ml_features.get("hard_rule_count")),
            "soft_rule_count": self._number(ml_features.get("soft_rule_count")),
            "frames_per_second": self._number(
                ml_features.get("frames_per_second", windowed_stats.get("frames_per_second"))
            ),
        }

    def write_csv_rows(self, path: str, rows: Iterable[Mapping[str, Any]]) -> None:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        with open(path, "a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.output_columns, extrasaction="ignore")
            if handle.tell() == 0:
                writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def _as_mapping(value: Any) -> Mapping[str, Any]:
        if isinstance(value, Mapping):
            return value
        if pd is not None and isinstance(value, pd.Series):
            return value.to_dict()
        return {}

    @staticmethod
    def _number(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default
