"""Feature engineering for decoded PMU frames.

This module turns decoded packet-reader rows into model-ready numeric features.
It intentionally does not perform rule evaluation, attack detection, scoring, or
classification.
"""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional

import numpy as np
import pandas as pd


LOGGER = logging.getLogger(__name__)


class PMUFeatureExtractor:
    """Build ML-ready engineered features from decoded PMU dataframe rows.

    Parameters
    ----------
    thresholds_path:
        Path to a thresholds JSON file produced by ``packet_reader.baseline_profiler``.
        PMU-specific expected values are loaded from the matching profile.
    """

    OUTPUT_COLUMNS = [
        "IA_mag",
        "IB_mag",
        "IC_mag",
        "VA_mag",
        "VB_mag",
        "VC_mag",
        "FREQ",
        "ROCOF",
        "inter_arrival_time",
        "network_delay",
        "delay_change",
        "packet_size",
        "payload_size",
        "fracsec",
        "crc_ok",
        "ROCOF_abs",
        "freq_change",
        "delta_VA_mag",
        "delta_VB_mag",
        "delta_VC_mag",
        "delta_IA_mag",
        "delta_IB_mag",
        "delta_IC_mag",
        "VA_ang_sin",
        "VA_ang_cos",
        "VB_ang_sin",
        "VB_ang_cos",
        "VC_ang_sin",
        "VC_ang_cos",
        "IA_ang_sin",
        "IA_ang_cos",
        "IB_ang_sin",
        "IB_ang_cos",
        "IC_ang_sin",
        "IC_ang_cos",
        "VAB_angle_diff_sin",
        "VAB_angle_diff_cos",
        "VBC_angle_diff_sin",
        "VBC_angle_diff_cos",
        "VCA_angle_diff_sin",
        "VCA_angle_diff_cos",
        "IAB_angle_diff_sin",
        "IAB_angle_diff_cos",
        "IBC_angle_diff_sin",
        "IBC_angle_diff_cos",
        "ICA_angle_diff_sin",
        "ICA_angle_diff_cos",
        "voltage_imbalance",
        "current_imbalance",
        "avg_voltage",
        "avg_current",
        "packet_size_error",
        "payload_size_error",
        "soc_diff",
        "soc_timing_error",
        "fracsec_diff",
    ]

    _MAG_COLUMNS = ("IA_mag", "IB_mag", "IC_mag", "VA_mag", "VB_mag", "VC_mag")
    _ANGLE_COLUMNS = ("IA_ang", "IB_ang", "IC_ang", "VA_ang", "VB_ang", "VC_ang")
    _PHASE_TO_PROFILE = {
        "IA": ("current", "ia"),
        "IB": ("current", "ib"),
        "IC": ("current", "ic"),
        "VA": ("voltage", "va"),
        "VB": ("voltage", "vb"),
        "VC": ("voltage", "vc"),
    }

    def __init__(self, thresholds_path: str | Path) -> None:
        self.thresholds_path = Path(thresholds_path)
        self.thresholds = self._load_thresholds(self.thresholds_path)
        self.pmu_profiles: Dict[str, Dict[str, Any]] = self.thresholds.get("pmu_profiles", {})
        self._last_row_by_pmu: Dict[str, Dict[str, Any]] = {}
        self.logger = LOGGER.getChild(self.__class__.__name__)

        if not self.pmu_profiles:
            self.logger.warning("No PMU profiles found in %s", self.thresholds_path)

    def extract_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Return engineered features for every input row.

        The returned dataframe preserves the input index and always contains
        exactly ``OUTPUT_COLUMNS`` in order. Missing source columns are handled
        as nulls and then converted to neutral numeric values.
        """

        if df.empty:
            return pd.DataFrame(columns=self.OUTPUT_COLUMNS, index=df.index)

        pmu_ids = self._series(df, "pmu_id").map(self._pmu_key).fillna("__default__")
        parts = []

        for pmu_key, index in pmu_ids.groupby(pmu_ids, sort=False).groups.items():
            profile = self._profile_for_pmu(None if pmu_key == "__default__" else pmu_key)
            group = df.loc[index]
            parts.append(self._extract_group(group, profile))

        features = pd.concat(parts).sort_index()
        features = features.reindex(columns=self.OUTPUT_COLUMNS)
        return features.apply(pd.to_numeric, errors="coerce").fillna(0.0)

    def extract_row(
        self,
        row: Mapping[str, Any] | pd.Series,
        history: Optional[pd.DataFrame] = None,
    ) -> pd.Series:
        """Return engineered features for a single PMU frame.

        This method keeps the previous raw row per PMU ID so delta and timing
        features are meaningful during realtime streaming. When a history window
        is available, the row is evaluated in the context of previous frames.
        """

        row_dict = dict(row.items()) if isinstance(row, pd.Series) else dict(row)
        pmu_key = self._pmu_key(self._value(row_dict, "pmu_id")) or "__default__"

        if history is not None and not history.empty:
            combined = pd.concat([history, pd.DataFrame([row_dict])], ignore_index=True)
            feature_row = self._extract_group(combined, self._profile_for_pmu(pmu_key)).iloc[-1]
        else:
            previous = self._last_row_by_pmu.get(pmu_key)
            if previous is None:
                frame = pd.DataFrame([row_dict])
                feature_row = self._extract_group(frame, self._profile_for_pmu(pmu_key)).iloc[-1]
            else:
                frame = pd.DataFrame([previous, row_dict])
                feature_row = self._extract_group(frame, self._profile_for_pmu(pmu_key)).iloc[-1]

        self._last_row_by_pmu[pmu_key] = row_dict
        return feature_row.reindex(self.OUTPUT_COLUMNS).apply(pd.to_numeric, errors="coerce").fillna(0.0)

    @staticmethod
    def _load_thresholds(path: Path) -> Dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"Thresholds file not found: {path}")
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError(f"Thresholds file must contain a JSON object: {path}")
        return data

    def _extract_group(self, df: pd.DataFrame, profile: Mapping[str, Any]) -> pd.DataFrame:
        features = pd.DataFrame(index=df.index)

        raw_mags = {name: self._numeric(self._series(df, name)) for name in self._MAG_COLUMNS}
        norm_mags = {
            name: self._normalize_by_profile_base(raw_mags[name], profile, name[:2])
            for name in self._MAG_COLUMNS
        }

        for name in self._MAG_COLUMNS:
            features[name] = norm_mags[name]

        freq = self._numeric(self._series(df, "freq1", "frequency", "FREQ"))
        nominal_freq = self._expected_frequency(profile)
        features["FREQ"] = self._relative_to_expected(freq, nominal_freq)

        rocof = self._numeric(self._series(df, "dfreq1", "rocof", "ROCOF"))
        rocof_scale = self._rocof_scale(profile)
        features["ROCOF"] = rocof / rocof_scale if rocof_scale else rocof

        timestamp_seconds = self._timestamp_seconds(df)
        inter_arrival = timestamp_seconds.diff().abs().fillna(0.0)
        expected_interval = self._expected_interval(profile)
        features["inter_arrival_time"] = (
            (inter_arrival - expected_interval) / expected_interval
            if expected_interval
            else inter_arrival
        )

        # Network delay and its change: prefer datetime difference between
        # `frame_time` and `capture_time` where available, falling back to
        # numeric seconds if needed.
        network_delay = self._network_delay(df)
        features["network_delay"] = network_delay.fillna(0.0)
        features["delay_change"] = features["network_delay"].diff().fillna(0.0)

        # Packet/payload sizes normalized relative to expected values from profile
        packet_size = self._numeric(self._series(df, "packet_size"))
        payload_size = self._numeric(self._series(df, "payload_size"))
        expected_packet_size = self._expected_size(profile, "packet_size", "packet_sizes")
        expected_payload_size = self._expected_size(profile, "payload_size", "payload_sizes")

        features["packet_size"] = self._relative_to_expected(packet_size, expected_packet_size)
        features["payload_size"] = self._relative_to_expected(payload_size, expected_payload_size)

        time_base = self._numeric(self._series(df, "time_base")).replace(0, np.nan)
        fracsec_raw = self._numeric(self._series(df, "fracsec"))
        features["fracsec"] = (fracsec_raw / time_base).where(time_base.notna(), fracsec_raw)
        features["crc_ok"] = self._bool_series(self._series(df, "crc_ok")).astype(float)

        features["ROCOF_abs"] = features["ROCOF"].abs()
        features["freq_change"] = features["FREQ"].diff().fillna(0.0)

        for name in ("VA_mag", "VB_mag", "VC_mag", "IA_mag", "IB_mag", "IC_mag"):
            features[f"delta_{name}"] = features[name].diff().fillna(0.0)

        angles = {
            name: self._angle_radians(self._numeric(self._series(df, name)))
            for name in self._ANGLE_COLUMNS
        }

        for name, values in angles.items():
            features[f"{name}_sin"] = np.sin(values)
            features[f"{name}_cos"] = np.cos(values)

        angle_pairs = {
            "VAB_angle_diff": angles["VA_ang"] - angles["VB_ang"],
            "VBC_angle_diff": angles["VB_ang"] - angles["VC_ang"],
            "VCA_angle_diff": angles["VC_ang"] - angles["VA_ang"],
            "IAB_angle_diff": angles["IA_ang"] - angles["IB_ang"],
            "IBC_angle_diff": angles["IB_ang"] - angles["IC_ang"],
            "ICA_angle_diff": angles["IA_ang"] - angles["IC_ang"],
        }
        for name, values in angle_pairs.items():
            features[f"{name}_sin"] = np.sin(values)
            features[f"{name}_cos"] = np.cos(values)

        voltage_cols = ["VA_mag", "VB_mag", "VC_mag"]
        current_cols = ["IA_mag", "IB_mag", "IC_mag"]
        features["voltage_imbalance"] = features[voltage_cols].std(axis=1)
        features["current_imbalance"] = features[current_cols].std(axis=1)
        features["avg_voltage"] = features[voltage_cols].mean(axis=1)
        features["avg_current"] = features[current_cols].mean(axis=1)

        expected_packet_size = self._expected_size(profile, "packet_size", "packet_sizes")
        expected_payload_size = self._expected_size(profile, "payload_size", "payload_sizes")
        features["packet_size_error"] = self._relative_to_expected(packet_size, expected_packet_size)
        features["payload_size_error"] = self._relative_to_expected(payload_size, expected_payload_size)

        soc = self._numeric(self._series(df, "soc"))
        features["soc_diff"] = soc.diff().fillna(0.0)
        features["soc_timing_error"] = (
            (features["soc_diff"] - expected_interval) / expected_interval
            if expected_interval
            else 0.0
        )
        features["fracsec_diff"] = features["fracsec"].diff().fillna(0.0)

        return features.reindex(columns=self.OUTPUT_COLUMNS).fillna(0.0)

    def _profile_for_pmu(self, pmu_id: Optional[str]) -> Dict[str, Any]:
        if pmu_id is not None and str(pmu_id) in self.pmu_profiles:
            return self.pmu_profiles[str(pmu_id)]
        if len(self.pmu_profiles) == 1:
            return next(iter(self.pmu_profiles.values()))
        self.logger.warning("No matching PMU profile for pmu_id=%s", pmu_id)
        return {}

    def _normalize_by_profile_base(
        self, series: pd.Series, profile: Mapping[str, Any], phase: str
    ) -> pd.Series:
        domain, key = self._PHASE_TO_PROFILE[phase]
        phase_profile = self._as_mapping(self._as_mapping(profile.get(domain)).get(key))
        base = self._positive_number(phase_profile.get("base"))
        if base is None:
            stats = self._as_mapping(phase_profile.get("stats"))
            base = self._positive_number(stats.get("mean"))
        if base is None:
            self.logger.debug("No %s base found in profile; leaving values unscaled", phase)
            return series
        return series / base

    def _expected_frequency(self, profile: Mapping[str, Any]) -> Optional[float]:
        frequency = self._as_mapping(profile.get("frequency"))
        return self._positive_number(frequency.get("mean"))

    def _rocof_scale(self, profile: Mapping[str, Any]) -> Optional[float]:
        candidates: Iterable[Any] = (
            self._as_mapping(profile.get("dfreq")).get("abs_p99"),
            self._as_mapping(profile.get("dfreq")).get("p99"),
            self._as_mapping(profile.get("dfreq")).get("std"),
            self._as_mapping(profile.get("rocof")).get("p99"),
            self._as_mapping(profile.get("rocof")).get("std"),
        )
        for value in candidates:
            scale = self._positive_number(value)
            if scale:
                return scale
        return None

    def _expected_interval(self, profile: Mapping[str, Any]) -> Optional[float]:
        rate = self._as_mapping(profile.get("rate"))
        interval = self._positive_number(rate.get("expected_interval_seconds"))
        if interval is not None:
            return interval

        interval = self._positive_number(self._as_mapping(profile.get("inter_arrival")).get("mean"))
        if interval is not None:
            return interval

        fps = self._positive_number(rate.get("expected_fps"))
        if fps is None:
            fps = self._positive_number(self._as_mapping(self.thresholds.get("metadata")).get("fps"))
        return 1.0 / fps if fps else None

    def _expected_size(
        self, profile: Mapping[str, Any], stats_key: str, identity_key: str
    ) -> Optional[float]:
        stats = self._as_mapping(profile.get(stats_key))
        expected = self._positive_number(stats.get("mean"))
        if expected is not None:
            return expected

        identity = self._as_mapping(profile.get("identity"))
        values = identity.get(identity_key, [])
        if isinstance(values, list) and values:
            numeric = [self._positive_number(value) for value in values]
            numeric = [value for value in numeric if value is not None]
            if numeric:
                return float(pd.Series(numeric).mode().iloc[0])
        return None

    def _timestamp_seconds(self, df: pd.DataFrame) -> pd.Series:
        timestamp = self._series(df, "timestamp")
        parsed = pd.to_datetime(timestamp, errors="coerce")
        if parsed.notna().any():
            return pd.Series(parsed.astype("int64") / 1_000_000_000, index=df.index).where(parsed.notna())

        soc = self._numeric(self._series(df, "soc"))
        fracsec = self._numeric(self._series(df, "fracsec"))
        time_base = self._numeric(self._series(df, "time_base")).replace(0, np.nan)
        from_soc = soc + (fracsec / time_base)
        if from_soc.notna().any():
            return from_soc

        capture_time = self._numeric(self._series(df, "capture_time"))
        if capture_time.notna().any():
            return capture_time

        frame_time = pd.to_datetime(self._series(df, "frame_time"), errors="coerce")
        return pd.Series(frame_time.astype("int64") / 1_000_000_000, index=df.index).where(frame_time.notna())

    def _network_delay(self, df: pd.DataFrame) -> pd.Series:
        existing = self._numeric(self._series(df, "network_delay"))
        if existing.notna().any():
            return existing.fillna(0.0)

        frame_raw = self._series(df, "frame_time")
        capture_raw = self._series(df, "capture_time")
        frame_num = self._numeric(frame_raw)
        capture_num = self._numeric(capture_raw)
        if frame_num.notna().any() and capture_num.notna().any():
            return (frame_num - capture_num).fillna(0.0)

        frame_dt = pd.to_datetime(frame_raw, errors="coerce")
        capture_dt = pd.to_datetime(capture_raw, errors="coerce")
        if frame_dt.notna().any() and capture_dt.notna().any():
            return (frame_dt - capture_dt).dt.total_seconds().fillna(0.0)

        return pd.Series(0.0, index=df.index)

    @staticmethod
    def _relative_to_expected(series: pd.Series, expected: Optional[float]) -> pd.Series:
        if expected is None or expected == 0:
            return series.fillna(0.0)
        return ((series - expected) / expected).fillna(0.0)

    @staticmethod
    def _series(df: pd.DataFrame, *names: str) -> pd.Series:
        lower_to_actual = {str(col).lower(): col for col in df.columns}
        for name in names:
            actual = lower_to_actual.get(name.lower())
            if actual is not None:
                return df[actual]
        return pd.Series(np.nan, index=df.index)

    @staticmethod
    def _value(row: Mapping[str, Any], name: str) -> Any:
        for key, value in row.items():
            if str(key).lower() == name.lower():
                return value
        return None

    @staticmethod
    def _numeric(series: pd.Series) -> pd.Series:
        return pd.to_numeric(series, errors="coerce")

    @staticmethod
    def _bool_series(series: pd.Series) -> pd.Series:
        if series.empty:
            return series
        text = series.astype(str).str.strip().str.lower()
        result = text.map(
            {
                "true": True,
                "t": True,
                "1": True,
                "yes": True,
                "y": True,
                "false": False,
                "f": False,
                "0": False,
                "no": False,
                "n": False,
            }
        )
        return result.fillna(False)

    @staticmethod
    def _angle_radians(series: pd.Series) -> pd.Series:
        values = series.fillna(0.0)
        max_abs = values.abs().max()
        if pd.notna(max_abs) and max_abs > (2.0 * math.pi):
            return np.deg2rad(values)
        return values

    @staticmethod
    def _pmu_key(value: Any) -> Optional[str]:
        if value is None or pd.isna(value):
            return None
        try:
            numeric = float(value)
            if numeric.is_integer():
                return str(int(numeric))
        except (TypeError, ValueError):
            pass
        text = str(value).strip()
        return text or None

    @staticmethod
    def _as_mapping(value: Any) -> MutableMapping[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _positive_number(value: Any) -> Optional[float]:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        if math.isnan(number) or math.isinf(number) or number <= 0:
            return None
        return number
