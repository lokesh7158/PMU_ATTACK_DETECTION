"""
Baseline profiler for PMU decoded CSV data.

Reads normal decoded PMU rows, computes statistical thresholds, and writes thresholds.json.
This is intended to complement packet_reader output: decode normal traffic into CSV first, then run this profiler.
"""

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import pandas as pd
except ImportError:
    raise ImportError("baseline_profiler.py requires pandas. Install with: pip install pandas")


def numeric_series(df, cols):
    values = []
    for col in cols:
        if col in df.columns:
            values.append(pd.to_numeric(df[col], errors="coerce"))
    if not values:
        return pd.Series(dtype=float)
    return pd.concat(values, ignore_index=True).dropna()


def simple_stats(series):
    if series.empty:
        return {}
    return {
        "count": int(series.count()),
        "mean": float(series.mean()),
        "std": float(series.std(ddof=0)),
        "min": float(series.min()),
        "max": float(series.max()),
        "p1": float(series.quantile(0.01)),
        "p5": float(series.quantile(0.05)),
        "p95": float(series.quantile(0.95)),
        "p99": float(series.quantile(0.99)),
    }


def envelope_stats(series, std_multiplier: float = 3.0):
    stats = simple_stats(series)
    if not stats:
        return {}
    lower = max(float(stats["mean"]) - std_multiplier * float(stats["std"]), 0.0)
    upper = float(stats["mean"]) + std_multiplier * float(stats["std"])
    return {
        **stats,
        "lower_bound": lower,
        "upper_bound": upper,
        "std_multiplier": std_multiplier,
    }


def unique_values(series):
    if series.empty:
        return []
    unique = series.dropna().unique()
    try:
        unique = sorted(unique)
    except Exception:
        unique = sorted(str(x) for x in unique)

    cleaned = []
    for x in unique:
        if isinstance(x, (int, float)):
            if isinstance(x, float) and float(x).is_integer():
                cleaned.append(int(x))
            else:
                cleaned.append(x if isinstance(x, int) else float(x))
        else:
            cleaned.append(str(x))
    return cleaned


def profile_identity(df):
    identity = {}
    mappings = {
        "pmu_id": "pmu_id",
        "stream_ids": "stream_id",
        "pmu_names": "pmu_name",
        "src_ips": "src_ip",
        "dst_ips": "dst_ip",
        "src_macs": "src_mac",
        "dst_macs": "dst_mac",
        "src_ports": "src_port",
        "dst_ports": "dst_port",
        "ttls": "ttl",
        "packet_sizes": "packet_size",
        "payload_sizes": "payload_size",
    }
    for key, col in mappings.items():
        if col in df.columns:
            values = df[col]
            if key == "pmu_id":
                nums = pd.to_numeric(values, errors="coerce").dropna().astype(int)
                identity[key] = unique_values(nums)
            elif key in {"src_ports", "dst_ports", "ttls", "packet_sizes", "payload_sizes", "stream_ids"}:
                nums = pd.to_numeric(values, errors="coerce").dropna()
                identity[key] = unique_values(nums)
            else:
                identity[key] = unique_values(values.astype(str))
        else:
            identity[key] = []
    return identity


def compute_timestamp(df):
    if "soc" not in df.columns or "fracsec" not in df.columns:
        return None
    time_base = df.get("time_base", pd.Series(1_000_000, index=df.index))
    return df["soc"].astype(float) + df["fracsec"].astype(float) / pd.to_numeric(time_base, errors="coerce").replace(0, 1)


def _numeric_time_series(df, column: str) -> pd.Series:
    if column not in df.columns:
        return pd.Series(dtype=float)
    return pd.to_numeric(df[column], errors="coerce").dropna()


def arrival_timestamp(df) -> Tuple[Optional[pd.Series], str]:
    """Return the best clock for arrival-rate profiling.

    `frame_time` is the packet timestamp captured by PyShark/Scapy and preserves
    the PMU reporting cadence in offline CSVs. `capture_time` is a close fallback.
    Protocol `soc/fracsec` is kept for protocol-timestamp checks, but some C37
    sources encode FRACSEC in a way that does not reflect packet reporting rate.
    """
    candidates = [
        ("frame_time", _numeric_time_series(df, "frame_time")),
        ("capture_time", _numeric_time_series(df, "capture_time")),
    ]
    for name, series in candidates:
        if len(series) < 2:
            continue
        diffs = series.sort_index().diff().dropna()
        positive = diffs[diffs > 0]
        if len(positive) >= max(2, int(len(series) * 0.5)):
            return series, name

    protocol_ts = compute_timestamp(df)
    if protocol_ts is None:
        return None, "none"
    return protocol_ts.dropna(), "soc_fracsec"


def profile_frequency(df):
    freq_cols = [c for c in df.columns if c.startswith("freq") and c[4:].isdigit()]
    result = simple_stats(numeric_series(df, freq_cols))
    return result


def profile_dfreq(df):
    rocof_cols = [c for c in df.columns if c.startswith("dfreq") and c[5:].isdigit()]
    series = numeric_series(df, rocof_cols).abs()
    if series.empty:
        return {}
    stats = simple_stats(series)
    return {**stats, "abs_p99": float(series.quantile(0.99))}


def profile_frame_deltas(df, prefix_list):
    if df.empty:
        return {}
    ts = compute_timestamp(df)
    if ts is None:
        return {}
    sorted_idx = ts.sort_values().index
    series = pd.Series(dtype=float)
    for name in prefix_list:
        cols = [c for c in df.columns if c.startswith(name) and c.endswith("_mag")]
        for col in cols:
            values = pd.to_numeric(df.loc[sorted_idx, col], errors="coerce")
            delta = values.diff().abs().dropna()
            if not delta.empty:
                series = pd.concat([series, delta], ignore_index=True)
    return simple_stats(series)


def compute_network_delay_columns(df):
    """Compute `network_delay` and `delay_change` columns using frame_time and capture_time."""
    if "frame_time" in df.columns and "capture_time" in df.columns:
        try:
            net_delay = (pd.to_datetime(df["frame_time"]) - pd.to_datetime(df["capture_time"]))
            # total_seconds may produce floats; assign into dataframe
            df["network_delay"] = net_delay.dt.total_seconds()
            df["delay_change"] = df["network_delay"].diff().fillna(0)
        except Exception:
            # If parsing fails, leave columns absent
            pass


def profile_angle_diff(df):
    if df.empty:
        return {}
    ts = compute_timestamp(df)
    if ts is None:
        return {}
    sorted_idx = ts.sort_values().index
    series = pd.Series(dtype=float)
    angle_cols = [c for c in df.columns if c.endswith("_ang")]
    for col in angle_cols:
        values = pd.to_numeric(df.loc[sorted_idx, col], errors="coerce")
        diff = values.diff().dropna().abs()
        diff = diff.where(diff <= 180, 360 - diff).dropna()
        if not diff.empty:
            series = pd.concat([series, diff], ignore_index=True)
    return simple_stats(series)


def mean_delta_series(df, mag_cols):
    if df.empty:
        return pd.Series(dtype=float)
    ts = compute_timestamp(df)
    if ts is None:
        return pd.Series(dtype=float)
    sorted_idx = ts.sort_values().index
    available = [col for col in mag_cols if col in df.columns]
    if len(available) < 2:
        return pd.Series(dtype=float)
    values = df.loc[sorted_idx, available].apply(pd.to_numeric, errors="coerce").mean(axis=1)
    return values.diff().abs().dropna()


def profile_mean_delta(df, mag_cols):
    delta = mean_delta_series(df, mag_cols)
    if delta.empty:
        return {}
    return simple_stats(delta)


def profile_frequency_delta(df):
    if "freq1" not in df.columns:
        return {}
    ts = compute_timestamp(df)
    if ts is None:
        return {}
    sorted_idx = ts.sort_values().index
    freq = pd.to_numeric(df.loc[sorted_idx, "freq1"], errors="coerce")
    delta = freq.diff().abs().dropna()
    return simple_stats(delta)


def profile_rocof(df):
    if "dfreq1" not in df.columns:
        return {}
    series = pd.to_numeric(df["dfreq1"], errors="coerce").abs().dropna()
    return simple_stats(series)


def profile_smoothness(df):
    series = pd.Series(dtype=float)
    voltage_delta = mean_delta_series(df, ["va_mag", "vb_mag", "vc_mag"])
    current_delta = mean_delta_series(df, ["ia_mag", "ib_mag", "ic_mag"])
    if not voltage_delta.empty:
        series = pd.concat([series, voltage_delta], ignore_index=True)
    if not current_delta.empty:
        series = pd.concat([series, current_delta], ignore_index=True)
    if "freq1" in df.columns:
        freq_delta = pd.to_numeric(df["freq1"], errors="coerce").diff().abs().dropna()
        if not freq_delta.empty:
            series = pd.concat([series, freq_delta], ignore_index=True)
    if series.empty:
        return {}
    return simple_stats(series)


def profile_phase_angle_stability(df):
    required = ["va_ang", "vb_ang", "vc_ang"]
    if not all(col in df.columns for col in required):
        return {}
    va = pd.to_numeric(df["va_ang"], errors="coerce")
    vb = pd.to_numeric(df["vb_ang"], errors="coerce")
    vc = pd.to_numeric(df["vc_ang"], errors="coerce")
    series = pd.concat([
        (angle_distance_series(va, vb) - 120).abs(),
        (angle_distance_series(vb, vc) - 120).abs(),
        (angle_distance_series(vc, va) - 120).abs(),
    ], ignore_index=True).dropna()
    return simple_stats(series)


def profile_imbalance(df, prefix):
    p = prefix.lower()
    if p == "v":
        phases = [f"v{phase.lower()}_mag" for phase in ["a", "b", "c"]]
    else:
        phases = [f"i{phase.lower()}_mag" for phase in ["a", "b", "c"]]
    cols = [c for c in phases if c in df.columns]
    if len(cols) < 3:
        cols = [c for c in df.columns if c.startswith(prefix) and c.endswith("_mag")]
    if len(cols) < 3:
        return {}
    values = df[cols].apply(pd.to_numeric, errors="coerce")
    imbalance = values.std(axis=1, ddof=0) / values.mean(axis=1).replace(0, pd.NA).abs()
    imbalance = imbalance.dropna().astype(float)
    return simple_stats(imbalance)


def profile_timing(df):
    if df.empty:
        return {}
    ts, source = arrival_timestamp(df)
    if ts is None:
        return {}
    interval = ts.diff().dropna()
    interval = interval[interval > 0]
    interval = interval[interval < 1]
    if interval.empty:
        return {}
    stats = envelope_stats(interval)
    stats["source"] = source
    return stats


def profile_rate(df):
    ts, source = arrival_timestamp(df)
    if ts is None:
        return {}
    valid = ts.dropna()
    if len(valid) < 2:
        return {}
    intervals = valid.diff().dropna()
    intervals = intervals[intervals > 0]
    if intervals.empty:
        return {}
    median_interval = float(intervals.median())
    span = float(valid.iloc[-1] - valid.iloc[0])
    expected_fps = 1.0 / median_interval if median_interval > 0 else (len(valid) / span if span > 0 else 0.0)
    observed_fps = (len(valid) - 1) / span if span > 0 else expected_fps
    return {
        "expected_fps": round(expected_fps, 3),
        "observed_fps": round(observed_fps, 3),
        "expected_interval_seconds": median_interval,
        "source": source,
    }


def profile_network_delay(df):
    if "network_delay" not in df.columns:
        return {}
    values = pd.to_numeric(df["network_delay"], errors="coerce").dropna()
    return simple_stats(values)


def profile_delay_change(df):
    if "network_delay" not in df.columns:
        return {}
    values = pd.to_numeric(df["network_delay"], errors="coerce").dropna()
    changes = values.diff().abs().dropna()
    return simple_stats(changes)


def profile_sequence(df):
    result = {}
    for name in ("frame_number", "sequence_number", "tcp_seq"):
        if name not in df.columns:
            continue
        values = pd.to_numeric(df[name], errors="coerce").dropna()
        if len(values) < 2:
            continue
        diffs = values.diff().dropna()
        positive = diffs[diffs > 0]
        if positive.empty:
            continue
        rounded = positive.round().astype(int)
        mode = int(rounded.mode().iloc[0]) if not rounded.mode().empty else int(round(float(positive.median())))
        stats = envelope_stats(positive)
        result[f"{name}_step"] = {**stats, "mode": mode}
    return result


def profile_packet_sizes(df):
    result = {}
    for name in ["packet_size", "payload_size"]:
        if name in df.columns:
            result[name] = simple_stats(pd.to_numeric(df[name], errors="coerce").dropna())
    return result


def profile_phase_stats(df, phases: List[str]):
    """Compute per-phase magnitude stats and base (mean) values for given phase prefixes.

    phases: list of phase prefixes like ["Va","Vb","Vc"] or ["Ia","Ib","Ic"]
    Returns dict: { phase: {"stats": {...}, "base": mean_value} }
    """
    out = {}
    for ph in phases:
        col = f"{ph}_mag"
        if col in df.columns:
            series = pd.to_numeric(df[col], errors="coerce").dropna()
            stats = simple_stats(series)
            base = float(series.mean()) if not series.empty else None
            out[ph] = {"stats": stats, "base": base}
        else:
            out[ph] = {"stats": {}, "base": None}
    return out


def profile_soc_fracsec(df):
    result = {}
    if "soc" in df.columns:
        soc = pd.to_numeric(df["soc"], errors="coerce").dropna()
        result["soc_diff"] = simple_stats(soc.diff().dropna().abs())
    if "fracsec" in df.columns:
        frac = pd.to_numeric(df["fracsec"], errors="coerce").dropna()
        result["fracsec_diff"] = simple_stats(frac.diff().dropna().abs())
    return result


def angle_distance_series(a, b):
    diff = (a - b).abs() % 360
    return diff.where(diff <= 180, 360 - diff)


def relative_delta_series(series):
    values = pd.to_numeric(series, errors="coerce")
    prev = values.shift(1)
    return ((values - prev).abs() / prev.abs().replace(0, pd.NA)).dropna().astype(float)


def phase_power(df):
    active_power = pd.Series(0.0, index=df.index)
    reactive_power = pd.Series(0.0, index=df.index)
    apparent_power = pd.Series(0.0, index=df.index)
    phases_used = 0

    for phase in ["a", "b", "c"]:
        required = [f"v{phase}_mag", f"i{phase}_mag", f"v{phase}_ang", f"i{phase}_ang"]
        if not all(col in df.columns for col in required):
            continue

        voltage = pd.to_numeric(df[f"v{phase}_mag"], errors="coerce")
        current = pd.to_numeric(df[f"i{phase}_mag"], errors="coerce")
        voltage_angle = pd.to_numeric(df[f"v{phase}_ang"], errors="coerce")
        current_angle = pd.to_numeric(df[f"i{phase}_ang"], errors="coerce")
        apparent = (voltage * current).abs()
        angle_rad = (voltage_angle - current_angle) * 3.141592653589793 / 180.0

        active_power = active_power + apparent * angle_rad.apply(lambda x: pd.NA if pd.isna(x) else math.cos(x))
        reactive_power = reactive_power + apparent * angle_rad.apply(lambda x: pd.NA if pd.isna(x) else math.sin(x))
        apparent_power = apparent_power + apparent
        phases_used += 1

    if phases_used == 0:
        return None

    return {
        "p": active_power,
        "q": reactive_power,
        "s": apparent_power,
    }


def profile_physical_consistency(df):
    thresholds = {
        "voltage_current_voltage_change_ratio": 0.1,
        "voltage_current_current_response_ratio": 0.02,
        "angle_symmetry_tolerance_deg": 40.0,
        "power_apparent_margin": 1.2,
        "rocof_frequency_max_error": 0.2,
        "multi_signal_voltage_change_ratio": 0.1,
        "multi_signal_current_change_ratio": 0.1,
        "multi_signal_frequency_change_hz": 0.2,
        "multi_signal_dfreq_change": 0.2,
        "multi_signal_angle_change_deg": 20.0,
        "smooth_voltage_step_ratio": 0.25,
        "smooth_current_step_ratio": 0.5,
        "smooth_frequency_step_hz": 1.0,
        "smooth_angle_step_deg": 60.0,
        "apparent_power_change_ratio_p99": 0.5,
        "power_factor_abs_min": 0.05,
        "power_min_apparent": 1e-6,
    }

    ts = compute_timestamp(df)
    if ts is not None:
        df = df.loc[ts.sort_values().index].copy()

    voltage_rel = []
    current_rel = []
    angle_steps = []
    for phase in ["a", "b", "c"]:
        v_col = f"v{phase}_mag"
        i_col = f"i{phase}_mag"
        va_col = f"v{phase}_ang"
        if v_col in df.columns:
            voltage_rel.append(relative_delta_series(df[v_col]))
        if i_col in df.columns:
            current_rel.append(relative_delta_series(df[i_col]))
        if va_col in df.columns:
            angles = pd.to_numeric(df[va_col], errors="coerce")
            angle_steps.append(angle_distance_series(angles, angles.shift(1)).dropna())

    if voltage_rel:
        voltage_delta = pd.concat(voltage_rel, ignore_index=True).dropna()
        if not voltage_delta.empty:
            v_p99 = float(voltage_delta.quantile(0.99))
            thresholds["voltage_current_voltage_change_ratio"] = max(v_p99 * 3, 0.1)
            thresholds["multi_signal_voltage_change_ratio"] = max(v_p99 * 3, 0.1)
            thresholds["smooth_voltage_step_ratio"] = max(v_p99 * 5, 0.25)

    if current_rel:
        current_delta = pd.concat(current_rel, ignore_index=True).dropna()
        if not current_delta.empty:
            i_p99 = float(current_delta.quantile(0.99))
            thresholds["voltage_current_current_response_ratio"] = max(i_p99 * 0.25, 0.02)
            thresholds["multi_signal_current_change_ratio"] = max(i_p99 * 3, 0.1)
            thresholds["smooth_current_step_ratio"] = max(i_p99 * 5, 0.5)

    if all(col in df.columns for col in ["va_ang", "vb_ang", "vc_ang"]):
        va = pd.to_numeric(df["va_ang"], errors="coerce")
        vb = pd.to_numeric(df["vb_ang"], errors="coerce")
        vc = pd.to_numeric(df["vc_ang"], errors="coerce")
        spacing_error = pd.concat([
            (angle_distance_series(va, vb) - 120).abs(),
            (angle_distance_series(vb, vc) - 120).abs(),
            (angle_distance_series(vc, va) - 120).abs(),
        ], ignore_index=True).dropna()
        if not spacing_error.empty:
            thresholds["angle_symmetry_tolerance_deg"] = max(float(spacing_error.quantile(0.99)) * 3, 40.0)

    if angle_steps:
        angle_delta = pd.concat(angle_steps, ignore_index=True).dropna()
        if not angle_delta.empty:
            thresholds["multi_signal_angle_change_deg"] = max(float(angle_delta.quantile(0.99)) * 3, 20.0)
            thresholds["smooth_angle_step_deg"] = max(float(angle_delta.quantile(0.99)) * 5, 60.0)

    if "freq1" in df.columns:
        freq = pd.to_numeric(df["freq1"], errors="coerce")
        freq_step = freq.diff().abs().dropna()
        if not freq_step.empty:
            thresholds["multi_signal_frequency_change_hz"] = max(float(freq_step.quantile(0.99)) * 3, 0.2)
            thresholds["smooth_frequency_step_hz"] = max(float(freq_step.quantile(0.99)) * 5, 1.0)

    if "dfreq1" in df.columns:
        dfreq = pd.to_numeric(df["dfreq1"], errors="coerce")
        dfreq_step = dfreq.diff().abs().dropna()
        if not dfreq_step.empty:
            thresholds["multi_signal_dfreq_change"] = max(float(dfreq_step.quantile(0.99)) * 3, 0.2)

    if ts is not None and "freq1" in df.columns and "dfreq1" in df.columns:
        aligned_ts = compute_timestamp(df)
        freq = pd.to_numeric(df["freq1"], errors="coerce")
        dfreq = pd.to_numeric(df["dfreq1"], errors="coerce")
        dt = aligned_ts.diff().replace(0, pd.NA)
        expected_dfreq = freq.diff() / dt
        rocof_error = (dfreq - expected_dfreq).abs().dropna()
        if not rocof_error.empty:
            thresholds["rocof_frequency_max_error"] = max(float(rocof_error.quantile(0.99)) * 3, 0.2)

    power = phase_power(df)
    if power is not None:
        p_change = power["p"].diff().abs().dropna()
        q_change = power["q"].diff().abs().dropna()
        s_change_ratio = ((power["s"] - power["s"].shift(1)).abs() / power["s"].shift(1).abs().replace(0, pd.NA)).dropna()
        power_magnitude = (power["p"] ** 2 + power["q"] ** 2) ** 0.5
        power_factor = (power["p"].abs() / power_magnitude.replace(0, pd.NA)).dropna()
        apparent = power["s"].dropna()
        if not p_change.empty:
            thresholds["active_power_change_abs_p99"] = float(p_change.quantile(0.99)) * 3
        if not q_change.empty:
            thresholds["reactive_power_change_abs_p99"] = float(q_change.quantile(0.99)) * 3
        if not s_change_ratio.empty:
            thresholds["apparent_power_change_ratio_p99"] = max(float(s_change_ratio.quantile(0.99)) * 3, 0.5)
        if not power_factor.empty:
            thresholds["power_factor_abs_min"] = max(float(power_factor.quantile(0.01)) * 0.5, 0.01)
        if not apparent.empty:
            thresholds["power_min_apparent"] = max(float(apparent.quantile(0.01)) * 0.1, 1e-6)

    return thresholds


def build_thresholds(df):
    # normalize column names to lowercase for consistent matching
    df = df.rename(columns=str.lower)
    if "pmu_id" not in df.columns:
        raise ValueError("Input CSV must contain a pmu_id column")

    metadata = {
        "profile_version": "1.0.0",
        "generated_timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }

    ts, rate_source = arrival_timestamp(df)
    if ts is not None and not ts.dropna().empty:
        ts_clean = ts.dropna()
        start = float(ts_clean.min())
        end = float(ts_clean.max())
        metadata["trusted_training_window"] = {
            "start": start,
            "end": end,
            "frames": int(len(ts_clean)),
            "rate_source": rate_source,
        }
        span = float(end - start)
        metadata["fps"] = round((len(ts_clean) - 1) / span, 3) if span > 0 and len(ts_clean) > 1 else 0.0
    else:
        metadata["trusted_training_window"] = {"frames": int(len(df))}
        metadata["fps"] = 0.0

    profiles: Dict[str, Any] = {}
    for pmu_id, group in df.groupby(pd.to_numeric(df["pmu_id"], errors="coerce").dropna().astype(int)):
        profile: Dict[str, Any] = {}
        profile["identity"] = profile_identity(group)
        profile["frequency"] = profile_frequency(group)
        profile["dfreq"] = profile_dfreq(group)
        compute_network_delay_columns(group)
        profile["voltage"] = profile_phase_stats(group, ["va", "vb", "vc"])
        profile["current"] = profile_phase_stats(group, ["ia", "ib", "ic"])
        profile["network_delay"] = profile_network_delay(group)
        profile["inter_arrival"] = profile_timing(group)
        profile["rate"] = profile_rate(group)
        profile["delay_change"] = profile_delay_change(group)
        profile["sequence"] = profile_sequence(group)
        profile["packet_size"] = simple_stats(pd.to_numeric(group["packet_size"], errors="coerce").dropna()) if "packet_size" in group.columns else {}
        profile["payload_size"] = simple_stats(pd.to_numeric(group["payload_size"], errors="coerce").dropna()) if "payload_size" in group.columns else {}
        profile["angle_diff"] = profile_angle_diff(group)
        profile["voltage_imbalance"] = profile_imbalance(group, "V")
        profile["current_imbalance"] = profile_imbalance(group, "I")
        profile["voltage_delta"] = profile_mean_delta(group, ["va_mag", "vb_mag", "vc_mag"])
        profile["current_delta"] = profile_mean_delta(group, ["ia_mag", "ib_mag", "ic_mag"])
        profile["frequency_delta"] = profile_frequency_delta(group)
        profile["rocof"] = profile_rocof(group)
        profile["smoothness"] = profile_smoothness(group)
        profile["phase_angle_diff"] = profile_phase_angle_stability(group)
        profile["physical_consistency"] = profile_physical_consistency(group)
        profile.update(profile_soc_fracsec(group))
        warnings = validate_profile(profile)
        if warnings:
            profile["profile_warnings"] = warnings
        profiles[str(int(pmu_id))] = profile

    detection_thresholds = {
        "rate_window_seconds": 1.0,
        "burst_window_seconds": 0.25,
        "min_rate_samples": 5,
        "fps_flood_multiplier": 1.75,
        "fps_slowdown_multiplier": 0.60,
        "fps_suppression_multiplier": 0.25,
        "burst_multiplier": 2.50,
        "bytes_per_second_multiplier": 2.00,
        "sustained_rate_frames": 3,
        "missing_frame_threshold": 2,
        "timestamp_tolerance_ratio": 0.35,
        "sequence_jump_threshold": 1,
        "sequence_replay_window": 32,
        "use_frame_number_sequence": True,
        "route_latency_multiplier": 3.0,
        "route_latency_consecutive_frames": 2,
        "enable_route_latency_rules": False,
        "inter_arrival_consecutive_frames": 3,
        "silence_timeout_multiplier": 5.0,
    }
    evaluation_thresholds = {
        "attack_score_threshold": 55.0,
        "fault_score_threshold": 50.0,
        "suspicious_score_threshold": 35.0,
        "persistence_window": 10,
        "persistence_trigger_count": 4,
        "aggressive_mode": True,
        "cyber_weight": 1.4,
        "fault_weight": 1.1,
        "replay_weight": 1.5,
        "timing_weight": 1.3,
        "sequence_weight": 1.3,
        "disturbance_weight": 0.9,
        "persistence_attack_bonus": 14.0,
        "persistence_fault_bonus": 8.0,
        "ml_attack_weight": 0.0,
        "ml_fault_weight": 0.0,
    }
    return {
        "metadata": metadata,
        "detection_thresholds": detection_thresholds,
        "evaluation_thresholds": evaluation_thresholds,
        "pmu_profiles": profiles,
    }


def validate_profile(profile: Dict[str, Any]) -> List[str]:
    warnings = []
    rate = profile.get("rate", {})
    inter_arrival = profile.get("inter_arrival", {})
    expected_fps = rate.get("expected_fps")
    observed_fps = rate.get("observed_fps")
    expected_interval = rate.get("expected_interval_seconds")

    if expected_fps and expected_interval:
        implied = 1.0 / float(expected_interval)
        if abs(float(expected_fps) - implied) > max(0.5, float(expected_fps) * 0.02):
            warnings.append(f"expected_fps {expected_fps} does not match expected_interval_seconds {expected_interval}")

    if expected_fps and observed_fps:
        delta = abs(float(expected_fps) - float(observed_fps))
        if delta > max(1.0, float(expected_fps) * 0.05):
            warnings.append(f"expected_fps {expected_fps} differs from observed_fps {observed_fps}")

    if expected_interval and inter_arrival.get("mean"):
        delta = abs(float(expected_interval) - float(inter_arrival["mean"]))
        if delta > max(0.002, float(expected_interval) * 0.10):
            warnings.append("inter_arrival mean does not match expected_interval_seconds")

    return warnings


def save_thresholds(thresholds: Dict[str, Any], path: Path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(thresholds, f, indent=2)


def parse_args():
    parser = argparse.ArgumentParser(description="Create PMU baseline thresholds from normal decoded CSV data")
    parser.add_argument("csv_path", type=Path, help="Path to normal decoded PMU CSV file")
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "thresholds.json", help="Output thresholds JSON file")
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.csv_path.exists():
        raise FileNotFoundError(f"CSV file not found: {args.csv_path}")

    df = pd.read_csv(args.csv_path)
    thresholds = build_thresholds(df)
    save_thresholds(thresholds, args.output)
    print(f"Thresholds written to {args.output}")


if __name__ == "__main__":
    main()
