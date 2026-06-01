import json
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class SeverityLevel(Enum):
    NORMAL = "NORMAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RuleType(Enum):
    HARD = "HARD"
    SOFT = "SOFT"


@dataclass
class RuleEvaluation:
    rule_id: str
    name: str
    category: str
    priority: int
    severity: SeverityLevel
    confidence: float
    score: float
    reason: str


@dataclass
class StreamState:
    key: Tuple[str, str, str]
    last_timestamp: Optional[Tuple[int, int]] = None
    last_capture_time: float = 0.0
    last_observed_timestamp: Optional[Tuple[int, int]] = None
    last_observed_capture_time: float = 0.0
    last_voltage_mean: float = 1.0
    last_current_mean: float = 0.0
    last_freq: float = 50.0
    last_rocof: float = 0.0
    last_safe_frame: Optional[Dict[str, Any]] = None
    suspicious_count: int = 0
    inter_arrival_history: deque = field(default_factory=lambda: deque(maxlen=50))
    jitter_history: deque = field(default_factory=lambda: deque(maxlen=50))
    timing_variance_history: deque = field(default_factory=lambda: deque(maxlen=50))
    replay_fingerprints: deque = field(default_factory=lambda: deque(maxlen=30))
    score_history: deque = field(default_factory=lambda: deque(maxlen=30))
    voltage_history: deque = field(default_factory=lambda: deque(maxlen=25))
    current_history: deque = field(default_factory=lambda: deque(maxlen=25))
    freq_history: deque = field(default_factory=lambda: deque(maxlen=25))
    anomaly_history: deque = field(default_factory=lambda: deque(maxlen=30))
    fps_history: deque = field(default_factory=lambda: deque(maxlen=60))
    arrival_times: deque = field(default_factory=lambda: deque(maxlen=512))
    byte_events: deque = field(default_factory=lambda: deque(maxlen=512))
    frames_per_second: float = 0.0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    burst_rate: float = 0.0
    rate_violation_count: int = 0
    expected_sequence: Optional[int] = None
    last_sequence: Optional[int] = None
    recent_sequences: deque = field(default_factory=lambda: deque(maxlen=64))
    sequence_gap_counter: int = 0
    duplicate_counter: int = 0
    out_of_order_counter: int = 0
    missing_window_counter: int = 0
    last_source_ip: Optional[str] = None
    last_source_mac: Optional[str] = None
    route_delay_history: deque = field(default_factory=lambda: deque(maxlen=30))
    route_latency_anomaly_count: int = 0


class CaseInsensitiveFrame(dict):
    def __init__(self, data: Optional[Dict[str, Any]] = None):
        super().__init__(data or {})
        self._lower_map = {str(k).lower(): k for k in self.keys()}

    def _resolve(self, key: str):
        if super().__contains__(key):
            return key
        return self._lower_map.get(key.lower())

    def get(self, key, default=None):
        resolved = self._resolve(key)
        if resolved is None:
            return default
        return super().get(resolved, default)

    def __getitem__(self, key):
        resolved = self._resolve(key)
        if resolved is None:
            raise KeyError(key)
        return super().__getitem__(resolved)

    def __contains__(self, key):
        return super().__contains__(key) or key.lower() in self._lower_map


DEFAULT_PROFILE_THRESHOLDS = {
    "voltage_delta": {"mean": 0.0, "std": 0.05, "p95": 0.10, "p99": 0.20},
    "current_delta": {"mean": 0.0, "std": 0.05, "p95": 0.10, "p99": 0.20},
    "frequency_delta": {"mean": 0.0, "std": 0.05, "p95": 0.10, "p99": 0.20},
    "rocof": {"mean": 0.0, "std": 0.05, "p95": 0.10, "p99": 0.20},
    "voltage_imbalance": {"mean": 0.0, "std": 0.02, "p95": 0.03, "p99": 0.05},
    "current_imbalance": {"mean": 0.0, "std": 0.02, "p95": 0.03, "p99": 0.05},
    "phase_angle_diff": {"mean": 0.0, "std": 0.10, "p95": 0.20, "p99": 0.40},
    "smoothness": {"mean": 0.0, "std": 0.05, "p95": 0.10, "p99": 0.20},
}

DEFAULT_DETECTOR_THRESHOLDS = {
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
}


def load_thresholds(path: Optional[str] = None) -> Dict[str, Any]:
    fallback_path = Path(__file__).parent / "thresholds.json"
    candidate_paths = []
    if path is not None:
        candidate_paths.append(Path(path))
    candidate_paths.append(Path(__file__).parent.parent / "profiles" / "thresholds.json")
    candidate_paths.append(fallback_path)

    for candidate in candidate_paths:
        try:
            if candidate.exists():
                with open(candidate, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                if isinstance(data, dict):
                    return data
        except Exception:
            continue
    return {"pmu_profiles": {}}


def _safe_float(value, default=None):
    try:
        out = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(out) or math.isinf(out):
        return default
    return out


def _safe_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_bool(value, default=None):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"true", "t", "1", "yes", "y", "on"}:
        return True
    if text in {"false", "f", "0", "no", "n", "off"}:
        return False
    return default


def _safe_str(value):
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _safe_dict(value):
    if isinstance(value, dict):
        return value
    return {}


def _avg(values):
    cleaned = [v for v in values if v is not None]
    if not cleaned:
        return 0.0
    return sum(cleaned) / len(cleaned)


def _voltage_mean(frame):
    values = [_safe_float(frame.get("va_mag")), _safe_float(frame.get("vb_mag")), _safe_float(frame.get("vc_mag"))]
    return _avg(values)


def _current_mean(frame):
    values = [_safe_float(frame.get("ia_mag")), _safe_float(frame.get("ib_mag")), _safe_float(frame.get("ic_mag"))]
    return _avg(values)


def _timestamp_to_key(frame):
    soc = _safe_int(frame.get("soc"))
    frac = _safe_int(frame.get("fracsec"), 0)
    if soc is None:
        return None
    return (soc, frac)


def _timestamp_seconds(timestamp: Optional[Tuple[int, int]], time_base: float) -> Optional[float]:
    if timestamp is None:
        return None
    return timestamp[0] + timestamp[1] / max(time_base, 1.0)


def _build_fingerprint(frame):
    phasors = tuple(round(_safe_float(frame.get(key), 0.0), 3) for key in ("va_mag", "vb_mag", "vc_mag", "ia_mag", "ib_mag", "ic_mag"))
    return (
        round(_safe_float(frame.get("freq1"), 50.0), 4),
        round(_safe_float(frame.get("dfreq1"), 0.0), 4),
        round(_safe_float(frame.get("va_ang"), 0.0), 3),
        round(_safe_float(frame.get("vb_ang"), 0.0), 3),
        round(_safe_float(frame.get("vc_ang"), 0.0), 3),
        phasors,
        _safe_int(frame.get("packet_size"), 0),
    )


def _profile_thresholds(profile: Dict[str, Any], name: str) -> Dict[str, float]:
    defaults = DEFAULT_PROFILE_THRESHOLDS.get(name, {"mean": 0.0, "std": 0.05, "p95": 0.10, "p99": 0.20})
    stats = _safe_dict(profile.get(name, {}))
    merged = {}
    for key in ("mean", "std", "p95", "p99"):
        value = _safe_float(stats.get(key), defaults.get(key, 0.0))
        if value is None:
            value = defaults.get(key, 0.0)
        merged[key] = float(value)
    if merged["p99"] < merged["p95"]:
        merged["p99"] = merged["p95"]
    return merged


def _effective_threshold(stats: Dict[str, float], floor: float, multiplier: float = 1.0) -> float:
    p95 = float(stats.get("p95", 0.0))
    p99 = float(stats.get("p99", 0.0))
    mean = float(stats.get("mean", 0.0))
    std = float(stats.get("std", 0.0))
    robust = max(p99 + (2.0 * std), p95, mean + (3.0 * std), floor)
    return max(robust * multiplier, floor)


def _compute_imbalance(values: List[float]) -> float:
    cleaned = [v for v in values if v is not None]
    if not cleaned:
        return 0.0
    mean = sum(cleaned) / len(cleaned)
    if mean == 0:
        return 0.0
    variance = sum((v - mean) ** 2 for v in cleaned) / len(cleaned)
    return math.sqrt(variance) / abs(mean)


def _phase_spacing_error(frame: Dict[str, Any]) -> float:
    va = _safe_float(frame.get("va_ang"))
    vb = _safe_float(frame.get("vb_ang"))
    vc = _safe_float(frame.get("vc_ang"))
    if va is None or vb is None or vc is None:
        return 0.0

    def clip_distance(a: float, b: float) -> float:
        diff = (a - b) % 360.0
        if diff > 180.0:
            diff = 360.0 - diff
        return diff

    return max(abs(clip_distance(va, vb) - 120.0), abs(clip_distance(vb, vc) - 120.0), abs(clip_distance(vc, va) - 120.0))


class FrameRuleEngine:
    def __init__(self, threshold_file: Optional[str] = None):
        self.thresholds = load_thresholds(threshold_file)
        self.known_pmu_ids = set()
        self.known_stream_ids = set()
        self._load_known_identities()
        self.stream_states: Dict[Tuple[str, str, str], StreamState] = {}
        self.frame_count = 0
        self.rule_frequency = defaultdict(int)
        self.suspicious_threshold = 35.0

    def _load_known_identities(self):
        profiles = self.thresholds.get("pmu_profiles", {}) if isinstance(self.thresholds, dict) else {}
        for pmu_id, profile in profiles.items():
            if isinstance(profile, dict):
                self.known_pmu_ids.add(str(pmu_id))
                identity = profile.get("identity", {})
                for stream_id in identity.get("stream_ids", []):
                    sid = _safe_str(stream_id)
                    if sid is not None:
                        self.known_stream_ids.add(sid)

    def set_known_pmu_ids(self, pmu_ids: List[int], stream_ids: List[int]):
        self.known_pmu_ids = {str(value) for value in pmu_ids if value is not None}
        self.known_stream_ids = {str(value) for value in stream_ids if value is not None}

    def _get_profile(self, pmu_id: Optional[str]) -> Dict[str, Any]:
        if pmu_id is None:
            return {}
        return _safe_dict(self.thresholds.get("pmu_profiles", {}).get(str(pmu_id), {}))

    def _detector_config(self) -> Dict[str, Any]:
        configured = _safe_dict(self.thresholds.get("detection_thresholds", {}))
        return {**DEFAULT_DETECTOR_THRESHOLDS, **configured}

    def _expected_fps(self, profile: Dict[str, Any]) -> float:
        rate = _safe_dict(profile.get("rate", {}))
        expected = _safe_float(rate.get("expected_fps"))
        if expected is None or expected <= 0:
            expected = _safe_float(_safe_dict(self.thresholds.get("metadata", {})).get("fps"), 0.0)
        return max(expected or 0.0, 0.0)

    def _expected_next_timestamp(self, state: StreamState, profile: Dict[str, Any], time_base: float) -> Optional[Dict[str, int]]:
        expected_fps = self._expected_fps(profile)
        last_seconds = _timestamp_seconds(state.last_observed_timestamp, time_base)
        if expected_fps <= 0 or last_seconds is None:
            return None
        next_seconds = last_seconds + 1.0 / expected_fps
        soc = int(math.floor(next_seconds))
        fracsec = int(round((next_seconds - soc) * time_base))
        if fracsec >= int(time_base):
            soc += 1
            fracsec = 0
        return {"soc": soc, "fracsec": fracsec}

    def _compose_stream_key(self, frame: Dict[str, Any]) -> Tuple[str, str, str]:
        pmu_id = _safe_str(frame.get("pmu_id")) or "unknown"
        stream_id = _safe_str(frame.get("stream_id")) or "unknown"
        dst_ip = _safe_str(frame.get("dst_ip")) or "unknown"
        return (pmu_id, stream_id, dst_ip)

    def _build_context(self, frame: Dict[str, Any], state: StreamState) -> Dict[str, Any]:
        profile = self._get_profile(_safe_str(frame.get("pmu_id")))
        previous_frame = state.last_safe_frame
        previous_ts = state.last_timestamp
        current_ts = _timestamp_to_key(frame)
        delta = None
        if previous_ts and current_ts:
            delta = max((current_ts[0] - previous_ts[0]) + (current_ts[1] - previous_ts[1]) / max(_safe_float(frame.get("time_base"), 1000000.0), 1.0), 0.0)
        if previous_frame and current_ts:
            previous_capture = _safe_float(previous_frame.get("capture_time"), None)
            current_capture = _safe_float(frame.get("capture_time"), None)
            if previous_capture is not None and current_capture is not None:
                delta = max(current_capture - previous_capture, delta or 0.0)

        return {
            "profile": profile,
            "known_pmu_ids": self.known_pmu_ids,
            "known_stream_ids": self.known_stream_ids,
            "previous_frame": previous_frame,
            "previous_timestamp": previous_ts,
            "current_timestamp": current_ts,
            "time_delta": delta,
            "freq_history": list(state.freq_history),
            "voltage_history": list(state.voltage_history),
            "current_history": list(state.current_history),
            "score_history": list(state.score_history),
            "replay_fingerprints": list(state.replay_fingerprints),
            "inter_arrival_history": list(state.inter_arrival_history),
            "jitter_history": list(state.jitter_history),
            "timing_variance_history": list(state.timing_variance_history),
            "anomaly_history": list(state.anomaly_history),
            "fps_history": list(state.fps_history),
            "frames_per_second": state.frames_per_second,
            "burst_rate": state.burst_rate,
        }

    def _severity_from_score(self, final_score: float, corrupted: bool, cyber_score: float, fault_score: float) -> SeverityLevel:
        if corrupted or final_score >= 80 or cyber_score >= 75 or fault_score >= 75:
            return SeverityLevel.CRITICAL
        if final_score >= 55 or cyber_score >= 55 or fault_score >= 60:
            return SeverityLevel.HIGH
        if final_score >= 30 or cyber_score >= 35 or fault_score >= 30:
            return SeverityLevel.MEDIUM
        if final_score >= 10 or fault_score >= 10:
            return SeverityLevel.LOW
        return SeverityLevel.NORMAL

    def _tier_score(self, tier: Optional[str]) -> int:
        scores = {"LOW": 24, "MEDIUM": 40, "HIGH": 56}
        return scores.get(tier, 0)

    def _tier_confidence(self, tier: Optional[str]) -> float:
        confidences = {"LOW": 0.60, "MEDIUM": 0.75, "HIGH": 0.90}
        return confidences.get(tier, 0.0)

    def _anomaly_tier(self, value: float, stats: Dict[str, float]) -> Optional[str]:
        magnitude = abs(value)
        p95 = float(stats.get("p95", 0.0))
        p99 = float(stats.get("p99", 0.0))
        if magnitude > p99:
            return "HIGH"
        if magnitude > p95:
            return "MEDIUM"
        return None

    def _profile_rule(self, rule_id: str, name: str, tier: Optional[str], reason: str) -> Optional[RuleEvaluation]:
        if tier is None:
            return None
        return RuleEvaluation(
            rule_id,
            name,
            "physics",
            70,
            {
                "LOW": SeverityLevel.LOW,
                "MEDIUM": SeverityLevel.MEDIUM,
                "HIGH": SeverityLevel.HIGH,
            }.get(tier, SeverityLevel.LOW),
            self._tier_confidence(tier),
            self._tier_score(tier),
            reason,
        )

    def _hard_rule_evaluations(self, frame: Dict[str, Any], context: Dict[str, Any]) -> List[RuleEvaluation]:
        evaluations = []

        if frame.get("crc_ok") is False:
            evaluations.append(RuleEvaluation("HARD_CRC_01", "CRC failure", "structural", 100, SeverityLevel.CRITICAL, 0.99, 100.0, "Frame CRC validation failed"))

        pmu_id = _safe_str(frame.get("pmu_id"))
        if pmu_id is None or pmu_id == "0" or (self.known_pmu_ids and pmu_id not in self.known_pmu_ids):
            evaluations.append(RuleEvaluation("HARD_PMU_ID_02", "Invalid PMU ID", "structural", 95, SeverityLevel.HIGH, 0.98, 90.0, "Unknown or invalid PMU ID"))

        stream_id = _safe_str(frame.get("stream_id"))
        if stream_id is None or stream_id == "0" or (self.known_stream_ids and stream_id not in self.known_stream_ids):
            evaluations.append(RuleEvaluation("HARD_STREAM_ID_03", "Invalid stream ID", "structural", 95, SeverityLevel.HIGH, 0.98, 88.0, "Unknown or invalid stream ID"))

        required = ["pmu_id", "stream_id", "soc", "fracsec", "time_base"]
        missing = [name for name in required if frame.get(name) is None]
        if missing:
            evaluations.append(RuleEvaluation("HARD_MISSING_FIELDS_04", "Missing required fields", "structural", 100, SeverityLevel.CRITICAL, 0.99, 95.0, f"Missing required fields: {', '.join(missing)}"))

        current_ts = _timestamp_to_key(frame)
        prev_ts = context.get("previous_timestamp")
        if current_ts and prev_ts and current_ts < prev_ts:
            evaluations.append(RuleEvaluation("HARD_TIMESTAMP_REVERSAL_05", "Timestamp reversal", "structural", 92, SeverityLevel.HIGH, 0.98, 85.0, "Timestamp moved backwards"))

        time_base = _safe_float(frame.get("time_base"), 0.0)
        if time_base <= 0 or time_base > 100000000:
            evaluations.append(RuleEvaluation("HARD_TIME_BASE_06", "Impossible time base", "structural", 90, SeverityLevel.HIGH, 0.97, 82.0, "Invalid time_base"))

        profile = context.get("profile", {})
        identity = profile.get("identity", {})
        src_ips = {str(value) for value in identity.get("src_ips", []) if str(value).strip()}
        src_macs = {str(value) for value in identity.get("src_macs", []) if str(value).strip()}
        if src_ips and _safe_str(frame.get("src_ip")) not in src_ips:
            evaluations.append(RuleEvaluation("HARD_SRC_ID_07", "Source IP mismatch", "structural", 88, SeverityLevel.HIGH, 0.96, 80.0, "Source IP does not match the configured baseline"))
        if src_macs and _safe_str(frame.get("src_mac")) not in src_macs:
            evaluations.append(RuleEvaluation("HARD_SRC_ID_07", "Source MAC mismatch", "structural", 88, SeverityLevel.HIGH, 0.96, 80.0, "Source MAC does not match the configured baseline"))

        for key in ("freq1", "dfreq1", "va_mag", "vb_mag", "vc_mag", "ia_mag", "ib_mag", "ic_mag"):
            numeric = _safe_float(frame.get(key), None)
            if numeric is None:
                continue
            if numeric != numeric or numeric in {float("inf"), float("-inf")}:
                evaluations.append(RuleEvaluation("HARD_PACKET_CORRUPTION_08", "Packet corruption", "structural", 93, SeverityLevel.CRITICAL, 0.98, 92.0, f"Field {key} is not finite"))
                break

        for key in ("va_mag", "vb_mag", "vc_mag", "ia_mag", "ib_mag", "ic_mag"):
            numeric = _safe_float(frame.get(key), None)
            if numeric is not None and numeric < 0:
                evaluations.append(RuleEvaluation("HARD_PHASOR_09", "Impossible phasor values", "structural", 94, SeverityLevel.CRITICAL, 0.99, 96.0, f"Negative phasor magnitude for {key}"))
                break

        return evaluations

    def _timing_evaluations(self, frame: Dict[str, Any], state: StreamState, context: Dict[str, Any]) -> List[RuleEvaluation]:
        evaluations = []
        current_ts = _timestamp_to_key(frame)
        if current_ts is None:
            return evaluations

        profile = context.get("profile", {})
        if state.last_timestamp and current_ts:
            inter_arrival = max((current_ts[0] - state.last_timestamp[0]) + (current_ts[1] - state.last_timestamp[1]) / max(_safe_float(frame.get("time_base"), 1000000.0), 1.0), 0.0)
            state.inter_arrival_history.append(inter_arrival)

            inter_arrival_stats = _profile_thresholds(profile, "inter_arrival") if profile.get("inter_arrival") else _profile_thresholds({"inter_arrival": {}}, "inter_arrival")
            min_bound = _effective_threshold(inter_arrival_stats, floor=0.001, multiplier=1.0)
            max_bound = _effective_threshold(inter_arrival_stats, floor=0.001, multiplier=1.5)
            if inter_arrival < min_bound:
                evaluations.append(RuleEvaluation("HARD_IA_MIN_10", "Minimum inter-arrival bound exceeded", "timing", 90, SeverityLevel.HIGH, 0.95, 78.0, f"Inter-arrival {inter_arrival:.6f}s is below the trusted lower bound"))
            if inter_arrival > max_bound:
                evaluations.append(RuleEvaluation("HARD_IA_MAX_11", "Maximum inter-arrival bound exceeded", "timing", 90, SeverityLevel.HIGH, 0.95, 80.0, f"Inter-arrival {inter_arrival:.6f}s exceeds the trusted upper bound"))

            if len(state.inter_arrival_history) >= 4:
                mean = sum(state.inter_arrival_history) / len(state.inter_arrival_history)
                jitter = max(abs(inter_arrival - mean), 0.0)
                state.jitter_history.append(jitter)
                jitter_threshold = max(min_bound * 3.0, 0.05)
                if jitter > jitter_threshold:
                    evaluations.append(RuleEvaluation("SOFT_JITTER_12", "Inter-arrival jitter anomaly", "timing", 68, SeverityLevel.MEDIUM, 0.74, 42.0, f"Observed jitter {jitter:.6f}s exceeds the trusted jitter envelope"))

            capture_time = _safe_float(frame.get("capture_time"), time.time())
            if state.last_capture_time and capture_time - state.last_capture_time > max_bound * 2.5:
                evaluations.append(RuleEvaluation("HARD_SILENCE_13", "Silence timeout", "timing", 88, SeverityLevel.HIGH, 0.92, 76.0, "No PMU frames were observed for longer than the allowed silence window"))

        packet_size = _safe_int(frame.get("packet_size"), 0)
        if profile.get("packet_size"):
            packet_stats = _profile_thresholds(profile, "packet_size")
            packet_min = _safe_float(packet_stats.get("p5"), 60.0)
            packet_max = _safe_float(packet_stats.get("p99"), 200.0)
            if packet_size < packet_min or packet_size > packet_max:
                evaluations.append(RuleEvaluation("HARD_RATE_14", "Packet size threshold breach", "timing", 86, SeverityLevel.HIGH, 0.90, 74.0, f"Packet size {packet_size} is outside the trusted envelope"))

        if len(state.jitter_history) >= 5:
            jitter_values = list(state.jitter_history)
            mean_jitter = sum(jitter_values) / len(jitter_values)
            variance = sum((value - mean_jitter) ** 2 for value in jitter_values) / len(jitter_values)
            state.timing_variance_history.append(variance)
            if variance > max(0.001, mean_jitter * 2.0):
                evaluations.append(RuleEvaluation("SOFT_DELAY_INSTABILITY_15", "Delay instability", "timing", 55, SeverityLevel.LOW, 0.60, 31.0, "Timing variance is elevated relative to the steady-state baseline"))

        if len(state.timing_variance_history) >= 4:
            drift = abs(state.timing_variance_history[-1] - state.timing_variance_history[0])
            if drift > 0.002:
                evaluations.append(RuleEvaluation("SOFT_TIMING_DRIFT_16", "Timing drift", "timing", 52, SeverityLevel.LOW, 0.58, 28.0, "Observed timing drift exceeds the normal operating envelope"))

        return evaluations

    def _replay_evaluations(self, frame: Dict[str, Any], state: StreamState, context: Dict[str, Any]) -> List[RuleEvaluation]:
        evaluations = []
        current_ts = _timestamp_to_key(frame)
        current_fingerprint = _build_fingerprint(frame)

        if current_ts and state.last_timestamp and current_ts == state.last_timestamp:
            evaluations.append(RuleEvaluation("REPLAY_TS_17", "Repeated timestamps", "replay", 90, SeverityLevel.HIGH, 0.94, 84.0, "Consecutive frames share the same timestamp"))

        if state.last_safe_frame is not None:
            last_fingerprint = _build_fingerprint(state.last_safe_frame)
            if current_fingerprint == last_fingerprint and current_ts != state.last_timestamp:
                evaluations.append(RuleEvaluation("REPLAY_FROZEN_18", "Frozen phasors", "replay", 88, SeverityLevel.HIGH, 0.92, 82.0, "Current payload matches the last safe frame while timestamp advanced"))

        if state.replay_fingerprints:
            identical = sum(1 for value in state.replay_fingerprints if value == current_fingerprint)
            if identical >= 3:
                evaluations.append(RuleEvaluation("REPLAY_PATTERN_19", "Repeated frame patterns", "replay", 84, SeverityLevel.HIGH, 0.88, 76.0, "The same frame fingerprint repeated across the replay window"))

        if len(state.replay_fingerprints) >= 4:
            recent = list(state.replay_fingerprints)[-4:]
            similarity = sum(1 for value in recent if value == current_fingerprint) / len(recent)
            if similarity >= 0.75:
                evaluations.append(RuleEvaluation("REPLAY_SIMILARITY_20", "Replay window similarity", "replay", 80, SeverityLevel.MEDIUM, 0.85, 72.0, "Current payload is highly similar to the replay window"))

        if len(state.replay_fingerprints) >= 3 and list(state.replay_fingerprints)[-3:] == [current_fingerprint] * 3:
            evaluations.append(RuleEvaluation("REPLAY_SEQUENCE_21", "Repeated sequence detection", "replay", 82, SeverityLevel.HIGH, 0.86, 74.0, "A repeated sequence of identical frames was observed"))

        if state.last_safe_frame is not None and current_ts and state.last_timestamp and current_ts[0] - state.last_timestamp[0] > 5:
            stale_fingerprint = _build_fingerprint(state.last_safe_frame)
            if current_fingerprint == stale_fingerprint:
                evaluations.append(RuleEvaluation("REPLAY_STALE_22", "Stale injection", "replay", 86, SeverityLevel.HIGH, 0.90, 79.0, "A previously safe payload reappeared after an extended gap"))

        return evaluations

    def _rate_evaluations(self, frame: Dict[str, Any], state: StreamState, context: Dict[str, Any]) -> List[RuleEvaluation]:
        evaluations = []
        config = self._detector_config()
        expected_fps = self._expected_fps(context.get("profile", {}))
        observed_time = _safe_float(frame.get("frame_time"), _safe_float(frame.get("capture_time"), time.time()))
        window = max(_safe_float(config.get("rate_window_seconds"), 1.0), 0.1)
        burst_window = max(_safe_float(config.get("burst_window_seconds"), 0.25), 0.05)

        state.arrival_times.append(observed_time)
        state.byte_events.append((observed_time, max(_safe_int(frame.get("packet_size"), 0), 0)))
        while state.arrival_times and observed_time - state.arrival_times[0] > window:
            state.arrival_times.popleft()
        while state.byte_events and observed_time - state.byte_events[0][0] > window:
            state.byte_events.popleft()

        elapsed = observed_time - state.arrival_times[0] if len(state.arrival_times) >= 2 else 0.0
        if elapsed > 0:
            state.frames_per_second = (len(state.arrival_times) - 1) / elapsed
            state.packets_per_second = state.frames_per_second
            state.bytes_per_second = sum(size for _, size in state.byte_events) / elapsed
        else:
            state.frames_per_second = 0.0
            state.packets_per_second = 0.0
            state.bytes_per_second = 0.0
        burst_count = sum(1 for stamp in state.arrival_times if observed_time - stamp <= burst_window)
        state.burst_rate = max(0.0, (burst_count - 1) / burst_window)
        if state.frames_per_second > 0:
            state.fps_history.append(state.frames_per_second)

        minimum = max(_safe_int(config.get("min_rate_samples"), 5), 2)
        if expected_fps <= 0 or len(state.arrival_times) < minimum:
            return evaluations

        observed_fps = state.frames_per_second
        flood_limit = expected_fps * _safe_float(config.get("fps_flood_multiplier"), 1.75)
        slowdown_limit = expected_fps * _safe_float(config.get("fps_slowdown_multiplier"), 0.60)
        suppression_limit = expected_fps * _safe_float(config.get("fps_suppression_multiplier"), 0.25)
        burst_limit = expected_fps * _safe_float(config.get("burst_multiplier"), 2.50)
        profile_packet_mean = _safe_float(_safe_dict(context.get("profile", {}).get("packet_size", {})).get("mean"), _safe_int(frame.get("packet_size"), 0))
        byte_limit = expected_fps * max(profile_packet_mean or 0.0, 1.0) * _safe_float(config.get("bytes_per_second_multiplier"), 2.0)

        abnormal_rate = observed_fps > flood_limit or observed_fps < slowdown_limit
        state.rate_violation_count = state.rate_violation_count + 1 if abnormal_rate else 0
        sustained = state.rate_violation_count >= max(_safe_int(config.get("sustained_rate_frames"), 3), 1)

        if observed_fps > flood_limit:
            evaluations.append(RuleEvaluation("RATE_FLOOD_32", "Packet flooding", "timing", 84, SeverityLevel.HIGH if sustained else SeverityLevel.MEDIUM, 0.90, 68.0 if sustained else 46.0, f"Observed FPS {observed_fps:.2f} exceeds expected {expected_fps:.2f}"))
        if observed_fps < suppression_limit:
            evaluations.append(RuleEvaluation("RATE_SUPPRESS_33", "Frame-rate suppression", "timing", 86, SeverityLevel.HIGH, 0.91, 72.0, f"Observed FPS {observed_fps:.2f} is far below expected {expected_fps:.2f}"))
        elif observed_fps < slowdown_limit:
            evaluations.append(RuleEvaluation("RATE_SLOW_34", "Timing slowdown", "timing", 65, SeverityLevel.MEDIUM if sustained else SeverityLevel.LOW, 0.75, 44.0 if sustained else 26.0, f"Observed FPS {observed_fps:.2f} is below expected {expected_fps:.2f}"))
        if state.burst_rate > burst_limit:
            evaluations.append(RuleEvaluation("RATE_BURST_35", "Abnormal burst rate", "timing", 72, SeverityLevel.MEDIUM, 0.82, 48.0, f"Burst rate {state.burst_rate:.2f} FPS exceeds the allowed burst envelope"))
        if state.bytes_per_second > byte_limit and observed_fps > flood_limit:
            evaluations.append(RuleEvaluation("DOS_BYTES_36", "Sustained traffic surge", "timing", 83, SeverityLevel.HIGH if sustained else SeverityLevel.MEDIUM, 0.87, 64.0 if sustained else 42.0, f"Traffic rate {state.bytes_per_second:.2f} bytes/s exceeds expected byte rate"))

        return evaluations

    def _sequence_evaluations(self, frame: Dict[str, Any], state: StreamState) -> List[RuleEvaluation]:
        evaluations = []
        sequence = _safe_int(frame.get("sequence_number"))
        if sequence is None and _safe_bool(self._detector_config().get("use_frame_number_sequence"), True):
            sequence = _safe_int(frame.get("frame_number"))
        if sequence is None:
            return evaluations

        jump_threshold = max(_safe_int(self._detector_config().get("sequence_jump_threshold"), 1), 1)
        replay_window = max(_safe_int(self._detector_config().get("sequence_replay_window"), 32), 2)
        recent = list(state.recent_sequences)[-replay_window:]
        if state.last_sequence is not None:
            if sequence == state.last_sequence:
                state.duplicate_counter += 1
                evaluations.append(RuleEvaluation("SEQ_DUPLICATE_37", "Duplicate sequence", "replay", 82, SeverityLevel.HIGH, 0.92, 70.0, f"Sequence {sequence} repeated"))
            elif sequence < state.last_sequence:
                state.out_of_order_counter += 1
                evaluations.append(RuleEvaluation("SEQ_ORDER_38", "Out-of-order sequence", "replay", 82, SeverityLevel.HIGH, 0.90, 68.0, f"Sequence {sequence} arrived after {state.last_sequence}"))
            elif sequence - state.last_sequence > jump_threshold:
                missing = sequence - state.last_sequence - 1
                state.sequence_gap_counter += missing
                evaluations.append(RuleEvaluation("SEQ_GAP_39", "Missing frames or sequence jump", "timing", 78, SeverityLevel.MEDIUM, 0.86, 56.0, f"Sequence advanced by {sequence - state.last_sequence}; estimated missing frames={missing}"))
        if sequence in recent and sequence != state.last_sequence:
            evaluations.append(RuleEvaluation("SEQ_REPLAY_WINDOW_40", "Replayed sequence window", "replay", 86, SeverityLevel.HIGH, 0.91, 74.0, f"Sequence {sequence} reappeared within the recent sequence window"))

        if state.last_sequence is None or sequence > state.last_sequence:
            state.expected_sequence = sequence + 1
            state.last_sequence = sequence
        state.recent_sequences.append(sequence)
        return evaluations

    def _suppression_evaluations(self, frame: Dict[str, Any], state: StreamState, context: Dict[str, Any]) -> List[RuleEvaluation]:
        evaluations = []
        current_ts = _timestamp_to_key(frame)
        expected_fps = self._expected_fps(context.get("profile", {}))
        if current_ts is None or expected_fps <= 0:
            state.last_observed_timestamp = current_ts or state.last_observed_timestamp
            return evaluations

        interval = 1.0 / expected_fps
        previous_seconds = _timestamp_seconds(state.last_observed_timestamp, _safe_float(frame.get("time_base"), 1000000.0))
        current_seconds = _timestamp_seconds(current_ts, _safe_float(frame.get("time_base"), 1000000.0))
        if previous_seconds is not None and current_seconds is not None:
            elapsed = current_seconds - previous_seconds
            tolerance = interval * _safe_float(self._detector_config().get("timestamp_tolerance_ratio"), 0.35)
            missing = max(0, int(math.floor((elapsed + tolerance) / interval)) - 1)
            threshold = max(_safe_int(self._detector_config().get("missing_frame_threshold"), 2), 1)
            if missing >= threshold:
                state.missing_window_counter += missing
                evaluations.append(RuleEvaluation("SUPPRESS_WINDOW_41", "Missing timestamp window", "timing", 87, SeverityLevel.HIGH, 0.92, 74.0, f"Timestamp gap indicates approximately {missing} absent expected frames"))
        state.last_observed_timestamp = current_ts
        return evaluations

    def _mitm_symptom_evaluations(self, frame: Dict[str, Any], state: StreamState, context: Dict[str, Any], current_evaluations: List[RuleEvaluation]) -> List[RuleEvaluation]:
        evaluations = []
        src_ip = _safe_str(frame.get("src_ip"))
        src_mac = _safe_str(frame.get("src_mac"))
        identity = _safe_dict(context.get("profile", {}).get("identity", {}))
        baseline_ips = {str(value) for value in identity.get("src_ips", []) if str(value).strip()}
        baseline_macs = {str(value) for value in identity.get("src_macs", []) if str(value).strip()}
        changed_mapping = (state.last_source_ip is not None and src_ip != state.last_source_ip) or (state.last_source_mac is not None and src_mac != state.last_source_mac)
        outside_baseline = (baseline_ips and src_ip not in baseline_ips) or (baseline_macs and src_mac not in baseline_macs)

        if changed_mapping or outside_baseline:
            evaluations.append(RuleEvaluation("MITM_REMAP_42", "Source mapping change symptom", "structural", 77, SeverityLevel.MEDIUM, 0.78, 48.0, "Observed source MAC/IP mapping changed from the trusted or recent stream identity; possible interception symptom"))

        current_ts = _timestamp_to_key(frame)
        time_base = _safe_float(frame.get("time_base"), 1000000.0)
        observed_time = _safe_float(frame.get("frame_time"), _safe_float(frame.get("capture_time"), time.time()))
        previous_seconds = _timestamp_seconds(state.last_observed_timestamp, time_base)
        current_seconds = _timestamp_seconds(current_ts, time_base)
        latency_anomaly = False
        if state.last_observed_capture_time and previous_seconds is not None and current_seconds is not None:
            arrival_delta = observed_time - state.last_observed_capture_time
            protocol_delta = current_seconds - previous_seconds
            asymmetry = abs(arrival_delta - protocol_delta)
            state.route_delay_history.append(asymmetry)
            expected_fps = self._expected_fps(context.get("profile", {}))
            interval = 1.0 / expected_fps if expected_fps > 0 else 0.05
            latency_limit = interval * _safe_float(self._detector_config().get("route_latency_multiplier"), 3.0)
            state.route_latency_anomaly_count = state.route_latency_anomaly_count + 1 if asymmetry > latency_limit else 0
            latency_anomaly = state.route_latency_anomaly_count >= max(_safe_int(self._detector_config().get("route_latency_consecutive_frames"), 2), 1)
            if latency_anomaly:
                evaluations.append(RuleEvaluation("DOS_CONGESTION_45", "Queue-like timing congestion", "timing", 68, SeverityLevel.MEDIUM, 0.72, 40.0, f"Repeated arrival/timestamp asymmetry reached {asymmetry:.6f}s and may indicate traffic congestion"))
                evaluations.append(RuleEvaluation("MITM_LATENCY_43", "Abnormal route-like latency behavior", "timing", 62, SeverityLevel.LOW, 0.62, 28.0, f"Repeated arrival/timestamp asymmetry reached {asymmetry:.6f}s; this is a symptom, not attribution"))

        correlated = changed_mapping or outside_baseline or latency_anomaly
        if correlated and any(item.category == "replay" or item.rule_id.startswith(("SUPPRESS_", "RATE_")) for item in current_evaluations):
            evaluations.append(RuleEvaluation("MITM_CORRELATED_44", "Correlated interception symptoms", "replay", 88, SeverityLevel.HIGH, 0.88, 70.0, "Identity or route-like timing symptoms coincide with replay or suppression behavior; possible MITM activity"))

        state.last_source_ip = src_ip
        state.last_source_mac = src_mac
        state.last_observed_capture_time = observed_time
        return evaluations

    def _compute_disturbance(self, frame: Dict[str, Any], state: StreamState, profile: Dict[str, Any]) -> Dict[str, Any]:
        if state.last_safe_frame is None:
            return {"score": 0.0, "active": False, "multiplier": 1.0}

        voltage = _voltage_mean(frame)
        current = _current_mean(frame)
        freq = _safe_float(frame.get("freq1"), 50.0)
        rocof = abs(_safe_float(frame.get("dfreq1"), 0.0))
        voltage_delta = abs(voltage - state.last_voltage_mean)
        current_delta = abs(current - state.last_current_mean)
        freq_delta = abs(freq - state.last_freq)

        v_stats = _profile_thresholds(profile, "voltage_delta")
        c_stats = _profile_thresholds(profile, "current_delta")
        f_stats = _profile_thresholds(profile, "frequency_delta")
        r_stats = _profile_thresholds(profile, "rocof")
        s_stats = _profile_thresholds(profile, "smoothness")
        angle_stats = _profile_thresholds(profile, "phase_angle_diff")
        v_imb_stats = _profile_thresholds(profile, "voltage_imbalance")
        c_imb_stats = _profile_thresholds(profile, "current_imbalance")

        voltage_imbalance = _compute_imbalance([
            _safe_float(frame.get("va_mag")),
            _safe_float(frame.get("vb_mag")),
            _safe_float(frame.get("vc_mag")),
        ])
        current_imbalance = _compute_imbalance([
            _safe_float(frame.get("ia_mag")),
            _safe_float(frame.get("ib_mag")),
            _safe_float(frame.get("ic_mag")),
        ])
        phase_angle_error = _phase_spacing_error(frame)

        if len(state.voltage_history) >= 2:
            smooth_voltage = max(abs(voltage - state.voltage_history[-1]), abs(voltage - state.voltage_history[-2]))
        else:
            smooth_voltage = voltage_delta
        if len(state.current_history) >= 2:
            smooth_current = max(abs(current - state.current_history[-1]), abs(current - state.current_history[-2]))
        else:
            smooth_current = current_delta
        if len(state.freq_history) >= 2:
            smooth_freq = abs(freq - state.freq_history[-1])
        else:
            smooth_freq = freq_delta
        smoothness = max(smooth_voltage, smooth_current, smooth_freq)

        thresholds = {
            "voltage": _effective_threshold(v_stats, floor=0.01),
            "current": _effective_threshold(c_stats, floor=0.01),
            "frequency": _effective_threshold(f_stats, floor=0.05),
            "rocof": _effective_threshold(r_stats, floor=0.05),
            "smoothness": _effective_threshold(s_stats, floor=0.01),
            "voltage_imbalance": _effective_threshold(v_imb_stats, floor=0.01),
            "current_imbalance": _effective_threshold(c_imb_stats, floor=0.01),
            "phase_angle_diff": _effective_threshold(angle_stats, floor=0.1),
        }

        ratios = {
            "voltage": min(1.5, voltage_delta / max(thresholds["voltage"], 1e-6)),
            "current": min(1.5, current_delta / max(thresholds["current"], 1e-6)),
            "frequency": min(1.5, freq_delta / max(thresholds["frequency"], 1e-6)),
            "rocof": min(1.5, rocof / max(thresholds["rocof"], 1e-6)),
            "smoothness": min(1.5, smoothness / max(thresholds["smoothness"], 1e-6)),
            "voltage_imbalance": min(1.5, voltage_imbalance / max(thresholds["voltage_imbalance"], 1e-6)),
            "current_imbalance": min(1.5, current_imbalance / max(thresholds["current_imbalance"], 1e-6)),
            "phase_angle_diff": min(1.5, phase_angle_error / max(thresholds["phase_angle_diff"], 1e-6)),
        }

        weighted_terms = [
            (0.18, ratios["voltage"]),
            (0.16, ratios["current"]),
            (0.14, ratios["frequency"]),
            (0.12, ratios["rocof"]),
            (0.16, ratios["smoothness"]),
            (0.08, ratios["voltage_imbalance"]),
            (0.08, ratios["current_imbalance"]),
            (0.08, ratios["phase_angle_diff"]),
        ]
        raw_score = sum(weight * min(ratio / 1.5, 1.0) for weight, ratio in weighted_terms)
        score = round(min(100.0, raw_score * 100.0), 2)

        if score >= 75:
            multiplier = 3.0
        elif score >= 50:
            multiplier = 2.0
        elif score >= 25:
            multiplier = 1.5
        else:
            multiplier = 1.0

        return {"score": score, "active": score >= 25.0, "multiplier": multiplier}

    def _physics_evaluations(self, frame: Dict[str, Any], state: StreamState, context: Dict[str, Any], disturbance_multiplier: float) -> List[RuleEvaluation]:
        evaluations = []
        profile = context.get("profile", {})
        voltage = _voltage_mean(frame)
        current = _current_mean(frame)
        freq = _safe_float(frame.get("freq1"), 50.0)
        rocof = abs(_safe_float(frame.get("dfreq1"), 0.0))

        if state.last_safe_frame is None:
            prev_voltage = voltage
            prev_current = current
            prev_freq = freq
        else:
            prev_voltage = state.last_voltage_mean
            prev_current = state.last_current_mean
            prev_freq = state.last_freq

        voltage_delta = abs(voltage - prev_voltage)
        current_delta = abs(current - prev_current)
        freq_delta = abs(freq - prev_freq)

        v_stats = _profile_thresholds(profile, "voltage_delta")
        c_stats = _profile_thresholds(profile, "current_delta")
        f_stats = _profile_thresholds(profile, "frequency_delta")
        r_stats = _profile_thresholds(profile, "rocof")
        s_stats = _profile_thresholds(profile, "smoothness")
        angle_stats = _profile_thresholds(profile, "phase_angle_diff")
        v_imb_stats = _profile_thresholds(profile, "voltage_imbalance")
        c_imb_stats = _profile_thresholds(profile, "current_imbalance")

        voltage_imbalance = _compute_imbalance([
            _safe_float(frame.get("va_mag")),
            _safe_float(frame.get("vb_mag")),
            _safe_float(frame.get("vc_mag")),
        ])
        current_imbalance = _compute_imbalance([
            _safe_float(frame.get("ia_mag")),
            _safe_float(frame.get("ib_mag")),
            _safe_float(frame.get("ic_mag")),
        ])
        phase_angle_error = _phase_spacing_error(frame)

        voltage_threshold = _effective_threshold(v_stats, floor=0.01, multiplier=disturbance_multiplier)
        current_threshold = _effective_threshold(c_stats, floor=0.01, multiplier=disturbance_multiplier)
        frequency_threshold = _effective_threshold(f_stats, floor=0.05, multiplier=disturbance_multiplier)
        smooth_threshold = _effective_threshold(s_stats, floor=0.01, multiplier=disturbance_multiplier)

        if abs(voltage_delta) > voltage_threshold and abs(current_delta) < current_threshold:
            tier = self._anomaly_tier(voltage_delta, v_stats)
            item = self._profile_rule("PHYS_VOLTAGE_23", "Voltage-current consistency", tier, "Voltage changed abruptly without a matching current response")
            if item is not None:
                evaluations.append(item)

        if abs(current_delta) > current_threshold and abs(voltage_delta) < voltage_threshold:
            tier = self._anomaly_tier(current_delta, c_stats)
            item = self._profile_rule("PHYS_CURRENT_24", "Power consistency", tier, "Current changed abruptly without a matching voltage response")
            if item is not None:
                evaluations.append(item)

        if abs(freq_delta) > frequency_threshold and rocof < _effective_threshold(r_stats, floor=0.05):
            tier = self._anomaly_tier(freq_delta, f_stats)
            item = self._profile_rule("PHYS_FREQ_25", "ROCOF-frequency consistency", tier, "Frequency changed abruptly without matching ROCOF behavior")
            if item is not None:
                evaluations.append(item)

        if len(state.voltage_history) >= 2 and len(state.current_history) >= 2:
            smooth_voltage = max(abs(voltage - state.voltage_history[-1]), abs(voltage - state.voltage_history[-2]))
            smooth_current = max(abs(current - state.current_history[-1]), abs(current - state.current_history[-2]))
            transient = max(smooth_voltage, smooth_current, abs(freq - state.freq_history[-1]) if state.freq_history else 0.0)
            tier = self._anomaly_tier(transient, s_stats)
            if tier is not None and transient > smooth_threshold:
                item = self._profile_rule("PHYS_SMOOTH_27", "Smooth temporal evolution", tier, "Transient evolution exceeded the trusted smoothness envelope")
                if item is not None:
                    evaluations.append(item)

        if len(state.freq_history) >= 2 and abs(freq_delta) > _effective_threshold(f_stats, floor=0.05, multiplier=disturbance_multiplier) and rocof > _effective_threshold(r_stats, floor=0.05) and abs(current_delta) > _effective_threshold(c_stats, floor=0.01):
            tier = self._anomaly_tier(abs(freq_delta) + rocof, {"p95": _effective_threshold(f_stats, floor=0.05, multiplier=disturbance_multiplier) + _effective_threshold(r_stats, floor=0.05), "p99": _effective_threshold(f_stats, floor=0.05, multiplier=disturbance_multiplier) + _effective_threshold(r_stats, floor=0.05) + 0.05, "std": 0.05})
            item = self._profile_rule("PHYS_MULTI_28", "Multi-signal correlation", tier, "Frequency, ROCOF, and current changes diverged beyond the trusted baseline")
            if item is not None:
                evaluations.append(item)

        if voltage_imbalance > _effective_threshold(v_imb_stats, floor=0.01):
            tier = self._anomaly_tier(voltage_imbalance, v_imb_stats)
            item = self._profile_rule("PHYS_VIMB_29", "Voltage imbalance", tier, "Voltage phase imbalance exceeded the trusted PMU baseline")
            if item is not None:
                evaluations.append(item)

        if current_imbalance > _effective_threshold(c_imb_stats, floor=0.01):
            tier = self._anomaly_tier(current_imbalance, c_imb_stats)
            item = self._profile_rule("PHYS_CIMB_30", "Current imbalance", tier, "Current phase imbalance exceeded the trusted PMU baseline")
            if item is not None:
                evaluations.append(item)

        if phase_angle_error > _effective_threshold(angle_stats, floor=0.1):
            tier = self._anomaly_tier(phase_angle_error, angle_stats)
            item = self._profile_rule("PHYS_ANGLE_31", "Angle difference stability", tier, "Phase-angle spacing deviated from the trusted baseline")
            if item is not None:
                evaluations.append(item)

        return evaluations

    def _state_evaluations(self, frame: Dict[str, Any], state: StreamState) -> List[RuleEvaluation]:
        evaluations = []
        if frame.get("time_sync") is False:
            evaluations.append(RuleEvaluation("STATE_TIME_SYNC_29", "Time synchronization loss", "structural", 75, SeverityLevel.HIGH, 0.78, 55.0, "PMU time synchronization flag is set"))
        if frame.get("pmu_error") is True:
            evaluations.append(RuleEvaluation("STATE_PMU_ERROR_30", "PMU error flag", "structural", 78, SeverityLevel.HIGH, 0.80, 58.0, "PMU internal error flag is set"))
        if frame.get("data_error") is True:
            evaluations.append(RuleEvaluation("STATE_DATA_ERROR_31", "Data error flag", "structural", 78, SeverityLevel.HIGH, 0.80, 58.0, "PMU data error flag is set"))
        return evaluations

    def _compute_fault_score(self, frame: Dict[str, Any], state: StreamState, profile: Dict[str, Any], disturbance_score: float) -> float:
        if state.last_safe_frame is None:
            return 0.0

        voltage = _voltage_mean(frame)
        current = _current_mean(frame)
        freq = _safe_float(frame.get("freq1"), 50.0)
        rocof = abs(_safe_float(frame.get("dfreq1"), 0.0))

        voltage_delta = abs(voltage - state.last_voltage_mean)
        current_delta = abs(current - state.last_current_mean)
        freq_delta = abs(freq - state.last_freq)

        v_stats = _profile_thresholds(profile, "voltage_delta")
        c_stats = _profile_thresholds(profile, "current_delta")
        f_stats = _profile_thresholds(profile, "frequency_delta")
        r_stats = _profile_thresholds(profile, "rocof")
        s_stats = _profile_thresholds(profile, "smoothness")

        fault_signals = []
        if voltage_delta >= _effective_threshold(v_stats, floor=0.01):
            fault_signals.append(30)
        if current_delta >= _effective_threshold(c_stats, floor=0.01):
            fault_signals.append(30)
        if freq_delta >= _effective_threshold(f_stats, floor=0.05):
            fault_signals.append(20)
        if rocof >= _effective_threshold(r_stats, floor=0.05):
            fault_signals.append(20)

        if len(state.voltage_history) >= 2 and len(state.current_history) >= 2:
            smooth_voltage = max(abs(voltage - state.voltage_history[-1]), abs(voltage - state.voltage_history[-2]))
            smooth_current = max(abs(current - state.current_history[-1]), abs(current - state.current_history[-2]))
            transient = max(smooth_voltage, smooth_current, abs(freq - state.freq_history[-1]) if state.freq_history else 0.0)
            if transient >= _effective_threshold(s_stats, floor=0.01):
                fault_signals.append(20)

        base_fault = min(100.0, sum(fault_signals))
        return min(100.0, max(base_fault, disturbance_score * 0.65))

    def _compute_cyber_score(self, evaluations: List[RuleEvaluation], suspicious_count: int) -> float:
        category_scores = {"structural": 0.0, "timing": 0.0, "replay": 0.0, "physics": 0.0}
        for evaluation in evaluations:
            if evaluation.category in category_scores:
                category_scores[evaluation.category] += evaluation.score

        capped = {key: min(100.0, value) for key, value in category_scores.items()}
        norms = {key: min(1.0, value / 100.0) for key, value in capped.items()}
        cyber_score = round(100.0 * (
            0.45 * norms["structural"]
            + 0.25 * norms["timing"]
            + 0.20 * norms["replay"]
            + 0.10 * norms["physics"]
        ), 2)
        if suspicious_count >= 5:
            cyber_score += 8.0
        if suspicious_count >= 10:
            cyber_score += 12.0
        return min(100.0, cyber_score)

    def _fuse_scores(self, evaluations: List[RuleEvaluation], fault_score: float, suspicious_count: int) -> Dict[str, Any]:
        category_scores = {"structural": 0.0, "timing": 0.0, "replay": 0.0, "physics": 0.0}
        rule_scores = {}

        for evaluation in evaluations:
            rule_scores[evaluation.rule_id] = round(evaluation.score / 100.0, 2)
            if evaluation.category in category_scores:
                category_scores[evaluation.category] += evaluation.score

        capped = {cat: min(100.0, score) for cat, score in category_scores.items()}
        normalized = {cat: min(1.0, score / 100.0) for cat, score in capped.items()}
        weights = {"structural": 0.35, "timing": 0.20, "replay": 0.15, "physics": 0.30}
        final_score = round(100.0 * sum(weights[cat] * normalized[cat] for cat in weights), 2)
        if suspicious_count >= 5:
            final_score += 8.0
        if suspicious_count >= 10:
            final_score += 12.0

        return {
            "category_scores": {key: round(value, 2) for key, value in capped.items()},
            "rule_scores": rule_scores,
            "final_score": min(100.0, final_score),
            "fault_score": round(fault_score, 2),
        }

    def _safe_update(self, frame: Dict[str, Any], state: StreamState, fused: Dict[str, Any], evaluations: List[RuleEvaluation], disturbance_score: float, anomaly_flag: bool) -> None:
        if fused["final_score"] >= self.suspicious_threshold or any(item.severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL} and item.category == "structural" for item in evaluations):
            state.suspicious_count = min(30, state.suspicious_count + 1)
            return

        current_ts = _timestamp_to_key(frame)
        state.last_timestamp = current_ts
        state.last_capture_time = _safe_float(frame.get("capture_time"), time.time())
        state.last_voltage_mean = _voltage_mean(frame)
        state.last_current_mean = _current_mean(frame)
        state.last_freq = _safe_float(frame.get("freq1"), 50.0)
        state.last_rocof = _safe_float(frame.get("dfreq1"), 0.0)
        state.last_safe_frame = dict(frame)
        state.suspicious_count = max(0, state.suspicious_count - 1)

        state.voltage_history.append(state.last_voltage_mean)
        state.current_history.append(state.last_current_mean)
        state.freq_history.append(state.last_freq)
        state.score_history.append(fused["final_score"])
        state.anomaly_history.append(1 if anomaly_flag else 0)
        state.replay_fingerprints.append(_build_fingerprint(frame))

    def _windowed_stats(self, state: StreamState) -> Dict[str, float]:
        stats = {}
        if state.score_history:
            stats["avg_score_window"] = round(sum(state.score_history) / len(state.score_history), 2)
            stats["max_score_window"] = round(max(state.score_history), 2)
        if state.anomaly_history:
            stats["anomaly_frequency"] = round(sum(state.anomaly_history) / len(state.anomaly_history), 2)
        if state.freq_history:
            mean_freq = sum(state.freq_history) / len(state.freq_history)
            freq_std = (sum((freq - mean_freq) ** 2 for freq in state.freq_history) / len(state.freq_history)) ** 0.5
            stats["freq_std"] = round(freq_std, 4)
            stats["freq_min"] = round(min(state.freq_history), 4)
            stats["freq_max"] = round(max(state.freq_history), 4)
        stats["frames_per_second"] = round(state.frames_per_second, 3)
        stats["packets_per_second"] = round(state.packets_per_second, 3)
        stats["bytes_per_second"] = round(state.bytes_per_second, 3)
        stats["burst_rate"] = round(state.burst_rate, 3)
        if state.fps_history:
            stats["avg_fps_window"] = round(sum(state.fps_history) / len(state.fps_history), 3)
        return stats

    def evaluate_frame(self, frame: Dict[str, Any]) -> Dict[str, Any]:
        self.frame_count += 1
        ci_frame = CaseInsensitiveFrame(frame)
        normalized = {
            "pmu_id": _safe_str(ci_frame.get("pmu_id")),
            "stream_id": _safe_str(ci_frame.get("stream_id")),
            "src_ip": _safe_str(ci_frame.get("src_ip")),
            "src_mac": _safe_str(ci_frame.get("src_mac")),
            "dst_ip": _safe_str(ci_frame.get("dst_ip")),
            "dst_mac": _safe_str(ci_frame.get("dst_mac")),
            "soc": _safe_int(ci_frame.get("soc")),
            "fracsec": _safe_int(ci_frame.get("fracsec"), 0),
            "time_base": _safe_float(ci_frame.get("time_base"), 1000000.0),
            "crc_ok": _safe_bool(ci_frame.get("crc_ok"), True),
            "time_sync": _safe_bool(ci_frame.get("time_sync"), None),
            "pmu_error": _safe_bool(ci_frame.get("pmu_error"), None),
            "data_error": _safe_bool(ci_frame.get("data_error"), None),
            "packet_size": _safe_int(ci_frame.get("packet_size"), 0),
            "capture_time": _safe_float(ci_frame.get("capture_time"), time.time()),
            "frame_time": _safe_float(ci_frame.get("frame_time"), None),
            "frame_number": _safe_int(ci_frame.get("frame_number"), None),
            "sequence_number": _safe_int(ci_frame.get("sequence_number", ci_frame.get("sequence")), None),
            "freq1": _safe_float(ci_frame.get("freq1"), 50.0),
            "dfreq1": _safe_float(ci_frame.get("dfreq1"), 0.0),
            "va_mag": _safe_float(ci_frame.get("va_mag"), 0.0),
            "vb_mag": _safe_float(ci_frame.get("vb_mag"), 0.0),
            "vc_mag": _safe_float(ci_frame.get("vc_mag"), 0.0),
            "ia_mag": _safe_float(ci_frame.get("ia_mag"), 0.0),
            "ib_mag": _safe_float(ci_frame.get("ib_mag"), 0.0),
            "ic_mag": _safe_float(ci_frame.get("ic_mag"), 0.0),
            "va_ang": _safe_float(ci_frame.get("va_ang"), 0.0),
            "vb_ang": _safe_float(ci_frame.get("vb_ang"), 0.0),
            "vc_ang": _safe_float(ci_frame.get("vc_ang"), 0.0),
        }
        normalized["timestamp"] = _timestamp_to_key(normalized)

        stream_key = self._compose_stream_key(normalized)
        state = self.stream_states.setdefault(stream_key, StreamState(key=stream_key))
        context = self._build_context(normalized, state)

        disturbance = self._compute_disturbance(normalized, state, context.get("profile", {}))
        disturbance_score = disturbance["score"]
        disturbance_active = disturbance["active"]
        disturbance_multiplier = disturbance["multiplier"]

        evaluations = []
        evaluations.extend(self._hard_rule_evaluations(normalized, context))
        evaluations.extend(self._timing_evaluations(normalized, state, context))
        evaluations.extend(self._replay_evaluations(normalized, state, context))
        evaluations.extend(self._rate_evaluations(normalized, state, context))
        evaluations.extend(self._sequence_evaluations(normalized, state))
        evaluations.extend(self._mitm_symptom_evaluations(normalized, state, context, evaluations))
        evaluations.extend(self._suppression_evaluations(normalized, state, context))
        evaluations.extend(self._physics_evaluations(normalized, state, context, disturbance_multiplier))
        evaluations.extend(self._state_evaluations(normalized, state))

        abnormal_flag = bool(evaluations) or disturbance_active
        state.anomaly_history.append(1 if abnormal_flag else 0)
        if abnormal_flag:
            state.suspicious_count = min(30, state.suspicious_count + 1)
        else:
            state.suspicious_count = max(0, state.suspicious_count - 1)

        fault_score = self._compute_fault_score(normalized, state, context.get("profile", {}), disturbance_score)
        fused = self._fuse_scores(evaluations, fault_score, state.suspicious_count)
        cyber_score = self._compute_cyber_score(evaluations, state.suspicious_count)
        final_score = min(100.0, max(fused["final_score"], cyber_score * 0.5, fault_score * 0.5))
        final_score = round(final_score + (min(20.0, state.suspicious_count * 1.5)), 2)
        final_score = min(100.0, final_score)

        corrupted = any(item.category == "structural" and item.severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL} for item in evaluations)
        severity = self._severity_from_score(final_score, corrupted, cyber_score, fault_score)

        for item in evaluations:
            self.rule_frequency[item.rule_id] += 1

        self._safe_update(normalized, state, fused, evaluations, disturbance_score, abnormal_flag)

        category_scores = fused["category_scores"]
        ml_features = {
            "frame_score": round(final_score, 2),
            "cyber_score": round(cyber_score, 2),
            "fault_score": round(fault_score, 2),
            "disturbance_score": round(disturbance_score, 2),
            "structural_score": round(category_scores.get("structural", 0.0), 2),
            "timing_score": round(category_scores.get("timing", 0.0), 2),
            "replay_score": round(category_scores.get("replay", 0.0), 2),
            "physics_score": round(category_scores.get("physics", 0.0), 2),
            "hard_rule_count": sum(1 for item in evaluations if item.category == "structural" and item.severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL}),
            "soft_rule_count": sum(1 for item in evaluations if not (item.category == "structural" and item.severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL})),
            "suspicious_count": int(state.suspicious_count),
            "frames_per_second": round(state.frames_per_second, 3),
            "burst_rate": round(state.burst_rate, 3),
            "bytes_per_second": round(state.bytes_per_second, 3),
            "sequence_gap_counter": int(state.sequence_gap_counter),
            "duplicate_counter": int(state.duplicate_counter),
            "out_of_order_counter": int(state.out_of_order_counter),
        }

        if corrupted:
            assessment = "CORRUPTED"
        elif disturbance_active and final_score < 30:
            assessment = "DISTURBANCE"
        elif final_score >= 55 or cyber_score >= 55 or fault_score >= 60:
            assessment = "HIGHLY SUSPICIOUS"
        elif final_score >= 30 or cyber_score >= 30 or fault_score >= 30:
            assessment = "SUSPICIOUS"
        elif final_score >= 10 or fault_score >= 10:
            assessment = "LOW SUSPICION"
        else:
            assessment = "NORMAL"

        expected_next_timestamp = self._expected_next_timestamp(
            state,
            context.get("profile", {}),
            _safe_float(normalized.get("time_base"), 1000000.0),
        )

        return {
            "frame_num": self.frame_count,
            "frame_score": round(final_score, 2),
            "normalized_score": round(final_score / 100.0, 4),
            "severity": severity.value,
            "corrupted": corrupted,
            "assessment": assessment,
            "rules_triggered": [item.rule_id for item in evaluations],
            "ml_features": ml_features,
            "windowed_stats": self._windowed_stats(state),
            "details": {
                "frame_num": self.frame_count,
                "pmu_id": normalized.get("pmu_id"),
                "stream_id": normalized.get("stream_id"),
                "timestamp": normalized.get("soc"),
                "fracsec": normalized.get("fracsec"),
                "src_ip": normalized.get("src_ip"),
                "src_mac": normalized.get("src_mac"),
                "disturbance_score": round(disturbance_score, 2),
                "disturbance_active": disturbance_active,
                "suspicious_count": int(state.suspicious_count),
                "expected_fps": round(self._expected_fps(context.get("profile", {})), 3),
                "frames_per_second": round(state.frames_per_second, 3),
                "packets_per_second": round(state.packets_per_second, 3),
                "bytes_per_second": round(state.bytes_per_second, 3),
                "burst_rate": round(state.burst_rate, 3),
                "fps_history": [round(value, 3) for value in state.fps_history],
                "expected_next_timestamp": expected_next_timestamp,
                "expected_sequence": state.expected_sequence,
                "sequence_gap_counter": int(state.sequence_gap_counter),
                "duplicate_counter": int(state.duplicate_counter),
                "out_of_order_counter": int(state.out_of_order_counter),
                "missing_window_counter": int(state.missing_window_counter),
            },
            "category_scores": category_scores,
            "fault_score": round(fault_score, 2),
            "cyber_score": round(cyber_score, 2),
            "disturbance_score": round(disturbance_score, 2),
            "disturbance_active": disturbance_active,
            "suspicious_count": int(state.suspicious_count),
            "explainability": {
                "disturbance_score": round(disturbance_score, 2),
                "disturbance_active": disturbance_active,
                "disturbance_multiplier": round(disturbance_multiplier, 2),
                "persistent_anomaly_level": int(state.suspicious_count),
                "rules": [
                    {
                        "id": item.rule_id,
                        "name": item.name,
                        "category": item.category,
                        "confidence": round(item.confidence, 2),
                        "reason": item.reason,
                    }
                    for item in evaluations
                ],
            },
        }

    def get_stats(self) -> Dict[str, Any]:
        return {
            "frames": self.frame_count,
            "rule_freq": dict(self.rule_frequency),
            "hard_rules": 0,
            "soft_rules": 0,
        }

    def get_stream_state(self, frame: Dict[str, Any]) -> Optional[StreamState]:
        """Return current rule state for final-decision evaluation of a frame."""
        ci_frame = CaseInsensitiveFrame(frame)
        lookup = {
            "pmu_id": _safe_str(ci_frame.get("pmu_id")),
            "stream_id": _safe_str(ci_frame.get("stream_id")),
            "dst_ip": _safe_str(ci_frame.get("dst_ip")),
        }
        return self.stream_states.get(self._compose_stream_key(lookup))

    def reset(self):
        self.stream_states.clear()
        self.frame_count = 0
        self.rule_frequency.clear()


if __name__ == "__main__":
    engine = FrameRuleEngine(threshold_file="packet_reader/thresholds.json")
    example_frame = {
        "pmu_id": 1,
        "stream_id": 1,
        "soc": 1700000000,
        "fracsec": 500000,
        "time_base": 1_000_000,
        "crc_ok": True,
        "src_ip": "127.0.0.1",
        "src_mac": "58:02:05:de:11:85",
        "freq1": 50.0,
        "dfreq1": 0.0,
        "va_mag": 1.0,
        "vb_mag": 1.0,
        "vc_mag": 1.0,
        "ia_mag": 0.1,
        "ib_mag": 0.1,
        "ic_mag": 0.1,
        "va_ang": 0.0,
        "vb_ang": -120.0,
        "vc_ang": 120.0,
        "packet_size": 120,
        "capture_time": time.time(),
    }
    print(engine.evaluate_frame(example_frame))
