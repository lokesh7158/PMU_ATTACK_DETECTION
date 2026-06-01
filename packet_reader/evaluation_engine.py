"""Realtime final decision layer for PMU IDS rule-engine results."""

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple


DEFAULT_EVALUATION_THRESHOLDS = {
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


@dataclass
class EvaluationStreamHistory:
    window: int
    recent_classifications: Deque[str] = field(init=False)
    recent_frame_scores: Deque[float] = field(init=False)
    recent_anomalies: Deque[int] = field(init=False)
    repeated_attack_indicators: Deque[int] = field(init=False)
    repeated_fault_indicators: Deque[int] = field(init=False)

    def __post_init__(self) -> None:
        self.recent_classifications = deque(maxlen=self.window)
        self.recent_frame_scores = deque(maxlen=self.window)
        self.recent_anomalies = deque(maxlen=self.window)
        self.repeated_attack_indicators = deque(maxlen=self.window)
        self.repeated_fault_indicators = deque(maxlen=self.window)


class EvaluationEngine:
    """Fuse rule-engine output into a final streaming classification."""

    def __init__(
        self,
        threshold_file: Optional[str] = None,
        evaluation_thresholds: Optional[Dict[str, Any]] = None,
    ) -> None:
        configured = self._load_thresholds(threshold_file)
        if evaluation_thresholds:
            configured.update(evaluation_thresholds)
        self.config = {**DEFAULT_EVALUATION_THRESHOLDS, **configured}
        self.persistence_window = max(int(self.config["persistence_window"]), 1)
        self.persistence_trigger_count = max(int(self.config["persistence_trigger_count"]), 1)
        self.stream_histories: Dict[Tuple[str, ...], EvaluationStreamHistory] = {}
        self.classification_counts = defaultdict(int)

    @staticmethod
    def _load_thresholds(path: Optional[str]) -> Dict[str, Any]:
        candidates = [Path(path)] if path else []
        candidates.append(Path(__file__).parent / "thresholds.json")
        for candidate in candidates:
            try:
                if candidate.exists():
                    with open(candidate, "r", encoding="utf-8") as handle:
                        thresholds = json.load(handle)
                    configured = thresholds.get("evaluation_thresholds", {})
                    if isinstance(configured, dict):
                        return configured
            except (OSError, ValueError):
                continue
        return {}

    @staticmethod
    def _number(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _stream_key(self, frame: Dict[str, Any], rule_result: Dict[str, Any], stream_state: Any) -> Tuple[str, ...]:
        key = getattr(stream_state, "key", None)
        if key:
            return tuple(str(value) for value in key)
        details = rule_result.get("details", {})
        return (
            str(details.get("pmu_id", frame.get("pmu_id", "unknown"))),
            str(details.get("stream_id", frame.get("stream_id", "unknown"))),
            str(frame.get("dst_ip", details.get("dst_ip", "unknown"))),
        )

    @staticmethod
    def _rule_ids(rule_result: Dict[str, Any]) -> List[str]:
        rules = rule_result.get("rules_triggered", rule_result.get("triggered_rules", []))
        return [str(rule) for rule in rules] if isinstance(rules, list) else []

    def _indicator_summary(self, rule_result: Dict[str, Any]) -> Dict[str, Any]:
        rule_ids = self._rule_ids(rule_result)
        categories = rule_result.get("category_scores", {})
        physics_score = self._number(categories.get("physics"))
        structural_prefixes = (
            "HARD_CRC",
            "HARD_PMU_ID",
            "HARD_STREAM_ID",
            "HARD_MISSING_FIELDS",
            "HARD_TIMESTAMP_REVERSAL",
            "HARD_TIME_BASE",
            "HARD_SRC_ID",
            "HARD_PACKET_CORRUPTION",
            "HARD_PHASOR",
            "STATE_",
        )
        indicators = {
            "structural": any(rule.startswith(structural_prefixes) for rule in rule_ids),
            "replay": any(rule.startswith(("REPLAY_", "SEQ_DUPLICATE", "SEQ_REPLAY", "MITM_CORRELATED")) for rule in rule_ids),
            "timing": any(rule.startswith(("HARD_IA", "SOFT_", "RATE_", "DOS_", "SUPPRESS_", "MITM_LATENCY")) for rule in rule_ids),
            "sequence": any(rule.startswith("SEQ_") for rule in rule_ids),
            "fps": any(rule.startswith(("RATE_", "DOS_")) for rule in rule_ids),
            "mitm_symptom": any(rule.startswith("MITM_") for rule in rule_ids),
            "physics": physics_score > 0 or self._number(rule_result.get("disturbance_score")) > 0,
        }
        summary = []
        labels = {
            "structural": "structural integrity anomalies",
            "replay": "replay indicators",
            "timing": "timing instability",
            "sequence": "sequence anomalies",
            "fps": "FPS or traffic-rate anomalies",
            "mitm_symptom": "possible interception symptoms",
            "physics": "physical disturbance indicators",
        }
        for key, label in labels.items():
            if indicators[key]:
                summary.append(label)
        indicators["summary"] = summary
        indicators["rule_ids"] = rule_ids
        return indicators

    def _fusion_scores(
        self,
        rule_result: Dict[str, Any],
        indicators: Dict[str, Any],
        persistent_anomaly: bool,
        ml_output: Optional[Dict[str, Any]],
    ) -> Dict[str, float]:
        cyber = self._number(rule_result.get("cyber_score"))
        fault = self._number(rule_result.get("fault_score"))
        disturbance = self._number(rule_result.get("disturbance_score"))
        category_scores = rule_result.get("category_scores", {})
        replay_score = self._number(category_scores.get("replay"), 30.0 if indicators["replay"] else 0.0)
        timing_score = self._number(category_scores.get("timing"), 25.0 if indicators["timing"] else 0.0)

        sequence_score = 35.0 if indicators["sequence"] else 0.0
        attack_score = cyber * self._number(self.config["cyber_weight"], 1.4)
        attack_score += replay_score * (self._number(self.config["replay_weight"], 1.5) - 1.0) * 0.35
        attack_score += timing_score * (self._number(self.config["timing_weight"], 1.3) - 1.0) * 0.30
        attack_score += sequence_score * (self._number(self.config["sequence_weight"], 1.3) - 1.0)
        if indicators["mitm_symptom"]:
            attack_score += 8.0
        if persistent_anomaly and (indicators["structural"] or indicators["replay"] or indicators["timing"] or indicators["sequence"]):
            attack_score += self._number(self.config["persistence_attack_bonus"], 14.0)

        fault_score = max(
            fault * self._number(self.config["fault_weight"], 1.1),
            disturbance * self._number(self.config["disturbance_weight"], 0.9),
        )
        if persistent_anomaly and indicators["physics"]:
            fault_score += self._number(self.config["persistence_fault_bonus"], 8.0)

        if ml_output:
            attack_score += 100.0 * self._number(ml_output.get("ml_attack_probability")) * self._number(self.config["ml_attack_weight"])
            fault_score += 100.0 * self._number(ml_output.get("ml_fault_probability")) * self._number(self.config["ml_fault_weight"])
        return {"attack": min(100.0, attack_score), "fault": min(100.0, fault_score)}

    @staticmethod
    def _severity(classification: str, confidence: float, rule_severity: str, persistent: bool) -> str:
        if classification == "ATTACK":
            if rule_severity == "CRITICAL" or confidence >= 0.86:
                return "CRITICAL"
            return "HIGH"
        if classification == "FAULT":
            return "HIGH" if confidence >= 0.80 or persistent else "MEDIUM"
        if classification == "SUSPICIOUS":
            return "HIGH" if persistent and confidence >= 0.70 else "MEDIUM"
        return "NORMAL"

    def evaluate(
        self,
        frame: Dict[str, Any],
        rule_result: Dict[str, Any],
        stream_state: Any = None,
        ml_output: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        key = self._stream_key(frame, rule_result, stream_state)
        history = self.stream_histories.setdefault(key, EvaluationStreamHistory(self.persistence_window))
        indicators = self._indicator_summary(rule_result)
        frame_score = self._number(rule_result.get("frame_score"))
        cyber_score = self._number(rule_result.get("cyber_score"))
        fault_score = self._number(rule_result.get("fault_score"))
        disturbance_score = self._number(rule_result.get("disturbance_score"))
        corrupted = bool(rule_result.get("corrupted"))
        state_suspicious_count = int(getattr(stream_state, "suspicious_count", 0) or 0)

        attack_indicator = corrupted or indicators["structural"] or indicators["replay"] or indicators["timing"] or indicators["sequence"]
        fault_indicator = indicators["physics"] and not attack_indicator
        anomalous = attack_indicator or fault_indicator or frame_score >= self._number(self.config["suspicious_score_threshold"], 35.0)
        history.recent_frame_scores.append(frame_score)
        history.recent_anomalies.append(1 if anomalous else 0)
        history.repeated_attack_indicators.append(1 if attack_indicator else 0)
        history.repeated_fault_indicators.append(1 if fault_indicator else 0)
        anomaly_count = sum(history.recent_anomalies)
        attack_count = sum(history.repeated_attack_indicators)
        fault_count = sum(history.repeated_fault_indicators)
        persistent_anomaly = anomaly_count >= self.persistence_trigger_count or state_suspicious_count >= self.persistence_trigger_count

        fused = self._fusion_scores(rule_result, indicators, persistent_anomaly, ml_output)
        ml_attack_active = bool(ml_output) and self._number(ml_output.get("ml_attack_probability")) >= 0.5
        ml_fault_active = bool(ml_output) and self._number(ml_output.get("ml_fault_probability")) >= 0.5
        aggressive = bool(self.config.get("aggressive_mode", True))
        cyber_combination = sum(bool(indicators[name]) for name in ("replay", "timing", "sequence"))
        physics_only = indicators["physics"] and not attack_indicator and not corrupted
        attack_threshold = self._number(self.config["attack_score_threshold"], 55.0)
        fault_threshold = self._number(self.config["fault_score_threshold"], 50.0)
        suspicious_threshold = self._number(self.config["suspicious_score_threshold"], 35.0)

        if corrupted:
            classification = "ATTACK"
            dominant_reason = "Structural corruption of PMU frame"
        elif cyber_combination >= 2 and (aggressive or fused["attack"] >= suspicious_threshold):
            classification = "ATTACK"
            dominant_reason = "Replay, timing, or sequence anomalies occurred together"
        elif attack_indicator and fused["attack"] >= attack_threshold:
            classification = "ATTACK"
            dominant_reason = "Cyber anomaly score exceeded attack threshold"
        elif ml_attack_active and fused["attack"] >= attack_threshold:
            classification = "ATTACK"
            dominant_reason = "Configured hybrid attack evidence exceeded attack threshold"
        elif persistent_anomaly and attack_count >= self.persistence_trigger_count and attack_indicator:
            classification = "ATTACK" if aggressive else "SUSPICIOUS"
            dominant_reason = "Repeated cyber anomalies persisted across the stream window"
        elif (physics_only or ml_fault_active) and (fused["fault"] >= fault_threshold or (persistent_anomaly and fault_count >= self.persistence_trigger_count)):
            classification = "FAULT"
            dominant_reason = "Sustained physical disturbance without cyber indicators"
        elif anomalous or fused["attack"] >= suspicious_threshold or fused["fault"] >= suspicious_threshold:
            classification = "SUSPICIOUS"
            dominant_reason = "Abnormal behavior requires continued observation"
        else:
            classification = "NORMAL"
            dominant_reason = "Stable stream with no material anomaly indicators"

        relevant_score = fused["attack"] if classification in {"ATTACK", "SUSPICIOUS"} else fused["fault"]
        if classification == "NORMAL":
            confidence = max(0.55, min(0.99, 1.0 - max(fused.values()) / 100.0))
        else:
            confidence = 0.45 + relevant_score / 180.0
            if persistent_anomaly:
                confidence += 0.08
            if cyber_combination >= 2 and classification == "ATTACK":
                confidence += 0.08
            confidence = min(0.99, confidence)

        severity = self._severity(classification, confidence, str(rule_result.get("severity", "NORMAL")), persistent_anomaly)
        history.recent_classifications.append(classification)
        self.classification_counts[classification] += 1

        contributing_factors = {
            "weighted_attack_score": round(fused["attack"], 2),
            "weighted_fault_score": round(fused["fault"], 2),
            "cyber_indicator_count": cyber_combination,
            "anomalies_in_window": anomaly_count,
            "attack_indicators_in_window": attack_count,
            "fault_indicators_in_window": fault_count,
            "rule_state_suspicious_count": state_suspicious_count,
            "persistence_window": self.persistence_window,
            "aggressive_mode": aggressive,
        }
        if ml_output:
            contributing_factors["ml_output"] = dict(ml_output)

        return {
            "classification": classification,
            "confidence": round(confidence, 2),
            "severity": severity,
            "dominant_reason": dominant_reason,
            "frame_score": round(frame_score, 2),
            "cyber_score": round(cyber_score, 2),
            "fault_score": round(fault_score, 2),
            "disturbance_score": round(disturbance_score, 2),
            "persistent_anomaly": persistent_anomaly,
            "trigger_summary": indicators["summary"],
            "contributing_factors": contributing_factors,
            "triggered_rules": indicators["rule_ids"],
        }

    def reset(self) -> None:
        self.stream_histories.clear()
        self.classification_counts.clear()

    def get_stats(self) -> Dict[str, Any]:
        return {
            "streams": len(self.stream_histories),
            "classifications": dict(self.classification_counts),
        }
