"""Realtime infrastructure health monitor for PMU capture pipelines."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, Optional


DEFAULT_HEALTH_THRESHOLDS = {
    "window_seconds": 10.0,
    "silence_timeout_seconds": 2.0,
    "critical_silence_seconds": 5.0,
    "fps_drop_ratio": 0.25,
    "expected_fps": 30.0,
    "raw_packet_rate_baseline": 120.0,
    "raw_packet_rate_flood": 1000.0,
    "burst_packet_rate": 1800.0,
    "decode_failure_ratio": 0.30,
    "parser_starvation_ratio": 0.10,
    "processing_delay_warning": 0.15,
    "processing_delay_critical": 0.50,
    "parser_lag_warning": 0.25,
    "queue_backlog_warning": 100,
    "queue_backlog_critical": 500,
}


@dataclass
class StreamHealthSnapshot:
    health_state: str
    silence_duration: float
    raw_packet_rate: float
    decoded_frame_rate: float
    decode_failure_rate: float
    processing_delay: float
    parser_lag: float
    queue_backlog: int
    packet_drop_estimate: float
    overload_state: bool
    suspected_attack: Optional[str]
    confidence: float
    severity: str
    reason: str
    last_frame_time: Optional[float]
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "stream_health",
            "health_state": self.health_state,
            "last_frame_time": self.last_frame_time,
            "silence_duration": round(self.silence_duration, 3),
            "raw_packet_rate": round(self.raw_packet_rate, 3),
            "decoded_frame_rate": round(self.decoded_frame_rate, 3),
            "decode_failure_rate": round(self.decode_failure_rate, 3),
            "processing_delay": round(self.processing_delay, 3),
            "parser_lag": round(self.parser_lag, 3),
            "queue_backlog": self.queue_backlog,
            "packet_drop_estimate": round(self.packet_drop_estimate, 3),
            "overload_state": self.overload_state,
            "suspected_attack": self.suspected_attack,
            "confidence": round(self.confidence, 3),
            "severity": self.severity,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }


class StreamHealthMonitor:
    """Watch capture health independently from decoded PMU frame availability."""

    def __init__(self, thresholds: Optional[Dict[str, Any]] = None, max_events: int = 4096):
        self.thresholds = {**DEFAULT_HEALTH_THRESHOLDS, **(thresholds or {})}
        self.window_seconds = float(self.thresholds["window_seconds"])
        self.raw_packets: Deque[float] = deque(maxlen=max_events)
        self.decoded_frames: Deque[float] = deque(maxlen=max_events)
        self.decode_failures: Deque[float] = deque(maxlen=max_events)
        self.processing_delays: Deque[tuple[float, float]] = deque(maxlen=max_events)
        self.parser_lags: Deque[tuple[float, float]] = deque(maxlen=max_events)
        self.start_time = time.time()
        self.last_frame_time: Optional[float] = None
        self.last_raw_packet_time: Optional[float] = None
        self.queue_backlog = 0
        self.packet_drop_estimate = 0.0
        self._lock = threading.RLock()
        self._last_snapshot: Optional[Dict[str, Any]] = None

    def update_raw_packet(self, timestamp: Optional[float] = None, queue_backlog: Optional[int] = None) -> None:
        now = timestamp or time.time()
        with self._lock:
            self.raw_packets.append(now)
            self.last_raw_packet_time = now
            if queue_backlog is not None:
                self.queue_backlog = max(0, int(queue_backlog))
            self._trim(now)

    def update_decoded_frame(
        self,
        frame: Optional[Dict[str, Any]] = None,
        timestamp: Optional[float] = None,
        processing_delay: Optional[float] = None,
    ) -> None:
        now = timestamp or time.time()
        capture_time = None
        if frame:
            capture_time = _safe_float(frame.get("capture_time") or frame.get("frame_time"))
        if processing_delay is None and capture_time is not None:
            processing_delay = max(0.0, now - capture_time)

        with self._lock:
            self.decoded_frames.append(now)
            self.last_frame_time = now
            if processing_delay is not None:
                self.processing_delays.append((now, max(0.0, float(processing_delay))))
            self._trim(now)

    def update_decode_failure(self, timestamp: Optional[float] = None, reason: Optional[str] = None) -> None:
        del reason
        now = timestamp or time.time()
        with self._lock:
            self.decode_failures.append(now)
            self._trim(now)

    def update_processing_delay(self, delay_seconds: float, timestamp: Optional[float] = None) -> None:
        now = timestamp or time.time()
        with self._lock:
            self.processing_delays.append((now, max(0.0, float(delay_seconds))))
            self._trim(now)

    def update_parser_lag(self, lag_seconds: float, timestamp: Optional[float] = None) -> None:
        now = timestamp or time.time()
        with self._lock:
            self.parser_lags.append((now, max(0.0, float(lag_seconds))))
            self._trim(now)

    def update_queue_backlog(self, backlog: int) -> None:
        with self._lock:
            self.queue_backlog = max(0, int(backlog))

    def update_packet_drop_estimate(self, drop_estimate: float) -> None:
        with self._lock:
            self.packet_drop_estimate = max(0.0, float(drop_estimate))

    def evaluate_health(self, timestamp: Optional[float] = None) -> Dict[str, Any]:
        now = timestamp or time.time()
        with self._lock:
            self._trim(now)
            raw_rate = self._rate(self.raw_packets, now)
            decoded_rate = self._rate(self.decoded_frames, now)
            failure_rate = self._failure_ratio(now)
            processing_delay = self._avg_value(self.processing_delays, now)
            parser_lag = self._avg_value(self.parser_lags, now)
            silence_duration = max(0.0, now - (self.last_frame_time or self.start_time))
            snapshot = self._classify(
                now,
                silence_duration,
                raw_rate,
                decoded_rate,
                failure_rate,
                processing_delay,
                parser_lag,
            ).to_dict()
            self._last_snapshot = snapshot
            return snapshot

    def should_alert(self, snapshot: Dict[str, Any], previous: Optional[Dict[str, Any]] = None) -> bool:
        if snapshot["health_state"] in {"OVERLOADED", "STARVED", "DISCONNECTED"}:
            return previous is None or previous.get("health_state") != snapshot["health_state"]
        return snapshot["severity"] in {"HIGH", "CRITICAL"} and snapshot.get("suspected_attack") is not None

    def _classify(
        self,
        now: float,
        silence_duration: float,
        raw_rate: float,
        decoded_rate: float,
        failure_rate: float,
        processing_delay: float,
        parser_lag: float,
    ) -> StreamHealthSnapshot:
        t = self.thresholds
        expected_fps = max(float(t["expected_fps"]), 0.001)
        raw_baseline = max(float(t["raw_packet_rate_baseline"]), 0.001)
        decoded_ratio = decoded_rate / expected_fps
        raw_surge = raw_rate >= float(t["raw_packet_rate_flood"]) or raw_rate >= raw_baseline * 4.0
        burst_surge = raw_rate >= float(t["burst_packet_rate"])
        fps_collapse = decoded_ratio <= float(t["fps_drop_ratio"])
        failure_high = failure_rate >= float(t["decode_failure_ratio"])
        parser_starved = raw_rate > 0 and decoded_rate <= max(1.0, raw_rate * float(t["parser_starvation_ratio"]))
        lag_high = parser_lag >= float(t["parser_lag_warning"]) or processing_delay >= float(t["processing_delay_warning"])
        backlog_high = self.queue_backlog >= int(t["queue_backlog_warning"])
        overload = raw_surge or burst_surge or failure_high or lag_high or backlog_high

        state = "HEALTHY"
        attack = None
        confidence = 0.05
        severity = "LOW"
        reasons = []

        if self.last_frame_time is None:
            if raw_surge:
                state = "OVERLOADED"
                attack = "PACKET_FLOODING"
                confidence = 0.90
                severity = "CRITICAL" if burst_surge or failure_high else "HIGH"
                reasons.append("Raw packet surge is present before decoded PMU frames are available")
            elif raw_rate > 0:
                state = "STARVED"
                attack = "SUBSCRIBER_STARVATION"
                confidence = 0.72
                severity = "HIGH"
                reasons.append("Raw packets are arriving but no decoded PMU frames have been produced")
            else:
                state = "DISCONNECTED"
                attack = "DOS_OR_STREAM_DISAPPEARANCE"
                confidence = 0.65
                severity = "HIGH"
                reasons.append("No decoded PMU frames have been observed")
        elif silence_duration >= float(t["critical_silence_seconds"]):
            state = "DISCONNECTED"
            attack = "DOS_OR_SUPPRESSION"
            confidence = 0.95
            severity = "CRITICAL"
            reasons.append("Critical PMU frame silence timeout exceeded")
        elif silence_duration >= float(t["silence_timeout_seconds"]):
            state = "STARVED" if raw_rate > 0 else "DISCONNECTED"
            attack = "SUBSCRIBER_STARVATION" if raw_rate > 0 else "DOS_OR_SUPPRESSION"
            confidence = 0.82 if raw_rate > 0 else 0.88
            severity = "HIGH"
            reasons.append("PMU frame silence timeout exceeded")
        elif raw_surge and parser_starved:
            state = "OVERLOADED"
            attack = "PACKET_FLOODING"
            confidence = 0.91
            severity = "CRITICAL" if burst_surge or failure_high else "HIGH"
            reasons.append("Raw packet surge with parser starvation")
        elif overload:
            state = "OVERLOADED"
            attack = "CAPTURE_OR_PARSER_OVERLOAD"
            confidence = 0.78
            severity = "HIGH"
            reasons.append("Infrastructure overload indicators exceeded thresholds")
        elif fps_collapse and raw_rate > 0:
            state = "DEGRADED"
            attack = "FPS_COLLAPSE"
            confidence = 0.66
            severity = "MEDIUM"
            reasons.append("Decoded frame rate collapsed while capture traffic continues")
        elif decoded_ratio < 0.75 or failure_rate > 0:
            state = "DEGRADED"
            confidence = 0.45
            severity = "MEDIUM"
            reasons.append("Stream health metrics are below normal operating range")
        else:
            reasons.append("Capture and decoding rates are within expected operating range")

        if failure_high and "decode failure rate is high" not in reasons:
            reasons.append("decode failure rate is high")
            confidence = min(0.98, confidence + 0.08)
        if backlog_high:
            reasons.append("queue backlog is growing")
            confidence = min(0.98, confidence + 0.07)
        if lag_high:
            reasons.append("processing delay or parser lag is elevated")
            confidence = min(0.98, confidence + 0.06)

        return StreamHealthSnapshot(
            health_state=state,
            silence_duration=silence_duration,
            raw_packet_rate=raw_rate,
            decoded_frame_rate=decoded_rate,
            decode_failure_rate=failure_rate,
            processing_delay=processing_delay,
            parser_lag=parser_lag,
            queue_backlog=self.queue_backlog,
            packet_drop_estimate=self.packet_drop_estimate,
            overload_state=state == "OVERLOADED",
            suspected_attack=attack,
            confidence=confidence,
            severity=severity,
            reason="; ".join(reasons),
            last_frame_time=self.last_frame_time,
            timestamp=now,
        )

    def _trim(self, now: float) -> None:
        cutoff = now - self.window_seconds
        for events in (self.raw_packets, self.decoded_frames, self.decode_failures):
            while events and events[0] < cutoff:
                events.popleft()
        for values in (self.processing_delays, self.parser_lags):
            while values and values[0][0] < cutoff:
                values.popleft()

    def _rate(self, events: Deque[float], now: float) -> float:
        self._trim(now)
        if not events:
            return 0.0
        elapsed = min(self.window_seconds, max(now - events[0], 1.0))
        return len(events) / elapsed

    def _failure_ratio(self, now: float) -> float:
        self._trim(now)
        attempts = len(self.decoded_frames) + len(self.decode_failures)
        if attempts <= 0:
            return 0.0
        return len(self.decode_failures) / attempts

    def _avg_value(self, values: Deque[tuple[float, float]], now: float) -> float:
        self._trim(now)
        if not values:
            return 0.0
        return sum(value for _, value in values) / len(values)


def _safe_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None
