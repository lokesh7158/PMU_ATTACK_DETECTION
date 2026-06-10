import argparse
import csv
import json
import os
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Deque, Dict, Optional

import pandas as pd

from detection.evaluation_engine import EvaluationEngine
from detection.rules import FrameRuleEngine
from feature_engineering import FeatureConcatenator
from packet_reader import capture_live_frames
from stream_health_monitor import StreamHealthMonitor


def write_jsonl(path: str, data: dict):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "a", encoding="utf-8") as output:
        output.write(json.dumps(data, default=str) + "\n")


def append_line(path: str, line: str):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "a", encoding="utf-8") as output:
        output.write(line + "\n")


class RecentFrameWindow:
    def __init__(self, maxlen: int = 100):
        self._frames: Deque[pd.DataFrame] = deque(maxlen=maxlen)

    def append(self, row: dict) -> None:
        self._frames.append(pd.DataFrame([row]))

    def as_dataframe(self) -> pd.DataFrame:
        if not self._frames:
            return pd.DataFrame()
        return pd.concat(list(self._frames), ignore_index=True)


def build_alert_message(result: dict) -> str:
    return (
        f"[{datetime.utcnow().isoformat()}] "
        f"PMU={result['details'].get('pmu_id')} "
        f"stream={result['details'].get('stream_id')} "
        f"score={result['frame_score']} "
        f"classification={result.get('classification', 'UNKNOWN')} "
        f"severity={result['severity']} "
        f"corrupted={result['corrupted']} "
        f"rules={','.join(result['rules_triggered'])}"
    )


def should_alert(result: dict) -> bool:
    return result["corrupted"] or result.get("classification") == "ATTACK" or result["severity"] in {"HIGH", "CRITICAL"}


def build_health_alert_message(snapshot: dict) -> str:
    return (
        f"[{datetime.utcnow().isoformat()}] "
        f"STREAM_HEALTH state={snapshot['health_state']} "
        f"severity={snapshot['severity']} "
        f"attack={snapshot.get('suspected_attack')} "
        f"confidence={snapshot['confidence']} "
        f"silence={snapshot['silence_duration']}s "
        f"raw_rate={snapshot['raw_packet_rate']} "
        f"decoded_rate={snapshot['decoded_frame_rate']} "
        f"decode_failure_rate={snapshot['decode_failure_rate']} "
        f"reason={snapshot['reason']}"
    )


def start_health_watchdog(monitor: StreamHealthMonitor, args, stop_event: threading.Event):
    previous_snapshot = None

    def run():
        nonlocal previous_snapshot
        while not stop_event.wait(args.health_interval):
            snapshot = monitor.evaluate_health()
            write_jsonl(args.result_log, snapshot)
            if monitor.should_alert(snapshot, previous_snapshot):
                alert = build_health_alert_message(snapshot)
                print("HEALTH ALERT:", alert, flush=True)
                append_line(args.alert_log, alert)
            previous_snapshot = snapshot

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def parse_args():
    parser = argparse.ArgumentParser(description="Realtime PMU detector using packet_reader and FrameRuleEngine")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface", help="Live capture interface")
    source.add_argument("--pcap", help="Read frames from a PCAP file")
    parser.add_argument("--capture-backend", choices=["pyshark", "scapy"], default="pyshark", help="Packet capture backend")
    parser.add_argument("--ports", nargs="*", type=int, default=[4712], help="TCP ports to capture")
    parser.add_argument("--alert-log", default="data/realtime_alerts.log", help="Path to alert log file")
    parser.add_argument("--result-log", default="data/realtime_results.jsonl", help="Path to JSONL result log")
    parser.add_argument("--realtime-csv", default="data/realtime_model_input.csv", help="Path to merged realtime CSV output")
    parser.add_argument("--thresholds", default="packet_reader/thresholds.json", help="Thresholds JSON file path for feature extraction and rules")
    parser.add_argument("--known-pmu-ids", nargs="*", type=int, default=[1, 2, 3, 4], help="List of known PMU IDs")
    parser.add_argument("--known-stream-ids", nargs="*", type=lambda x: int(x, 0), default=[0x4001, 0x4002, 0x4003, 0x4004], help="List of known stream IDs (hex or decimal)")
    parser.add_argument("--health-interval", type=float, default=1.0, help="Seconds between infrastructure health checks")
    parser.add_argument("--silence-timeout", type=float, default=2.0, help="Seconds without decoded frames before DoS/starvation warning")
    parser.add_argument("--critical-silence", type=float, default=5.0, help="Seconds without decoded frames before critical DoS alert")
    parser.add_argument("--expected-fps", type=float, default=30.0, help="Expected decoded PMU frames per second")
    parser.add_argument("--raw-flood-rate", type=float, default=1000.0, help="Raw packets per second threshold for flooding")
    return parser.parse_args()


def _ensure_directory(path: str) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)


def _extract_current_features(extractor, history_df: pd.DataFrame) -> pd.Series:
    if history_df.empty:
        return pd.Series({col: 0.0 for col in extractor.OUTPUT_COLUMNS})
    output = extractor.extract_dataframe(history_df)
    if output.empty:
        return pd.Series({col: 0.0 for col in extractor.OUTPUT_COLUMNS})
    return output.iloc[-1].reindex(extractor.OUTPUT_COLUMNS).fillna(0.0)


def main():
    args = parse_args()

    engine = FrameRuleEngine(threshold_file=args.thresholds)
    engine.set_known_pmu_ids(args.known_pmu_ids, args.known_stream_ids)
    evaluator = EvaluationEngine()
    feature_extractor = None
    try:
        from feature_extraction import PMUFeatureExtractor
        feature_extractor = PMUFeatureExtractor(args.thresholds)
    except Exception as exc:
        print(f"Failed to initialize feature extractor: {exc}")
        raise

    health_monitor = StreamHealthMonitor(
        {
            "silence_timeout_seconds": args.silence_timeout,
            "critical_silence_seconds": args.critical_silence,
            "expected_fps": args.expected_fps,
            "raw_packet_rate_flood": args.raw_flood_rate,
        }
    )
    stop_health = threading.Event()
    health_thread = start_health_watchdog(health_monitor, args, stop_health)

    _ensure_directory(args.realtime_csv)
    concatenator = FeatureConcatenator(PMUFeatureExtractor.OUTPUT_COLUMNS)

    csv_file = open(args.realtime_csv, "a", newline="", encoding="utf-8")
    try:
        writer = csv.DictWriter(csv_file, fieldnames=concatenator.output_columns)
        if csv_file.tell() == 0:
            writer.writeheader()

        history_window = RecentFrameWindow(maxlen=100)

        print("Starting realtime detector")
        print(f"  alert log: {os.path.abspath(args.alert_log)}")
        print(f"  result log: {os.path.abspath(args.result_log)}")
        print(f"  realtime csv: {os.path.abspath(args.realtime_csv)}")

        if args.pcap:
            source_desc = f"PCAP file {args.pcap}"
        else:
            source_desc = f"interface {args.interface}"
        print(f"Capturing from {source_desc} ports={args.ports} backend={args.capture_backend}")

        with ThreadPoolExecutor(max_workers=2) as executor:
            for frame in capture_live_frames(
                interface=args.interface,
                pcap_file=args.pcap,
                ports=args.ports,
                health_monitor=health_monitor,
                backend=args.capture_backend,
            ):
                frame_start = time.perf_counter()
                health_monitor.update_decoded_frame(frame)
                history_window.append(frame)
                history_df = history_window.as_dataframe()

                rule_future = executor.submit(engine.evaluate_frame, frame, history_df)
                feature_future = executor.submit(_extract_current_features, feature_extractor, history_df)

                result = rule_future.result()
                feature_row = feature_future.result()

                evaluation = evaluator.evaluate(frame, result, engine.get_stream_state(frame))
                result["evaluation"] = evaluation
                result["rule_severity"] = result["severity"]
                result["classification"] = evaluation["classification"]
                result["confidence"] = evaluation["confidence"]
                result["dominant_reason"] = evaluation["dominant_reason"]
                result["severity"] = evaluation["severity"]
                health_monitor.update_parser_lag(time.perf_counter() - frame_start)
                result["stream_health"] = health_monitor.evaluate_health()

                summary = (
                    f"frame={result['frame_num']} "
                    f"pmu={result['details'].get('pmu_id')} "
                    f"score={result['frame_score']} "
                    f"classification={result['classification']} "
                    f"severity={evaluation['severity']} "
                    f"health={result['stream_health']['health_state']} "
                    f"corrupted={result['corrupted']} "
                    f"rules={len(result['rules_triggered'])}"
                )
                print(summary)

                write_jsonl(args.result_log, result)

                if should_alert(result):
                    alert = build_alert_message(result)
                    print("ALERT:", alert)
                    append_line(args.alert_log, alert)

                csv_row = concatenator.concatenate(feature_row, result)
                writer.writerow(csv_row)
                csv_file.flush()
    finally:
        final_health = health_monitor.evaluate_health()
        write_jsonl(args.result_log, final_health)
        stop_health.set()
        health_thread.join(timeout=2.0)
        csv_file.close()


if __name__ == "__main__":
    main()
