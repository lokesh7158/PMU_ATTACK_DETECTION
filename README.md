# PMU Detection IDS

Realtime and offline intrusion/fault detection for IEEE C37.118 PMU streams.

The project decodes PMU traffic, extracts cyber and physical features, applies
rule-based detection, performs final attack/fault/recovery evaluation, monitors
stream health, and can produce ML-ready CSV rows.

## What This Repo Does

- Decode IEEE C37.118.2 CONFIG and DATA frames from PCAP files or live traffic.
- Preserve PMU measurements plus network metadata such as IP, TCP, packet size,
  payload size, timestamps, and CRC status.
- Run rule-based detection for replay, timing, sequence, identity, malformed
  data, suppression, flooding, abnormal phasor/frequency behavior, and physical
  fault conditions.
- Classify frames as `NORMAL`, `FAULT`, `RECOVERING`, `SUSPICIOUS`, or attack
  states through the final evaluation layer.
- Monitor infrastructure health when decoded frames slow down or stop.
- Generate compact rule summaries, full inspection CSVs, and concatenated
  feature-plus-rule CSVs for downstream ML.

## Project Layout

```text
PMU_detection/
  realtime_detector.py              Realtime IDS runner
  baseline_profiler.py              Root launcher for threshold generation
  feature_extraction.py             ML-oriented PMU feature extractor
  generate_concatenated_features.py Offline feature + rule CSV generator
  generate_rules_inspection_csv.py  Original CSV + appended rule outputs
  stream_health_monitor.py          Infrastructure health monitor
  test_rules_new_data.py            Offline CSV rule/evaluation runner
  data/                             PCAP files, CSV files, output logs
  detection/
    rules.py                        Active FrameRuleEngine detection rules
    evaluation_engine.py            Final attack/fault/recovery classifier
  feature_engineering/
    feature_concatenator.py         Combines engineered features and rule scores
  packet_reader/
    packet_reader.py                PyShark/Scapy capture and frame extraction
    decoder.py                      Frame routing and CSV output
    c37_decoder.py                  IEEE C37 frame parsing
    baseline_profiler.py            Threshold profiler implementation
    thresholds.json                 Active thresholds
    main.py                         Configurable raw capture/CSV script
```

## Requirements

Run from the project root:

```powershell
cd C:\Users\lokes\PMU_detection
python -m pip install -r packet_reader\requirements.txt
```

PyShark requires Wireshark/TShark. Scapy live capture on Windows usually
requires Npcap, and may require an Administrator terminal depending on the
interface.

## Main Data Flow

```text
PCAP or live interface
  -> packet_reader capture backend
  -> C37 frame extraction and decoding
  -> FrameRuleEngine rules
  -> EvaluationEngine final classification
  -> JSONL logs, alert logs, inspection CSVs, or ML-ready CSVs
```

For raw decoding without IDS evaluation, use `packet_reader\main.py`. For IDS
evaluation and health monitoring, use `realtime_detector.py`.

## Realtime IDS

Use PyShark, the default backend:

```powershell
python realtime_detector.py --interface "Ethernet" --ports 4712
```

Use Scapy:

```powershell
python realtime_detector.py --interface "Ethernet" --capture-backend scapy --ports 4712
```

Read from a PCAP file:

```powershell
python realtime_detector.py --pcap data\c37_pmu1_data_publisher_subscriber.pcapng --capture-backend pyshark --ports 4712
```

Useful health-monitor options:

```powershell
python realtime_detector.py --interface "Ethernet" --capture-backend scapy --ports 4712 `
  --health-interval 1 `
  --silence-timeout 2 `
  --critical-silence 5 `
  --expected-fps 30 `
  --raw-flood-rate 1000
```

Default realtime outputs:

```text
data\realtime_results.jsonl
data\realtime_alerts.log
data\realtime_model_input.csv
```

`realtime_results.jsonl` stores per-frame rule results, final classifications,
confidence, triggered rules, and health snapshots. `realtime_alerts.log` stores
human-readable high-severity, attack, corruption, and stream-health alerts.
`realtime_model_input.csv` stores concatenated engineered features and rule
scores for downstream models.

Custom output paths:

```powershell
python realtime_detector.py --pcap data\c37_pmu1_data_publisher_subscriber.pcapng --ports 4712 `
  --result-log data\my_results.jsonl `
  --alert-log data\my_alerts.log `
  --realtime-csv data\my_model_input.csv
```

## Thresholds

Generate thresholds from clean decoded PMU CSV data:

```powershell
python baseline_profiler.py data\pmu_data.csv --output packet_reader\thresholds.json
```

The detector and feature extractor load `packet_reader\thresholds.json` by
default. Use `--thresholds` on the scripts below to point at a different file.

## Offline Rule Evaluation

Run the active rules and final evaluator over a decoded CSV:

```powershell
python test_rules_new_data.py pmu_data_10min_replaced_labeled.csv
```

Default outputs:

```text
data\<input_stem>_rules_output.jsonl
data\<input_stem>_rules_summary.csv
```

Choose explicit output paths:

```powershell
python test_rules_new_data.py pmu_data_10min_replaced_labeled.csv `
  --csv-summary data\pmu_data_10min_replaced_labeled_recovery_rules_summary.csv `
  --jsonl-output data\pmu_data_10min_replaced_labeled_recovery_rules_output.jsonl
```

The summary CSV includes frame identity, scores, rule severity, final
classification, final severity, confidence, corruption status, triggered rules,
and dominant reason.

## Full Inspection CSV

Use this when you want every original input column plus appended rule/evaluation
fields:

```powershell
python generate_rules_inspection_csv.py pmu_data_10min_replaced_labeled.csv
```

Default output:

```text
data\pmu_data_10min_replaced_labeled_rules_inspection.csv
```

Custom output:

```powershell
python generate_rules_inspection_csv.py pmu_data_10min_replaced_labeled.csv `
  --output data\pmu_data_10min_replaced_labeled_recovery_rules_inspection.csv
```

Appended fields include `rules_classification`, `rules_confidence`,
`rules_triggered`, `rules_frame_score`, `rules_cyber_score`,
`rules_fault_score`, `rules_disturbance_score`, `rules_physics_score`,
`rules_weighted_attack_score`, `rules_weighted_fault_score`,
`rules_persistent_fault`, `rules_recovery_count`, and
`rules_dominant_reason`.

## ML Feature CSV

Generate a model-ready CSV containing engineered PMU features plus selected rule
scores:

```powershell
python generate_concatenated_features.py pmu_data_10min_replaced_labeled.csv `
  --output data\pmu_data_10min_concatenated_features.csv
```

The output combines columns from `PMUFeatureExtractor.OUTPUT_COLUMNS` with rule
summary fields such as `frame_score`, `normalized_score`, `fault_score`,
`cyber_score`, `disturbance_score`, `structural_score`, `timing_score`,
`replay_score`, `physics_score`, `hard_rule_count`, `soft_rule_count`, and
`frames_per_second`.

## Raw Packet Decoding

For raw C37 decoding to CSV, edit `packet_reader\main.py` to choose the CSV path
and capture source, then run:

```powershell
python packet_reader\main.py
```

The raw decoder captures PMU measurements and network metadata. See
`packet_reader\README.md` for the detailed decoder pipeline and field list.

## Current Detector Status

Current validation on `pmu_data_10min_replaced_labeled.csv`:

```text
Labels: 4399 normal, 900 fault

TP: 900
FP: 6
FN: 0
TN: 4393

Precision: 0.9934
Recall:    1.0000
F1:        0.9967
```

Final class counts from the latest recovery run:

```text
NORMAL:     4248
FAULT:       906
RECOVERING:  135
SUSPICIOUS:   10
```

`RECOVERING` frames are not counted as `FAULT` in the binary metrics. They make
post-fault clearing explainable without keeping the detector in the `FAULT`
state.

## Typical Workflow

1. Generate or refresh thresholds from clean data:

```powershell
python baseline_profiler.py data\pmu_data.csv --output packet_reader\thresholds.json
```

2. Validate rules offline:

```powershell
python test_rules_new_data.py pmu_data_10min_replaced_labeled.csv
```

3. Generate inspection or ML-ready CSVs:

```powershell
python generate_rules_inspection_csv.py pmu_data_10min_replaced_labeled.csv
python generate_concatenated_features.py pmu_data_10min_replaced_labeled.csv
```

4. Run realtime detection:

```powershell
python realtime_detector.py --interface "Ethernet" --capture-backend pyshark --ports 4712
```

5. Review outputs:

```text
data\realtime_results.jsonl
data\realtime_alerts.log
data\realtime_model_input.csv
```

## Troubleshooting

- `DATA frame without prior config`: capture must include the CONFIG frame before
  DATA frames can be decoded.
- PyShark cannot start: confirm Wireshark/TShark is installed and available on
  `PATH`.
- Scapy sees no live packets: confirm the interface name and install Npcap on
  Windows.
- Realtime health alerts but no rule alerts: the stream may be silent, flooded,
  or failing decode before frames reach the rule engine.
- Missing or unusual feature values: regenerate thresholds from representative
  clean data and confirm the input CSV has expected PMU columns such as
  `pmu_id`, `freq1`, `dfreq1`, phasor magnitudes/angles, timing, and packet
  sizes.
