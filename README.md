# PMU Detection IDS

Realtime IEEE C37 PMU intrusion detection system with packet capture, PMU frame decoding, rule-based detection, final evaluation, and stream health monitoring.

## Project Layout

```text
PMU_detection/
  realtime_detector.py              Main realtime IDS runner
  baseline_profiler.py              Root launcher for threshold generation
  stream_health_monitor.py          Infrastructure health monitor
  data/                             PCAP files, CSV files, realtime logs
  packet_reader/
    packet_reader.py                PyShark/Scapy capture and frame extraction
    decoder.py                      IEEE C37 frame decoding
    rules.py                        FrameRuleEngine detection rules
    evaluation_engine.py            Final attack/fault classification layer
    baseline_profiler.py            Real threshold profiler implementation
    thresholds.json                 Active detection/evaluation thresholds
```

## Install Requirements

Run from the project root:

```powershell
cd C:\Users\lokes\PMU_detection
python -m pip install pandas scapy pyshark
```

For PyShark, install Wireshark/TShark.

For Scapy live capture on Windows, install Npcap and run the terminal as Administrator if needed.

## Capture Modes

The realtime detector supports two packet capture backends:

```powershell
--capture-backend pyshark
--capture-backend scapy
```

PyShark is the default, so this:

```powershell
python realtime_detector.py --interface "Ethernet" --ports 4712
```

is the same as:

```powershell
python realtime_detector.py --interface "Ethernet" --capture-backend pyshark --ports 4712
```

Use Scapy like this:

```powershell
python realtime_detector.py --interface "Ethernet" --capture-backend scapy --ports 4712
```

Only change `--capture-backend` when switching between PyShark and Scapy.

## Run Realtime Detection

Live capture with PyShark:

```powershell
python realtime_detector.py --interface "Ethernet" --capture-backend pyshark --ports 4712
```

Live capture with Scapy:

```powershell
python realtime_detector.py --interface "Ethernet" --capture-backend scapy --ports 4712
```

Read from a PCAP file:

```powershell
python realtime_detector.py --pcap data\c37_pmu1_data_publisher_subscriber.pcapng --capture-backend pyshark --ports 4712
```

For `data\v3_fixed_sizes.pcap`, use port `8055`:

```powershell
python realtime_detector.py --pcap data\v3_fixed_sizes.pcap --capture-backend scapy --ports 8055
```

The realtime detector now also supports writing merged rules + feature outputs to CSV for downstream ML input:

```powershell
python realtime_detector.py --pcap data\c37_pmu1_data_publisher_subscriber.pcapng --capture-backend pyshark --ports 4712 \
  --realtime-csv data\realtime_model_input.csv
```

Useful realtime health options:

```powershell
python realtime_detector.py --interface "Ethernet" --capture-backend scapy --ports 4712 `
  --health-interval 1 `
  --silence-timeout 2 `
  --critical-silence 5 `
  --expected-fps 30 `
  --raw-flood-rate 1000
```

## Realtime Output Logs

By default, realtime results are stored here:

```text
data\realtime_results.jsonl
```

Realtime alerts are stored here:

```text
data\realtime_alerts.log
```

Merged ML-ready feature outputs from the realtime rules engine and feature extractor are written here by default:

```text
data\realtime_model_input.csv
```

Use `--realtime-csv` to change the CSV path and `--thresholds` to point to a custom thresholds JSON.

`realtime_results.jsonl` contains structured JSON lines for:

- decoded frame rule/evaluation results
- stream health snapshots
- classifications
- confidence values
- triggered rules
- infrastructure health state

`realtime_alerts.log` contains readable alert messages for:

- attack classifications
- critical/high severity detections
- stream health alerts
- DoS/silence/starvation/flooding conditions

Custom log paths:

```powershell
python realtime_detector.py --pcap data\v3_fixed_sizes.pcap --capture-backend scapy --ports 8055 `
  --result-log data\my_results.jsonl `
  --alert-log data\my_alerts.log
```

## Generate Thresholds

Use normal/clean decoded PMU CSV data to generate thresholds:

```powershell
python baseline_profiler.py data\pmu_data.csv
```

This writes by default to:

```text
packet_reader\thresholds.json
```

You can also run the implementation module directly:

```powershell
python -m packet_reader.baseline_profiler data\pmu_data.csv
```

Or specify the output path:

```powershell
python baseline_profiler.py data\pmu_data.csv --output packet_reader\thresholds.json
```

The IDS loads thresholds from `packet_reader\thresholds.json` automatically.

## Run Individual Files

Root baseline profiler launcher:

```powershell
python baseline_profiler.py data\pmu_data.csv
```

Packet-reader baseline profiler:

```powershell
python -m packet_reader.baseline_profiler data\pmu_data.csv
```

Realtime detector:

```powershell
python realtime_detector.py --pcap data\v3_fixed_sizes.pcap --capture-backend scapy --ports 8055
```

Rules demo/self-test:

```powershell
python -m packet_reader.rules
```

Evaluation engine:

```powershell
python packet_reader\evaluation_engine.py
```

`evaluation_engine.py` is mainly a library used by `realtime_detector.py`; running it directly does not start the IDS.

Stream health monitor:

```powershell
python stream_health_monitor.py
```

`stream_health_monitor.py` is mainly a library used by `realtime_detector.py`; it exposes APIs such as `update_raw_packet()`, `update_decoded_frame()`, `update_decode_failure()`, and `evaluate_health()`.

## What the System Detects

The IDS can detect PMU/protocol-level problems such as:

- replay attacks
- timing anomalies
- sequence anomalies
- malformed/corrupted PMU data
- PMU identity anomalies
- suppression symptoms
- flooding symptoms
- abnormal frequency/phasor behavior

The stream health monitor adds infrastructure-level detection for:

- complete stream silence
- DoS or stream disappearance
- subscriber starvation
- parser overload
- decode failure spikes
- packet flooding where decoding collapses
- capture queue backlog
- degraded stream health

This is important because normal rule detection only runs when decoded PMU frames arrive. The health monitor keeps checking the stream even when frames stop arriving or decoding becomes unreliable.

## Typical Workflow

1. Generate thresholds from clean data:

```powershell
python baseline_profiler.py data\pmu_data.csv --output packet_reader\thresholds.json
```

2. Run realtime IDS with your preferred capture backend:

```powershell
python realtime_detector.py --interface "Ethernet" --capture-backend pyshark --ports 4712
```

or:

```powershell
python realtime_detector.py --interface "Ethernet" --capture-backend scapy --ports 4712
```

3. Check results:

```text
data\realtime_results.jsonl
data\realtime_alerts.log
```

