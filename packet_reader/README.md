# PMU Data Decoding Pipeline

This document explains how PMU (Phasor Measurement Unit) data is decoded from C37.118.2 protocol frames in both PCAP files and live network captures.

## Overview

The decoding process has two main phases:

1. **Configuration Storage** – Extract and store PMU metadata from CONFIG frames
2. **Data Decoding** – Use stored config to decode actual measurement DATA frames

Both processes work identically whether reading from a PCAP file or live capture.

---

## Architecture

```
📦 Packet Source (PCAP / Live)
    ↓ (pyshark / scapy)
TCP Stream Buffer (per connection)
    ↓ (extract C37 frames)
Frame Parser
    ↓ (identify frame type)
    ├─→ CONFIG Frame (0xA/0xB/0xE)
    │       ↓
    │   decode_complete_config()
    │       ↓
    │   Store config in memory
    │
    ├─→ DATA Frame (0x8)
    │       ↓
    │   Retrieve config by stream_id
    │       ↓
    │   decode_data(frame, config)
    │       ↓
    │   Use config format to parse bytes
    │       ↓
    │   Flatten to CSV row
    │       ↓
    │   Write to pmu_data_RAW.csv
    │
    ├─→ DISCRETE Frame (0x9)
    │       ↓
    │   decode_discrete()
    │
    └─→ RENAME Frame (0xD)
            ↓
        decode_rename()
```

---

## Phase 1: Configuration Storage

### What is a CONFIG Frame?

A CONFIG frame contains the **metadata** describing all PMU measurements in a stream:
- How many phasors are being sent
- Whether data is transmitted as float or integer
- Whether phasors are in polar (mag+angle) or rectangular (real+imag) format
- Names of channels (e.g., "PhV_phsA", "PhV_phsB")
- Scales and offsets for values
- Time base (how many fractional seconds per second)

### How it Works

When `process_frame()` receives a CONFIG frame:

```python
# packet_reader/decoder.py - process_frame()
result = decode_config_frame(frame)

config = {
    "time_base": 1000000,           # 1 second = 1,000,000 fractional units
    "pdc_name": "JETSON_PDC",       # PDC (Phasor Data Concentrator) name
    "num_pmu": 1,                   # Number of PMUs in this stream
    "pmus": [
        {
            "index": 1,
            "name": "JETSON_PMU",
            "pmu_id": 1,
            "phnmr": 6,              # 6 phasors being sent
            "frnmr": 1,              # 1 frequency measurement
            "dfdtnmr": 1,            # 1 rate-of-change-of-frequency (ROCOF)
            "annmr": 0,              # 0 analog measurements
            "dgnmr": 0,              # 0 digital words
            
            # Format: 0x82 = 0b10000010
            #   Bit 0: 1 = polar encoding, 0 = rectangular
            #   Bit 1: 1 = float format, 0 = integer format
            #   Bit 2: analog format
            #   Bit 3: frequency format
            "phasor_format": "float",    # 32-bit IEEE float per phasor
            "phasor_encoding": "polar",  # Magnitude + Angle (not real + imaginary)
            
            # Names of each phasor channel
            "ph_names": ["PhV_phsA", "PhV_phsB", "PhV_phsC", 
                        "A_phsA", "A_phsB", "A_phsC"],
            
            # Names of frequency measurements
            "fr_names": ["Hz"],
            
            # Names of ROCOF measurements
            "rocof_names": ["HzRte"],
            
            # Scaling factors (for integer data)
            "phscales": [
                {
                    "scale": 0.001,
                    "angle_off": 0.0,
                    "vclass": 400.0,
                    "mod_flags": 0
                },
                # ... one per phasor
            ]
        }
    ]
}

# Store it
configs['192.168.137.1:50930>192.168.137.137:8055:1'] = config
```

**Key Point**: The config is now available for any DATA frames with the same stream ID.

---

## Phase 2: Data Frame Decoding

### When a DATA Frame Arrives

The `process_frame()` function:

```python
# Step 1: Get the config for this stream
config = get_config(conn_key, stream_id)

# Step 2: Decode using that config
result = decode_data(frame, config)
```

### Step-by-Step Decoding

#### **1. Parse Frame Header** (First 14 bytes)

```python
# packet_reader/c37_decoder.py - decode_data()

sync = struct.unpack(">H", frame[0:2])[0]      # 0xAA41 (sync magic)
framesize = struct.unpack(">H", frame[2:4])[0] # Total frame length
stream_id = struct.unpack(">H", frame[4:6])[0] # Stream identifier

soc = struct.unpack(">I", frame[6:10])[0]      # Seconds of century (unix timestamp)
leap = frame[10]                                # Leap second info
fracsec = int.from_bytes(frame[11:14], "big")  # Fractional seconds (0-999999)

# Compute ISO timestamp
time_base = config.get("time_base", 1000000)
timestamp = datetime.utcfromtimestamp(soc) + timedelta(seconds=fracsec/time_base)
# Result: "2026-03-29T08:40:17.045527"
```

#### **2. Verify CRC** (Last 2 bytes)

```python
recv_crc = struct.unpack(">H", frame[-2:])[0]
calc_crc = crc_ccitt(frame[:-2])  # Calculate expected CRC
crc_ok = recv_crc == calc_crc
```

#### **3. Decode PMU Data**

For each PMU in config (usually 1), parse:

**Status & Time Quality** (4 bytes):
```python
stat = struct.unpack(">H", frame[offset:offset+2])[0]
# Parse status flags
pmu_stat = {
    "data_error": bool(stat & 0x8000),      # PMU data error flag
    "pmu_error": bool(stat & 0x4000),       # PMU internal error
    "time_sync": not bool(stat & 0x2000),   # GPS time synchronized
    "data_sorting": (stat >> 11) & 0x03,    # Real-time or post-processing
}

# Parse time quality byte
tq_byte = frame[offset + 2]
tq_ns = frame[offset + 1] + (tq_byte & 0x0F) * 256  # Nanosecond quality
tq_mult = (tq_byte & 0x70) >> 4                     # Time quality flag
tq_ver = bool(tq_byte & 0x80)                       # Version info
offset += 4
```

#### **4. Decode Phasors** (Using Config Format)

This is where the **config format** determines how to read bytes:

**Case A: Float Format (`phasor_format == "float"`)**
```python
# Each phasor is 8 bytes (two 32-bit floats)
for i in range(pmu_cfg["phnmr"]):  # phnmr=6
    rx = read_float(frame, offset)        # Read 4 bytes
    ry = read_float(frame, offset + 4)    # Read 4 bytes
    offset += 8
    
    if pmu_cfg["phasor_encoding"] == "polar":
        # rx = magnitude, ry = angle
        mag = rx
        ang = ry  # Already in radians
        real = mag * math.cos(ang)
        imag = mag * math.sin(ang)
    else:
        # rx = real, ry = imaginary
        real = rx
        imag = ry
        mag = math.sqrt(real**2 + imag**2)
        ang = math.atan2(imag, real)
    
    phasors.append({
        "name": pmu_cfg["ph_names"][i],  # "PhV_phsA", "PhV_phsB", etc.
        "mag": mag,      # e.g., 230.0
        "ang": ang,      # e.g., 2.1375732421875
        "real": real,    # e.g., 229.78528771
        "imag": imag,    # e.g., -123.490618
    })
```

**Case B: Integer Format (`phasor_format == "int"`)**
```python
# Each phasor is 4 bytes (two 16-bit signed integers)
for i in range(pmu_cfg["phnmr"]):
    if pmu_cfg["phasor_encoding"] == "polar":
        mag = struct.unpack(">H", frame[offset:offset+2])[0]        # Unsigned 16-bit
        ang_raw = struct.unpack(">h", frame[offset+2:offset+4])[0]  # Signed 16-bit
        ang = ang_raw * 1e-4  # Scale to radians
        real = mag * math.cos(ang)
        imag = mag * math.sin(ang)
    else:
        real = struct.unpack(">h", frame[offset:offset+2])[0]
        imag = struct.unpack(">h", frame[offset+2:offset+4])[0]
        mag = math.sqrt(real**2 + imag**2)
        ang = math.atan2(imag, real)
    
    # Apply scale from config
    scale = pmu_cfg["phscales"][i]["scale"]
    real = real * scale
    imag = imag * scale
    mag = mag * scale
    
    phasors.append({"name": ..., "mag": mag, "ang": ang, "real": real, "imag": imag})
    
    offset += 4
    
    # Handle "data attached" flag if present
    if pmu_cfg["pmu_flag"] & 0x1000:
        offset += 2
```

#### **5. Decode Frequencies**

```python
for i in range(pmu_cfg["frnmr"]):  # Usually 1
    # Check format bit for frequency
    if pmu_cfg["format_word"] & 0x08:  # Bit 3 = frequency format
        # Float frequency
        value = read_float(frame, offset)
        offset += 4
    else:
        # Integer frequency (scaled by 1e-3 Hz or similar)
        value = struct.unpack(">h", frame[offset:offset+2])[0]
        offset += 2
        value = value * scale  # Apply scale from config
    
    freqs.append({
        "name": pmu_cfg["fr_names"][i],  # "Hz"
        "value": value,  # e.g., 50.024871826
    })
```

#### **6. Decode ROCOF (Rate of Change of Frequency)**

```python
for i in range(pmu_cfg["dfdtnmr"]):  # Usually 0 or 1
    # Same logic as frequency
    if pmu_cfg["format_word"] & 0x08:
        value = read_float(frame, offset)
        offset += 4
    else:
        value = struct.unpack(">h", frame[offset:offset+2])[0]
        offset += 2
    
    dfreqs.append({
        "name": pmu_cfg["rocof_names"][i],  # "HzRte"
        "value": value,  # e.g., 0.06085205078125
    })
```

#### **7. Flatten to CSV Row**

The decoded data is flattened into a single row:

```csv
timestamp,stream_id,soc,fracsec,time,leap,crc_ok,pmu_index,pmu_name,...
2026-03-29T08:40:17.045527,1,1648553217,45527,2026-03-29T08:40:17,0,True,1,JETSON_PMU,...
```

Each row contains all PMU measurements for that frame + metadata.

---

## Network-Based Cyber Attack Detection

### Overview

Beyond PMU measurements, the pipeline now captures **network layer metadata** from every packet. These fields are essential for detecting cyber attacks, network anomalies, and unauthorized access to PMU systems.

### Network Field Categories

#### **1. MAC Layer (Layer 2) – Identify Spoofing & ARP Attacks**

| Field | Type | Example | Attack Detection Use |
|-------|------|---------|----------------------|
| `src_mac` | string | `aa:bb:cc:dd:ee:ff` | Detect MAC spoofing, unauthorized devices, address table poisoning |
| `dst_mac` | string | `00:11:22:33:44:55` | Verify legitimate gateway/switch addresses |

**Example Attack Scenarios**:
- Unauthorized device pretending to be the PMU server
- ARP poisoning where attacker redirects traffic to their MAC address
- Man-in-the-middle (MITM) by intercepting traffic at Layer 2

#### **2. IP Layer (Layer 3) – Identify Routing Anomalies & IP Spoofing**

| Field | Type | Example | Attack Detection Use |
|-------|------|---------|----------------------|
| `src_ip` | string | `192.168.1.100` | Detect IP spoofing, unauthorized source devices |
| `dst_ip` | string | `192.168.1.1` | Verify traffic goes to legitimate destination |
| `ttl` | integer | 64 | Detect packet origin (TTL decreases per hop); unusual TTL = spoofed packet |
| `ip_version` | integer | 4 or 6 | Detect IPv6 tunneling attacks, protocol version mismatches |
| `ip_length` | integer | 1500 | Identify oversized packets (fragmentation attacks), DoS patterns |
| `ip_flags` | string | flags like DF, MF | Detect intentional fragmentation (causes processing delays) |
| `ip_fragmented` | boolean | True/False | Detect fragmentation attacks that bypass IDS detection |

**Example Attack Scenarios**:
- Spoofed source IP from outside the network claiming to be internal PMU
- Unusual TTL indicating packets from unexpected network path
- Fragmented packets designed to evade intrusion detection
- IP address conflicts/DHCP exhaustion attempts

#### **3. TCP Layer (Layer 4) – Identify Connection Exploits & DoS**

| Field | Type | Example | Attack Detection Use |
|-------|------|---------|----------------------|
| `src_port` | integer | 49152-65535 | Detect unusual client ports, port scanning |
| `dst_port` | integer | 4712, 4720, 4730 | Verify PMU standard ports (4712, 4720, 4721, etc.) |
| `tcp_seq` | integer | 1234567890 | Detect TCP hijacking, sequence prediction attacks |
| `tcp_ack` | integer | 9876543210 | Verify legitimate TCP handshake; unusual ACK = spoofed data |
| `tcp_flags` | string | SYN, ACK, FIN, RST | Detect TCP flag anomalies, port scanning, connection reset attacks |
| `tcp_window` | integer | 32768 | Detect window size attacks, DoS amplification attempts |

**TCP Flag Interpretation**:
- **SYN**: Connection initiation (expect during normal handshake)
- **ACK**: Acknowledgment (expect in data transmission)
- **FIN**: Connection termination (legitimate close)
- **RST**: Connection reset (can indicate attack or network issue)
- **PSH**: Push data immediately (normal)
- **URG**: Urgent pointer (rarely used, can be attack)
- **SYN-ACK**: Server responding to connection (normal)

**Example Attack Scenarios**:
```
Normal: SYN → SYN-ACK → ACK → DATA (legitimate 3-way handshake)
Attack 1: SYN → SYN → SYN → ... (SYN flood DoS attack)
Attack 2: ACK → DATA (without prior SYN-ACK, connection hijacking)
Attack 3: RST repeatedly (forced disconnections, availability attack)
Attack 4: FIN-ACK without proper close (ungraceful termination)
```

#### **4. Packet Size & Payload – Identify Data Exfiltration & Malformed Packets**

| Field | Type | Example | Attack Detection Use |
|-------|------|---------|----------------------|
| `packet_size` | integer | 1500 (bytes) | Detect oversized packets, fragmentation, unusual traffic patterns |
| `payload_size` | integer | 256 (bytes) | Identify PMU measurement data size; unusual payload = malicious data |

**Example Attack Scenarios**:
- Unusually large payloads containing stolen configuration data
- Zero-sized payloads that crash PMU parsers (buffer overflow)
- Payload size inconsistent with number of PMU measurements

#### **5. Packet Timing – Identify DoS & Timing Attacks**

| Field | Type | Example | Attack Detection Use |
|-------|------|---------|----------------------|
| `frame_time` | float (unix) | 1706521217.045527 | Detect burst traffic, timing-based attacks |
| `capture_time` | float (unix) | 1706521217.046 | Measure packet processing delay (should be <1ms) |

**Example Attack Scenarios**:
- Burst of packets in short time window (DoS)
- Regular intervals suggesting automated attack bot
- Delays suggesting congested/compromised path

#### **6. Frame Information – Track Data Stream Integrity**

| Field | Type | Example | Attack Detection Use |
|-------|------|---------|----------------------|
| `frame_number` | integer | 12345 | Track packet sequence for missing/reordered frames |

**Example Attack Scenarios**:
- Missing frame numbers (attacker dropping packets)
- Out-of-order frames (TCP hijacking or MITM replay)
- Duplicate frame numbers (packet replay attacks)

---

### Attack Detection Examples

#### **Example 1: Port Scanning Detection**

```python
# Detect SYN flood or port scan
# Expected: consistent dst_port, various src_port from legitimate sources
# Attack: many different dst_port values from same src_ip in short time

import pandas as pd
df = pd.read_csv('pmu_data_RAW.csv')

# Find src_ip with many different dst_port values
port_scan = df.groupby('src_ip')['dst_port'].nunique()
suspicious = port_scan[port_scan > 5]  # Unusual if >5 different ports

print("Potential port scan sources:", suspicious.index.tolist())
```

#### **Example 2: SYN Flood DoS Detection**

```python
# Count packets with only SYN flag (no ACK)
syn_only = df[df['tcp_flags'].str.contains('SYN', na=False) & 
              ~df['tcp_flags'].str.contains('ACK', na=False)]

# If many SYN packets without ACK, it's likely a SYN flood
if len(syn_only) > 100:
    print(f"⚠️ SYN Flood detected: {len(syn_only)} SYN packets without ACK")
    print(syn_only[['src_ip', 'src_port', 'tcp_flags', 'timestamp']].head())
```

#### **Example 3: IP Spoofing Detection**

```python
# Check for impossible TTL values or paths
# PMUs on same subnet should have high TTL (255 or close)
# Unexpected low TTL = packet traveled many hops = possibly spoofed

ttl_anomalies = df[df['ttl'] < 200]  # Should be ~255 for same-network PMUs
if len(ttl_anomalies) > 0:
    print("⚠️ Potential IP spoofing (unusual TTL):")
    print(ttl_anomalies[['src_ip', 'dst_ip', 'ttl', 'timestamp']].head())
```

#### **Example 4: Fragmentation Attack Detection**

```python
# Fragmented packets might bypass IDS
fragmented = df[df['ip_fragmented'] == True]
if len(fragmented) > 0:
    print(f"⚠️ {len(fragmented)} fragmented packets detected (potential IDS evasion)")
    print(fragmented[['src_ip', 'ip_length', 'payload_size']].head())
```

#### **Example 5: Unusual Payload Size Detection**

```python
# PMU data frames should have consistent payload sizes
# Outliers indicate malformed packets or data injection

avg_payload = df['payload_size'].mean()
std_payload = df['payload_size'].std()

# Zscore > 3 = statistical outlier
zscore = (df['payload_size'] - avg_payload) / std_payload
anomalies = df[zscore.abs() > 3]

if len(anomalies) > 0:
    print(f"⚠️ {len(anomalies)} packets with unusual payload size")
    print(anomalies[['src_ip', 'payload_size', 'timestamp']].head())
```

#### **Example 6: Connection Hijacking Detection**

```python
# Monitor TCP sequence/ACK numbers for unexpected jumps
# Large jumps = possible packet injection/hijacking

# Group by connection (src_ip + src_port + dst_ip + dst_port)
for conn_key, group in df.groupby(['src_ip', 'src_port', 'dst_ip', 'dst_port']):
    seq_deltas = group['tcp_seq'].diff()
    
    # Expect predictable increments; huge jumps are suspicious
    anomalous = seq_deltas[seq_deltas > 10000]
    if len(anomalous) > 0:
        print(f"⚠️ Unusual TCP sequence jumps on connection {conn_key}")
```

---

### CSV Fields for Network Analysis

When running the capture, configure fields for cyber attack analysis:

```python
# Focus on network anomaly detection
set_csv_fields([
    # Identification
    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
    'src_mac', 'dst_mac',
    
    # TCP/IP Analysis
    'tcp_flags', 'tcp_seq', 'tcp_ack', 'tcp_window',
    'ip_version', 'ttl', 'ip_fragmented', 'ip_flags',
    
    # Payload Analysis
    'packet_size', 'payload_size', 'frame_number', 'frame_time',
    
    # PMU Status (for correlation with attacks)
    'pmu_name', 'pmu_id', 'stat_data_error', 'stat_pmu_error',
    'crc_ok', 'soc', 'fracsec'
])
```

---

## Running the Capture

See [main.py](main.py) for configuration examples and usage.

```python
# packet_reader/decoder.py - _flatten_data_rows()
row = {
    "timestamp": "2026-03-29T08:40:17.045527",
    "stream_id": 1,
    "soc": 1774773617,
    "fracsec": 45527,
    "time": 1774773617.045527,
    "leap": 80,
    "crc_ok": True,
    "pmu_index": 1,
    "pmu_name": "JETSON_PMU",
    "pmu_id": 1,
    "pmu_flag": 8192,
    "time_base": 1000000,
    "ph_format": "float",
    "ph_encoding": "polar",
    
    # Status flags
    "stat_data_error": False,
    "stat_pmu_error": False,
    "stat_time_sync": True,
    "stat_data_sorting": 0,
    
    # Time quality
    "timequality_ver": False,
    "timequality_mult": 0,
    "timequality_ns": 0,
    
    # All 6 phasors
    "ph1_name": "PhV_phsA",
    "ph1_mag": 230.0,
    "ph1_ang": 2.1375732421875,
    "ph1_real": 229.78528771474603,
    "ph1_imag": -123.49061846065464,
    
    "ph2_name": "PhV_phsB",
    "ph2_mag": 230.0,
    "ph2_ang": 0.043212890625,
    # ... etc
    
    # Frequency
    "freq1_name": "Hz",
    "freq1": 50.024871826171875,
    
    # ROCOF
    "dfreq1_name": "HzRte",
    "dfreq1": 0.06085205078125,
}

# Write to CSV
```

---

## File vs. Live Capture

Both approaches use **identical decoding logic**:

| Component | PCAP File | Live Capture |
|-----------|-----------|--------------|
| **Packet Source** | `pyshark.FileCapture(pcap_file)` | `scapy.sniff()` |
| **Packet Handler** | `handle_pyshark_packet()` | `handle_scapy_packet()` |
| **TCP Assembly** | `buffers[conn_key]` accumulates packets | Same buffer mechanism |
| **Frame Extraction** | Look for `0xAA41` sync in buffer | Same |
| **Config Decoding** | `decode_complete_config()` | Same function |
| **Data Decoding** | `decode_data(frame, config)` | Same function |
| **CSV Writing** | After all packets processed | Batch write periodically |

### File Processing
```
1. Open PCAP
2. For each packet:
   - Extract TCP payload
   - Buffer it
   - Extract C37 frames from buffer
3. Process all frames
4. Write all rows to CSV at end
```

### Live Capture Processing
```
1. Start live capture
2. For each incoming packet:
   - Extract TCP payload
   - Buffer it
   - Extract C37 frames from buffer
3. Process frames in real-time
4. Write batch of rows every N frames
5. Continue until stopped
```

---

## Critical Dependency Chain

The entire system depends on this order:

```
1. CONFIG Frame received
   ↓ (contains format, encoding, channel names, scales)
2. Store config by stream_id
   ↓
3. DATA Frame received
   ↓
4. Get config for this stream_id
   ↓ (use format to know how to read bytes)
5. Read bytes according to format
   ↓
6. Convert bytes to values (with scales if needed)
   ↓
7. Write to CSV
```

**If CONFIG is missing**: DATA frames cannot be decoded (error: "DATA frame without prior config")

**If format is wrong**: Bytes are misinterpreted
- Wrong phasor_format → reads wrong number of bytes per phasor
- Wrong phasor_encoding → treats magnitude as real part (incorrect values)
- Wrong scales → values don't match sensor readings

---

## Code Files

- **`c37_decoder.py`** – All C37.118.2 decoding logic
  - `parse_header()` – Extract frame header
  - `decode_complete_config()` – Parse CONFIG frame payload
  - `decode_data()` – Parse DATA frame payload
  - `decode_discrete()`, `decode_rename()` – Other frame types

- **`decoder.py`** – Top-level frame routing and CSV output
  - `process_frame()` – Route frame by type
  - `_flatten_data_rows()` – Convert decoded data to CSV rows
  - `_write_csv_rows()` – Write to CSV file

- **`config_store.py`** – In-memory configuration storage
  - `store_config()` – Save CONFIG by stream_id
  - `get_config()` – Retrieve CONFIG for stream_id
  - `append_config_fragment()` – Handle multi-packet CONFIG frames

- **`packet_reader.py`** – Packet capture (file or live)
  - `start_pyshark()` – Read PCAP file with pyshark
  - `start_sniff()` – Live capture with scapy
  - `handle_pyshark_packet()` – Process pyshark packets

- **`main.py`** – Entry point
  - Configure CSV output file
  - Choose file or live capture mode
  - Start capture

---

## Running

### PCAP File
```bash
python main.py
# Processes v3_fixed_sizes.pcap → pmu_data_RAW.csv
```

### Live Capture
```bash
# Modify main.py to call start_sniff() instead of start_pyshark()
python main.py
# Listens on network interface → pmu_data_RAW.csv
```

---

## Output CSV Columns

The decoded data is written to `data/pmu_data_RAW.csv` with columns including:

```
timestamp, stream_id, soc, fracsec, time, leap, crc_ok,
pmu_index, pmu_name, pmu_id, pmu_flag,
stat_data_error, stat_pmu_error, stat_time_sync, stat_data_sorting,
timequality_ver, timequality_mult, timequality_ns,
ph1_name, ph1_mag, ph1_ang, ph1_real, ph1_imag,
ph2_name, ph2_mag, ph2_ang, ph2_real, ph2_imag,
... (more phasors) ...
freq1_name, freq1,
dfreq1_name, dfreq1,
... (more frequencies/ROCOF) ...
```

Each row represents one decoded DATA frame.

---

## Troubleshooting

**"DATA frame without prior config"**
- CONFIG frame hasn't been received yet
- Check if capture includes CONFIG frame at start

**All frequency values are 0**
- Frequency encoding bit wrong (check `format_word` bit 3)
- Frequency scale not applied for integer format

**Phasor values are wrong magnitude/polarity**
- `phasor_encoding` might be swapped (polar vs. rectangular)
- Scales not being applied for integer format

**Frame type 0x0 ignored**
- Frame header corruption or buffer sync issue
- Check TCP stream has correct payloads

---

## References

- IEEE C37.118.2 Standard (Synchrophasor Protocol)
- `struct.unpack()` format strings: `">H"` = big-endian unsigned 16-bit, `">f"` = big-endian 32-bit float
- `datetime` module for timestamp conversion
