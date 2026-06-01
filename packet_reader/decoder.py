import csv
import datetime
import math
import os
import re
import struct

try:
    from .c37_decoder import (
        crc_ccitt,
        decode_config_frame,
        decode_complete_config,
        decode_data,
        decode_discrete,
        decode_rename,
        get_frame_type,
        parse_header,
    )
except ImportError:
    from c37_decoder import (
        crc_ccitt,
        decode_config_frame,
        decode_complete_config,
        decode_data,
        decode_discrete,
        decode_rename,
        get_frame_type,
        parse_header,
    )

try:
    from .config_store import (
        append_config_fragment,
        clear_config_fragment,
        get_config,
        get_config_fragment,
        has_config,
        store_config,
    )
except ImportError:
    from config_store import (
        append_config_fragment,
        clear_config_fragment,
        get_config,
        get_config_fragment,
        has_config,
        store_config,
    )

CSV_FILE = "../data/pmu_data_RAW.csv"
CSV_FIELDS = None
CSV_FALLBACK_ACTIVE = False

# ALL POSSIBLE FIELDS that might appear in data (for consistent CSV headers)
ALL_POSSIBLE_FIELDS = [
    # Timing & Frame Info
    'timestamp', 'soc', 'fracsec', 'time', 'leap', 'frame_time', 'capture_time', 'frame_number',
    
    # Identification & Configuration
    'stream_id', 'pmu_index', 'pmu_name', 'pmu_id', 'pmu_flag', 'time_base',
    'ph_format', 'ph_encoding',
    
    # Network Layer - MAC (Layer 2)
    'src_mac', 'dst_mac',
    
    # Network Layer - IP (Layer 3)
    'src_ip', 'dst_ip', 'ttl', 'ip_version', 'ip_length', 'ip_flags', 'ip_fragmented',
    
    # Network Layer - TCP (Layer 4)
    'src_port', 'dst_port', 'tcp_flags', 'tcp_seq', 'tcp_ack', 'tcp_window',
    
    # Network - Payload & Packet Info
    'packet_size', 'payload_size',
    
    # Status & Quality
    'crc_ok', 'stat_data_error', 'stat_pmu_error', 'stat_time_sync', 'stat_data_sorting',
    'timequality_ver', 'timequality_mult', 'timequality_ns',
]


def set_csv_fields(field_names):
    global CSV_FIELDS
    CSV_FIELDS = field_names


def set_csv_file(file_path):
    global CSV_FILE, CSV_FALLBACK_ACTIVE
    CSV_FILE = file_path
    CSV_FALLBACK_ACTIVE = False


def _ensure_csv_dir():
    data_dir = os.path.dirname(CSV_FILE)
    if data_dir and not os.path.exists(data_dir):
        os.makedirs(data_dir, exist_ok=True)


def _activate_fallback_csv_file(reason):
    global CSV_FILE, CSV_FALLBACK_ACTIVE
    original = CSV_FILE
    data_dir = os.path.dirname(original) or "."
    base_name = os.path.basename(original)
    stem, ext = os.path.splitext(base_name)
    if not ext:
        ext = ".csv"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    CSV_FILE = os.path.join(data_dir, f"{stem}_unlocked_{timestamp}_{os.getpid()}{ext}")
    CSV_FALLBACK_ACTIVE = True
    print(
        f"CSV file is locked or not writable: {original}. "
        f"Writing new rows to fallback file: {CSV_FILE}. Reason: {reason}",
        flush=True,
    )


def _get_all_fieldnames(rows=None):
    """Get all fieldnames: use CSV_FIELDS if set, else combine ALL_POSSIBLE_FIELDS with row keys"""
    if CSV_FIELDS is not None:
        return CSV_FIELDS
    
    # Start with predefined fields
    fieldnames = set(ALL_POSSIBLE_FIELDS)
    
    # Add any dynamic fields from actual rows (phasors, frequencies, etc.)
    if rows:
        for row in rows:
            fieldnames.update(row.keys())
    
    return sorted(fieldnames)


def _write_csv_rows(rows):
    if not rows:
        return

    fieldnames = _get_all_fieldnames(rows)
    _ensure_csv_dir()
    try:
        write_header = not os.path.exists(CSV_FILE) or os.path.getsize(CSV_FILE) == 0

        with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            if write_header:
                writer.writeheader()
            writer.writerows(rows)
    except PermissionError as exc:
        if not CSV_FALLBACK_ACTIVE:
            _activate_fallback_csv_file(exc)
            _write_csv_rows(rows)
            return
        raise


def _normalize_phasor_field_name(name, index):
    """Return a friendly phasor field prefix like Va, Vb, Vc, Ia, Ib, Ic."""
    if not name:
        return f"ph{index}"

    normalized = name.strip()
    lower = normalized.lower()

    # Determine phase letter from phsA/B/C or final letter A/B/C.
    phase = None
    match = re.search(r"phs([abc])", lower)
    if match:
        phase = match.group(1).upper()
    else:
        match = re.search(r"([abc])$", lower)
        if match:
            phase = match.group(1).upper()

    # Determine current vs voltage by keyword patterns.
    if "phv" in lower or "volt" in lower or re.search(r"(^|_)v(?:a|b|c)?(?:_|$)", lower):
        prefix = "V"
    elif re.search(r"(^|_)(a|ia|i)(_|$)", lower) and "phv" not in lower:
        prefix = "I"
    else:
        # Fallback if the name already contains Va/Ia-like labels.
        if re.search(r"\bva\b|\bvb\b|\bvc\b", lower):
            prefix = "V"
        elif re.search(r"\bia\b|\bib\b|\bic\b", lower):
            prefix = "I"
        else:
            prefix = ""

    if prefix and phase:
        return f"{prefix}{phase}"
    if prefix:
        return prefix
    if phase:
        return f"ph{phase}"
    return f"ph{index}"


def initialize_csv():
    """Initialize CSV file with proper headers before capture starts"""
    _ensure_csv_dir()
    
    # Get all possible fieldnames
    fieldnames = _get_all_fieldnames()
    
    # Create/overwrite CSV file with header row
    try:
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
    except PermissionError as exc:
        if not CSV_FALLBACK_ACTIVE:
            _activate_fallback_csv_file(exc)
            initialize_csv()
            return
        raise
    
    print(f"CSV initialized: {CSV_FILE}")
    print(f"Total columns: {len(fieldnames)}")


def _flatten_data_rows(data, network_info=None):
    rows = []
    
    # Use provided network_info or create empty dict
    if network_info is None:
        network_info = {}

    for pmu in data["pmus"]:
        row = {
            "timestamp": data["timestamp"],
            "stream_id": data["stream_id"],
            "soc": data["soc"],
            "fracsec": data["fracsec"],
            "time": data["time"],
            "leap": data["leap"],
            "crc_ok": data["crc_ok"],
            "pmu_index": pmu["index"],
            "pmu_name": pmu["name"],
            "pmu_id": pmu["id"],
            "pmu_flag": pmu["pmu_flag"],
            "time_base": data.get("time_base"),
            "ph_format": pmu["phasor_format"],
            "ph_encoding": pmu["phasor_encoding"],
            # Network fields
            "src_mac": network_info.get("src_mac"),
            "dst_mac": network_info.get("dst_mac"),
            "src_ip": network_info.get("src_ip"),
            "dst_ip": network_info.get("dst_ip"),
            "src_port": network_info.get("src_port"),
            "dst_port": network_info.get("dst_port"),
            "ttl": network_info.get("ttl"),
            "ip_version": network_info.get("ip_version"),
            "ip_length": network_info.get("ip_length"),
            "ip_flags": network_info.get("ip_flags"),
            "ip_fragmented": network_info.get("ip_fragmented"),
            "tcp_seq": network_info.get("tcp_seq"),
            "tcp_ack": network_info.get("tcp_ack"),
            "tcp_flags": network_info.get("tcp_flags"),
            "tcp_window": network_info.get("tcp_window"),
            "packet_size": network_info.get("packet_size"),
            "payload_size": network_info.get("payload_size"),
            "frame_number": network_info.get("frame_number"),
            "frame_time": network_info.get("frame_time"),
            "capture_time": network_info.get("capture_time"),
        }

        for key, value in pmu.get("stat", {}).items():
            row[f"stat_{key}"] = value

        for key, value in pmu.get("timequality", {}).items():
            row[f"timequality_{key}"] = value

        for i, ph in enumerate(pmu["phasors"], start=1):
            alias = _normalize_phasor_field_name(ph.get("name"), i)
            if alias != f"ph{i}":
                row[f"{alias}_name"] = ph.get("name")
                row[f"{alias}_mag"] = ph.get("mag")
                row[f"{alias}_ang"] = ph.get("ang")
                row[f"{alias}_real"] = ph.get("real")
                row[f"{alias}_imag"] = ph.get("imag")
            else:
                row[f"ph{i}_name"] = ph.get("name")
                row[f"ph{i}_mag"] = ph.get("mag")
                row[f"ph{i}_ang"] = ph.get("ang")
                row[f"ph{i}_real"] = ph.get("real")
                row[f"ph{i}_imag"] = ph.get("imag")

        for i, freq in enumerate(pmu["freqs"], start=1):
            row[f"freq{i}_name"] = freq.get("name")
            row[f"freq{i}"] = freq.get("value")

        for i, rocof in enumerate(pmu["dfreqs"], start=1):
            row[f"dfreq{i}_name"] = rocof.get("name")
            row[f"dfreq{i}"] = rocof.get("value")

        for i, analog in enumerate(pmu["analogs"], start=1):
            row[f"analog{i}_name"] = analog.get("name")
            row[f"analog{i}"] = analog.get("value")

        for i, digital in enumerate(pmu["digital"], start=1):
            row[f"digital{i}"] = digital.get("value")
            for b, bit in enumerate(digital.get("bits", [])):
                row[f"digital{i}_bit{b}"] = bit.get("value")
                row[f"digital{i}_bit{b}_name"] = bit.get("name")

        rows.append(row)

    return rows


def decode_frame_rows(frame, conn_key=None, network_info=None):
    sync, framesize, stream_id = parse_header(frame)
    frame_type = get_frame_type(sync)

    if frame_type in (0xA, 0xB, 0xE):
        result = decode_config_frame(frame)
        if "error" in result:
            return {"error": True, "type": "config", "reason": result["error"]}, []

        if "fragment_payload" in result:
            append_config_fragment(conn_key, stream_id, result["fragment_payload"])
            return {"saved": False, "type": "config_fragment"}, []

        if get_config_fragment(conn_key, stream_id):
            combined = get_config_fragment(conn_key, stream_id) + frame[16:-2]
            clear_config_fragment(conn_key, stream_id)
            result = decode_complete_config(combined)
            if "error" in result:
                return {"error": True, "type": "config", "reason": result["error"]}, []

        config = result.get("config")
        if not config:
            return {"error": True, "type": "config", "reason": "no_config_returned"}, []

        store_config(config, None, conn_key, stream_id)
        return {"saved": False, "type": "config"}, []

    if frame_type == 0x8:
        if not has_config(conn_key, stream_id):
            return {"saved": False, "type": "data", "reason": "missing_config"}, []

        config = get_config(conn_key, stream_id)
        data = decode_data(frame, config)
        if "error" in data:
            return {"error": True, "type": "data", "reason": data["error"]}, []

        rows = _flatten_data_rows(data, network_info)
        return {"saved": True, "type": "data", "rows": len(rows)}, rows

    if frame_type == 0x9:
        if not has_config(conn_key, stream_id):
            return {"saved": False, "type": "discrete", "reason": "missing_config"}, []

        config = get_config(conn_key, stream_id)
        discrete = decode_discrete(frame, config)
        if "error" in discrete:
            return {"error": True, "type": "discrete", "reason": discrete["error"]}, []

        return {"saved": False, "type": "discrete"}, []

    if frame_type == 0xD:
        config = get_config(conn_key, stream_id)
        if not config:
            return {"saved": False, "type": "rename", "reason": "missing_config"}, []

        renamed = decode_rename(frame, config)
        if "error" in renamed:
            return {"error": True, "type": "rename", "reason": renamed["error"]}, []

        store_config(config, None, conn_key, stream_id)
        return {"saved": False, "type": "rename"}, []

    if frame_type == 0xC:
        return {"saved": False, "type": "command"}, []

    if frame_type == 0xF:
        return {"error": True, "type": "error_frame", "reason": "error_frame"}, []

    # Try as data if config exists
    if has_config(conn_key, stream_id):
        config = get_config(conn_key, stream_id)
        data = decode_data(frame, config)
        if "error" in data:
            return {"error": True, "type": "data", "reason": data["error"]}, []
        rows = _flatten_data_rows(data)
        return {"saved": True, "type": "data", "rows": len(rows)}, rows

    return {"saved": False, "type": "ignored", "reason": f"frame_type_0x{frame_type:X}"}, []


def process_frame(frame, conn_key=None, network_info=None):
    result, rows = decode_frame_rows(frame, conn_key, network_info)
    if result.get("saved") and rows:
        _write_csv_rows(rows)
    return result


def parse_config(frame):
    return decode_config_frame(frame)


def parse_data(frame, config):
    return decode_data(frame, config)
