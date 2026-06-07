# packet_reader.py

from scapy.all import AsyncSniffer, PcapReader, sniff, TCP, IP, IPv6, Ether
import struct
import os
import re
import subprocess
import threading
import time
from queue import Empty, Full, Queue

try:
    from .decoder import process_frame
except ImportError:
    from decoder import process_frame

# Add Wireshark path to PATH for pyshark to find tshark
wireshark_path = r"C:\Program Files\Wireshark"
if wireshark_path not in os.environ.get('PATH', ''):
    os.environ['PATH'] = wireshark_path + os.pathsep + os.environ.get('PATH', '')

try:
    import pyshark
    import pyshark.tshark.tshark as pyshark_tshark
    import pyshark.capture.capture as pyshark_capture_capture

    def _patch_pyshark_tshark_encoding():
        if hasattr(pyshark_tshark, 'get_tshark_version'):
            def get_tshark_version(tshark_path=None):
                parameters = [pyshark_tshark.get_process_path(tshark_path), '-v']
                with open(os.devnull, 'w') as null:
                    version_output = subprocess.check_output(parameters, stderr=null).decode('utf-8', errors='replace')
                version_lines = version_output.splitlines()
                pattern = r'.*\s(\d+\.\d+\.\d+).*'
                version_string = None
                for line in version_lines:
                    m = re.match(pattern, line)
                    if m:
                        version_string = m.groups()[0]
                        break
                if not version_string:
                    raise pyshark_tshark.TSharkVersionException(
                        'Unable to parse TShark version from output: {}'.format(version_output.splitlines()[0])
                    )
                return pyshark_tshark.version.parse(version_string)
            pyshark_tshark.get_tshark_version = get_tshark_version
            if hasattr(pyshark_capture_capture, 'get_tshark_version'):
                pyshark_capture_capture.get_tshark_version = get_tshark_version

    _patch_pyshark_tshark_encoding()
except ImportError:
    pyshark = None

buffers = {}
DEFAULT_BUFFER_KEY = "<default>"
capture_stats = {
    "packets": 0,
    "payload_packets": 0,
    "frames": 0,
    "saved_frames": 0,
    "saved_rows": 0,
    "data_without_config": 0,
    "decode_errors": 0,
}

def _buffer_key(conn_key):
    return conn_key or DEFAULT_BUFFER_KEY


def _packet_endpoint(packet):
    try:
        if hasattr(packet, "ip"):
            src = packet.ip.src
            dst = packet.ip.dst
        elif hasattr(packet, "ipv6"):
            src = packet.ipv6.src
            dst = packet.ipv6.dst
        else:
            src = "?"
            dst = "?"

        if hasattr(packet, "tcp"):
            return f"{src}:{packet.tcp.srcport} -> {dst}:{packet.tcp.dstport}"
    except Exception:
        pass

    return "unknown endpoint"


def _extract_frames(key):
    frames = []
    buffer = buffers.setdefault(key, bytearray())

    while len(buffer) >= 4:
        framesize = struct.unpack(">H", buffer[2:4])[0]
        if framesize <= 0 or len(buffer) < framesize:
            break

        frame = bytes(buffer[:framesize])
        del buffer[:framesize]
        frames.append(frame)

    return frames

def get_scapy_conn_key(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
        src = ip_layer.src
        dst = ip_layer.dst
    else:
        return None

    tcp_layer = packet[TCP]
    return f"{src}:{tcp_layer.sport}>{dst}:{tcp_layer.dport}"


def get_pyshark_conn_key(packet):
    try:
        if hasattr(packet, "ip"):
            src = packet.ip.src
            dst = packet.ip.dst
        elif hasattr(packet, "ipv6"):
            src = packet.ipv6.src
            dst = packet.ipv6.dst
        else:
            return None

        sport = packet.tcp.srcport
        dport = packet.tcp.dstport
        return f"{src}:{sport}>{dst}:{dport}"
    except Exception:
        return None


def _packet_capture_epoch(packet):
    try:
        return float(packet.time)
    except Exception:
        return None


def extract_scapy_network_info(packet, frame_number=None):
    """Extract network layer information from scapy packet"""
    info = {}

    if frame_number is not None:
        info["frame_number"] = frame_number

    frame_time = _packet_capture_epoch(packet)
    if frame_time is not None:
        info["frame_time"] = frame_time
    
    # MAC addresses
    if packet.haslayer(Ether):
        ether = packet[Ether]
        info["src_mac"] = ether.src
        info["dst_mac"] = ether.dst
    
    # IP addresses and ports
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        info["src_ip"] = ip_layer.src
        info["dst_ip"] = ip_layer.dst
        info["ttl"] = ip_layer.ttl
        info["ip_version"] = ip_layer.version
        info["ip_length"] = ip_layer.len
        info["ip_flags"] = ip_layer.flags
        info["ip_fragmented"] = bool(ip_layer.flags & 0x01)  # MF flag
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
        info["src_ip"] = ip_layer.src
        info["dst_ip"] = ip_layer.dst
        info["ttl"] = ip_layer.hlim
        info["ip_version"] = ip_layer.version
        info["ip_length"] = ip_layer.plen
    
    # TCP information
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        info["src_port"] = tcp_layer.sport
        info["dst_port"] = tcp_layer.dport
        info["tcp_seq"] = tcp_layer.seq
        info["tcp_ack"] = tcp_layer.ack
        info["tcp_flags"] = tcp_layer.flags
        info["tcp_window"] = tcp_layer.window
        info["packet_size"] = len(packet)
        info["payload_size"] = len(bytes(tcp_layer.payload))
    
    info["capture_time"] = time.time()
    
    return info


def extract_pyshark_network_info(packet):
    """Extract network layer information from pyshark packet"""
    info = {}
    
    try:
        # MAC addresses
        if hasattr(packet, "eth"):
            info["src_mac"] = packet.eth.src
            info["dst_mac"] = packet.eth.dst
        
        # IP information
        if hasattr(packet, "ip"):
            info["src_ip"] = packet.ip.src
            info["dst_ip"] = packet.ip.dst
            info["ttl"] = int(packet.ip.ttl)
            info["ip_version"] = int(packet.ip.version)
            info["ip_length"] = int(packet.ip.len)
            info["ip_flags"] = packet.ip.flags
        elif hasattr(packet, "ipv6"):
            info["src_ip"] = packet.ipv6.src
            info["dst_ip"] = packet.ipv6.dst
            info["ttl"] = int(packet.ipv6.hlim)
            info["ip_version"] = int(packet.ipv6.version)
            info["ip_length"] = int(packet.ipv6.plen)
        
        # TCP information
        if hasattr(packet, "tcp"):
            info["src_port"] = int(packet.tcp.srcport)
            info["dst_port"] = int(packet.tcp.dstport)
            info["tcp_seq"] = int(packet.tcp.seq)
            info["tcp_ack"] = int(packet.tcp.ack)
            info["tcp_flags"] = packet.tcp.flags
            info["tcp_window"] = int(packet.tcp.window_size)
            info["packet_size"] = int(packet.length)
            payload = get_pyshark_tcp_payload(packet)
            info["payload_size"] = len(payload)
        
        # Frame information
        if hasattr(packet, "frame_info"):
            info["frame_number"] = int(packet.frame_info.number)
            info["frame_time"] = float(packet.frame_info.time_epoch)
            info["capture_time"] = time.time()
    except Exception as e:
        # Silently ignore extraction errors for individual fields
        pass
    
    return info


def _normalize_frame_keys(row: dict) -> dict:
    return {str(key).lower(): value for key, value in row.items()}


def _pyshark_packet_to_rows(packet, health_monitor=None):
    if not hasattr(packet, "tcp"):
        return []

    capture_stats["packets"] += 1
    if health_monitor is not None:
        health_monitor.update_raw_packet()
    conn_key = get_pyshark_conn_key(packet)
    payload = get_pyshark_tcp_payload(packet)
    if not payload:
        return []

    capture_stats["payload_packets"] += 1
    network_info = extract_pyshark_network_info(packet)
    key = _buffer_key(conn_key)
    buffers.setdefault(key, bytearray()).extend(payload)
    frames = _extract_frames(key)
    rows = []

    try:
        from .decoder import decode_frame_rows
    except ImportError:
        from decoder import decode_frame_rows

    for frame in frames:
        capture_stats["frames"] += 1
        start_time = time.perf_counter()
        result, frame_rows = decode_frame_rows(frame, conn_key, network_info)
        processing_delay = time.perf_counter() - start_time
        if health_monitor is not None:
            health_monitor.update_processing_delay(processing_delay)
        if result and result.get("saved"):
            capture_stats["saved_frames"] += 1
            capture_stats["saved_rows"] += len(frame_rows)
            rows.extend(frame_rows)
        elif result and result.get("reason") == "missing_config":
            capture_stats["data_without_config"] += 1
        elif result and result.get("error"):
            capture_stats["decode_errors"] += 1
            if health_monitor is not None:
                health_monitor.update_decode_failure(reason=result.get("reason"))

    return rows


def _packet_matches_ports(packet, ports):
    if not packet.haslayer(TCP):
        return False
    tcp_layer = packet[TCP]
    return tcp_layer.sport in ports or tcp_layer.dport in ports


def _scapy_packet_to_rows(packet, health_monitor=None):
    if not packet.haslayer(TCP):
        return []

    capture_stats["packets"] += 1
    packet_number = capture_stats["packets"]
    if health_monitor is not None:
        health_monitor.update_raw_packet()

    conn_key = get_scapy_conn_key(packet)
    payload = bytes(packet[TCP].payload)
    if not payload:
        return []

    capture_stats["payload_packets"] += 1
    network_info = extract_scapy_network_info(packet, frame_number=packet_number)

    key = _buffer_key(conn_key)
    buffers.setdefault(key, bytearray()).extend(payload)
    frames = _extract_frames(key)
    rows = []

    try:
        from .decoder import decode_frame_rows
    except ImportError:
        from decoder import decode_frame_rows

    for frame in frames:
        capture_stats["frames"] += 1
        start_time = time.perf_counter()
        result, frame_rows = decode_frame_rows(frame, conn_key, network_info)
        processing_delay = time.perf_counter() - start_time
        if health_monitor is not None:
            health_monitor.update_processing_delay(processing_delay)
        if result and result.get("saved"):
            capture_stats["saved_frames"] += 1
            capture_stats["saved_rows"] += len(frame_rows)
            rows.extend(frame_rows)
        elif result and result.get("reason") == "missing_config":
            capture_stats["data_without_config"] += 1
        elif result and result.get("error"):
            capture_stats["decode_errors"] += 1
            if health_monitor is not None:
                health_monitor.update_decode_failure(reason=result.get("reason"))

    return rows


def _capture_scapy_frames(interface=None, pcap_file=None, ports=None, health_monitor=None):
    if pcap_file:
        with PcapReader(pcap_file) as packets:
            for packet in packets:
                if not _packet_matches_ports(packet, ports):
                    continue
                try:
                    rows = _scapy_packet_to_rows(packet, health_monitor=health_monitor)
                    for row in rows:
                        yield _normalize_frame_keys(row)
                except Exception as e:
                    if health_monitor is not None:
                        health_monitor.update_decode_failure(reason=str(e))
                    print("scapy packet processing failed:", e, flush=True)
        return

    if interface is None:
        raise ValueError("interface is required for live capture")

    packet_queue = Queue(maxsize=10000)
    dropped_packets = 0
    bpf = " or ".join(f"tcp port {p}" for p in ports)

    def enqueue_packet(packet):
        nonlocal dropped_packets
        try:
            packet_queue.put_nowait(packet)
            if health_monitor is not None:
                health_monitor.update_queue_backlog(packet_queue.qsize())
        except Full:
            dropped_packets += 1
            if health_monitor is not None:
                health_monitor.update_packet_drop_estimate(dropped_packets)
                health_monitor.update_queue_backlog(packet_queue.qsize())

    sniffer = AsyncSniffer(iface=interface, filter=bpf, prn=enqueue_packet, store=False)
    sniffer.start()
    try:
        while True:
            try:
                packet = packet_queue.get(timeout=0.5)
            except Empty:
                if health_monitor is not None:
                    health_monitor.update_queue_backlog(packet_queue.qsize())
                continue

            try:
                rows = _scapy_packet_to_rows(packet, health_monitor=health_monitor)
                if health_monitor is not None:
                    health_monitor.update_queue_backlog(packet_queue.qsize())
                for row in rows:
                    yield _normalize_frame_keys(row)
            except Exception as e:
                if health_monitor is not None:
                    health_monitor.update_decode_failure(reason=str(e))
                print("scapy packet processing failed:", e, flush=True)
    finally:
        sniffer.stop()


def capture_live_frames(interface=None, pcap_file=None, ports=None, health_monitor=None, backend="pyshark"):
    """Yield decoded PMU frame rows from live Pyshark capture or PCAP file."""
    if ports is None:
        ports = [4712, 4720, 4721, 4730, 4740, 8055]

    backend = (backend or "pyshark").lower()
    if backend == "scapy":
        yield from _capture_scapy_frames(interface=interface, pcap_file=pcap_file, ports=ports, health_monitor=health_monitor)
        return
    if backend != "pyshark":
        raise ValueError(f"Unsupported capture backend: {backend}")
    if pyshark is None:
        raise ImportError("pyshark is not installed. Install it with `pip install pyshark`.")

    if pcap_file:
        capture = pyshark.FileCapture(
            pcap_file,
            display_filter="tcp and tcp.len > 0",
            tshark_path=None,
        )
    else:
        if interface is None:
            raise ValueError("interface is required for live capture")
        bpf = " or ".join(f"tcp port {p}" for p in ports)
        capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf)

    for packet in capture:
        try:
            rows = _pyshark_packet_to_rows(packet, health_monitor=health_monitor)
            for row in rows:
                yield _normalize_frame_keys(row)
        except Exception as e:
            if health_monitor is not None:
                health_monitor.update_decode_failure(reason=str(e))
            print("capture_live_frames packet processing failed:", e, flush=True)


def handle_packet(packet):
    if not packet.haslayer(TCP):
        return

    capture_stats["packets"] += 1
    packet_number = capture_stats["packets"]
    conn_key = get_scapy_conn_key(packet)
    payload = bytes(packet[TCP].payload)
    if not payload:
        return

    capture_stats["payload_packets"] += 1
    # Extract network information from packet
    network_info = extract_scapy_network_info(packet, frame_number=packet_number)

    key = _buffer_key(conn_key)
    buffers.setdefault(key, bytearray()).extend(payload)
    frames = _extract_frames(key)

    for frame in frames:
        capture_stats["frames"] += 1
        result = process_frame(frame, conn_key, network_info)
        if result and result.get("saved"):
            capture_stats["saved_frames"] += 1
            capture_stats["saved_rows"] += result.get("rows", 0)
        elif result and result.get("reason") == "missing_config":
            capture_stats["data_without_config"] += 1
        elif result and result.get("error"):
            capture_stats["decode_errors"] += 1


def get_pyshark_tcp_payload(packet):
    if not hasattr(packet, "tcp"):
        return b""

    if hasattr(packet.tcp, "payload"):
        try:
            return packet.tcp.payload.binary_value
        except Exception:
            payload_text = str(packet.tcp.payload).replace(':', '')
            return bytes.fromhex(payload_text) if payload_text else b""

    return b""


def handle_pyshark_packet(packet):
    capture_stats["packets"] += 1
    conn_key = get_pyshark_conn_key(packet)
    payload = get_pyshark_tcp_payload(packet)

    if not payload:
        return

    capture_stats["payload_packets"] += 1

    # Extract network information from packet
    network_info = extract_pyshark_network_info(packet)

    key = _buffer_key(conn_key)
    buffers.setdefault(key, bytearray()).extend(payload)
    frames = _extract_frames(key)

    for frame in frames:
        capture_stats["frames"] += 1
        result = process_frame(frame, conn_key, network_info)
        if result and result.get("saved"):
            capture_stats["saved_frames"] += 1
            capture_stats["saved_rows"] += result.get("rows", 0)
        elif result and result.get("reason") == "missing_config":
            capture_stats["data_without_config"] += 1
        elif result and result.get("error"):
            capture_stats["decode_errors"] += 1


def _print_capture_totals():
    print(
        "Final totals: "
        f"packets={capture_stats['packets']} "
        f"payload_packets={capture_stats['payload_packets']} "
        f"extracted_frames={capture_stats['frames']} "
        f"decoded_frames={capture_stats['saved_frames']} "
        f"csv_rows_written={capture_stats['saved_rows']} "
        f"missing_config={capture_stats['data_without_config']} "
        f"errors={capture_stats['decode_errors']}",
        flush=True,
    )


def _start_status_reporter():
    stop_status = threading.Event()

    def print_status():
        last_time = time.perf_counter()
        last_stats = capture_stats.copy()
        while not stop_status.wait(1):
            now = time.perf_counter()
            elapsed = max(now - last_time, 0.001)

            packets_per_sec = (capture_stats["packets"] - last_stats["packets"]) / elapsed
            payload_packets_per_sec = (capture_stats["payload_packets"] - last_stats["payload_packets"]) / elapsed
            frames_per_sec = (capture_stats["frames"] - last_stats["frames"]) / elapsed
            saved_frames_per_sec = (capture_stats["saved_frames"] - last_stats["saved_frames"]) / elapsed
            rows_per_sec = (capture_stats["saved_rows"] - last_stats["saved_rows"]) / elapsed

            print(
                "[throughput] "
                f"received_packets/s={packets_per_sec:.1f} "
                f"payload_packets/s={payload_packets_per_sec:.1f} "
                f"extracted_frames/s={frames_per_sec:.1f} "
                f"decoded_frames/s={saved_frames_per_sec:.1f} "
                f"csv_rows_written/s={rows_per_sec:.1f} "
                f"totals packets={capture_stats['packets']} "
                f"frames={capture_stats['frames']} "
                f"decoded_frames={capture_stats['saved_frames']} "
                f"csv_rows_written={capture_stats['saved_rows']} "
                f"missing_config={capture_stats['data_without_config']} "
                f"errors={capture_stats['decode_errors']}",
                flush=True,
            )
            last_time = now
            last_stats = capture_stats.copy()

    threading.Thread(target=print_status, daemon=True).start()
    return stop_status


def start_sniff(interface, count=0, timeout=None):
    print("Starting scapy live capture on", interface)
    if "loopback" in str(interface).lower():
        print(
            "Loopback captures usually do not include Ethernet headers, "
            "so src_mac and dst_mac may be empty on this adapter.",
            flush=True,
        )
    stop_status = _start_status_reporter()

    try:
        sniff(iface=interface, prn=handle_packet, store=False, count=count, timeout=timeout)
    except KeyboardInterrupt:
        print("\nCapture stopped.", flush=True)
    except Exception as e:
        print("Scapy capture failed:", e, flush=True)
    finally:
        stop_status.set()
        _print_capture_totals()


def start_scapy_file(pcap_file, count=0):
    print("Reading from PCAP file with Scapy:", pcap_file)
    processed = 0
    try:
        with PcapReader(pcap_file) as packets:
            for packet in packets:
                if packet.haslayer(TCP):
                    handle_packet(packet)
                processed += 1
                if count and processed >= count:
                    break
    finally:
        _print_capture_totals()


def start_pyshark(interface=None, pcap_file=None, ports=None, packet_count=None, timeout=None):
    if pyshark is None:
        raise ImportError("pyshark is not installed. Install it with `pip install pyshark`.")

    if ports is None:
        ports = [4712, 4720, 4721, 4730, 4740, 8055]

    tshark_path = None
    default_tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.exists(default_tshark_path):
        tshark_path = default_tshark_path

    if pcap_file:
        print("Reading from PCAP file:", pcap_file)
        capture = pyshark.FileCapture(
            pcap_file,
            display_filter="tcp and tcp.len > 0",
            tshark_path=tshark_path,
        )
    else:
        if interface is None:
            raise ValueError("interface is required for live capture")
        bpf = " or ".join(f"tcp port {p}" for p in ports)
        print(f"Starting pyshark live capture on {interface} for ports: {ports}")
        print(f"Capture filter: {bpf}")
        if tshark_path:
            print(f"Using TShark: {tshark_path}")
        capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf, tshark_path=tshark_path)

    stop_status = threading.Event()

    def print_status():
        last_time = time.perf_counter()
        last_stats = capture_stats.copy()
        while not stop_status.wait(1):
            now = time.perf_counter()
            elapsed = max(now - last_time, 0.001)

            packets_per_sec = (capture_stats["packets"] - last_stats["packets"]) / elapsed
            payload_packets_per_sec = (capture_stats["payload_packets"] - last_stats["payload_packets"]) / elapsed
            frames_per_sec = (capture_stats["frames"] - last_stats["frames"]) / elapsed
            saved_frames_per_sec = (capture_stats["saved_frames"] - last_stats["saved_frames"]) / elapsed
            rows_per_sec = (capture_stats["saved_rows"] - last_stats["saved_rows"]) / elapsed

            print(
                "[throughput] "
                f"received_packets/s={packets_per_sec:.1f} "
                f"payload_packets/s={payload_packets_per_sec:.1f} "
                f"extracted_frames/s={frames_per_sec:.1f} "
                f"decoded_frames/s={saved_frames_per_sec:.1f} "
                f"csv_rows_written/s={rows_per_sec:.1f} "
                f"totals packets={capture_stats['packets']} "
                f"frames={capture_stats['frames']} "
                f"decoded_frames={capture_stats['saved_frames']} "
                f"csv_rows_written={capture_stats['saved_rows']} "
                f"missing_config={capture_stats['data_without_config']} "
                f"errors={capture_stats['decode_errors']}",
                flush=True,
            )
            last_time = now
            last_stats = capture_stats.copy()

    if not pcap_file:
        threading.Thread(target=print_status, daemon=True).start()

    try:
        if pcap_file:
            packet_iter = capture
        elif timeout is not None:
            def process_live_packet(packet):
                try:
                    handle_pyshark_packet(packet)
                except Exception as e:
                    print("Capture packet processing failed:", e, flush=True)

            capture.apply_on_packets(process_live_packet, timeout=timeout, packet_count=packet_count)
            packet_iter = []
        elif timeout is not None or packet_count is not None:
            capture.sniff(timeout=timeout, packet_count=packet_count)
            packet_iter = list(capture)
        else:
            packet_iter = capture

        for idx, packet in enumerate(packet_iter, start=1):
            try:
                handle_pyshark_packet(packet)
            except Exception as e:
                print("Capture packet processing failed:", e, flush=True)
            if pcap_file and packet_count is not None and idx >= packet_count:
                break
    except KeyboardInterrupt:
        print("\nCapture stopped.", flush=True)
    except Exception as e:
        if timeout is not None and not pcap_file and e.__class__.__name__ == "TimeoutError":
            print("Capture timeout reached.", flush=True)
        else:
            print("Capture failed:", e, flush=True)
    finally:
        stop_status.set()
        capture.close()
        print(
            "Final totals: "
            f"packets={capture_stats['packets']} "
            f"payload_packets={capture_stats['payload_packets']} "
            f"extracted_frames={capture_stats['frames']} "
            f"decoded_frames={capture_stats['saved_frames']} "
            f"csv_rows_written={capture_stats['saved_rows']} "
            f"missing_config={capture_stats['data_without_config']} "
            f"errors={capture_stats['decode_errors']}",
            flush=True,
        )
