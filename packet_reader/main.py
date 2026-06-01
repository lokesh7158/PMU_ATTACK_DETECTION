"""
PMU Data Capture and Processing Script

This script captures PMU (Phasor Measurement Unit) C37.118.2 protocol data from:
1. Live network interface (using Scapy)
2. PCAP file (using Pyshark)

It extracts BOTH PMU measurements AND network metadata for cyber attack detection.

Usage:
    python main.py  # Configure data source (interface or PCAP file) below

Key Features:
    • Decodes C37.118.2 protocol frames
    • Captures ALL PMU measurements (phasors, frequency, ROCOF, analog, digital)
    • Captures ALL network metadata (MAC, IP, TCP headers) for security analysis
    • Outputs to CSV for machine learning / anomaly detection
    • Single CSV file tracks all data (append mode)
    • Supports real-time capture and offline PCAP processing
"""

import os
from packet_reader import start_sniff, start_pyshark
try:
    from .decoder import set_csv_fields, set_csv_file
except ImportError:
    from decoder import set_csv_fields, set_csv_file


if __name__ == "__main__":
    # ===============================================================================
    # CONFIGURATION
    # ===============================================================================
    
    # CSV Output File (same file for all captures - append mode)
    # All data will be written to this single file
    csv_path = r"C:\Users\lokes\PMU_detection\data\pmu_data_RAW.csv"
    set_csv_file(csv_path)
    print(f"CSV output: {os.path.abspath(csv_path)}")
    print(f"Mode: Append (all captures written to same file)")
    
    # Capture ALL Fields (PMU measurements + Network metadata + Status)
    # Set to None = capture all available fields automatically
    # This ensures you get every field for future analysis
    set_csv_fields(None)
    print(f"Capturing: ALL FIELDS (PMU + Network + Status)")
    
    # ===============================================================================
    # Available Fields in CSV
    # ===============================================================================
    # The CSV will contain these field categories (use what you need):
    #
    # TIMING:
    #   timestamp, soc, fracsec, time, leap, frame_time, capture_time, frame_number
    #
    # IDENTIFICATION:
    #   stream_id, pmu_index, pmu_name, pmu_id, pmu_flag, time_base
    #
    # NETWORK (Cyber Attack Detection):
    #   MAC: src_mac, dst_mac
    #   IP: src_ip, dst_ip, ttl, ip_version, ip_length, ip_flags, ip_fragmented
    #   TCP: src_port, dst_port, tcp_flags, tcp_seq, tcp_ack, tcp_window
    #   Payload: packet_size, payload_size
    #
    # STATUS & QUALITY:
    #   crc_ok, stat_data_error, stat_pmu_error, stat_time_sync, stat_data_sorting
    #   timequality_ver, timequality_mult, timequality_ns
    #
    # PMU MEASUREMENTS (all phasors, frequencies, etc.):
    #   ph<N>_name, ph<N>_mag, ph<N>_ang, ph<N>_real, ph<N>_imag
    #   freq<N>_name, freq<N>
    #   dfreq<N>_name, dfreq<N>
    #   analog<N>_name, analog<N>
    #   digital<N>, digital<N>_bit<M>, digital<N>_bit<M>_name
    #
    # Use these field names if you want to filter later via pandas:
    #   df[['timestamp', 'src_ip', 'dst_ip', 'ph1_mag', 'freq1', ...]]
    
    # ===============================================================================
    # SELECT DATA SOURCE
    # ===============================================================================
    
    # === Read from PCAP File (Offline Analysis) ===
    print("\nStarting PMU data capture...")
    # start_pyshark(pcap_file="../data/v3_fixed_sizes.pcap")
    
    # === Alternative: Live Network Capture ===
    # Uncomment ONE of these to use live capture instead of PCAP file:
    
    # For Scapy (Linux/Mac):
    # print("\n📡 Live capture with Scapy...")
    start_sniff(r"\Device\NPF_Loopback")  # Change to your interface
    
    # For Pyshark (Windows/Mac/Linux - requires Wireshark):
    # print("\nLive capture with Pyshark...")
    # start_pyshark(interface="Ethernet 2", ports=[4712])
    # start_pyshark(interface=r"\Device\NPF_Loopback", ports=[4712])

