


import os
from collections import defaultdict
import pyshark
from pyshark.capture.capture import TSharkCrashException
import pandas as pd

# iocs modull
from iocs import (
    MALICIOUS_IPS,
    SUSPICIOUS_PORTS,
    SUSPICIOUS_PROTOCOLS,
    MAX_PACKET_SIZE,
    MAX_BYTES_PER_IP
)


class IDS:
    def __init__(self, config):
        self.config = config
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = defaultdict(int)
        self.ip_traffic = defaultdict(int)
        self.connections = set()
        self.suspicious_events = []

    def start_analysis(self, source, is_live_capture=False, timeout=None):

        try:
            if is_live_capture:
                print(f"[*] Starting live capture on interface: {source}")
                packets = pyshark.LiveCapture(interface=source)
                if timeout:
                    packets.sniff(timeout=timeout)
            else:
                if not os.path.exists(source):
                    raise FileNotFoundError(f"PCAP file not found: {source}")
                print(f"[*] Starting analysis of PCAP file: {source}")
                packets = pyshark.FileCapture(source)

            # Packet Processing
            for pcap in packets:
                self.total_packets += 1

                try:
                    frame_len = int(pcap.length)
                    self.total_bytes += frame_len
                except (AttributeError, ValueError):
                    frame_len = 0

                src_ip, dst_ip, transport_layer = "N/A", "N/A", "N/A"
                src_port, dst_port = -1, -1
                has_transport = pcap.transport_layer is not None

                for layer in pcap.layers:
                    layer_name = layer.layer_name.upper()

                    if "IP" in layer_name:
                        src_ip = str(layer.src)
                        dst_ip = str(layer.dst)

                    elif has_transport and layer_name == pcap.transport_layer:
                        transport_layer = layer_name
                        try:
                            src_port = int(layer.srcport)
                            dst_port = int(layer.dstport)
                        except (AttributeError, ValueError):
                            pass

                if src_ip == "N/A":
                    continue

                # Traffic Statistics
                self.protocol_counts[transport_layer] += 1
                self.ip_traffic[src_ip] += frame_len
                self.ip_traffic[dst_ip] += frame_len

                if transport_layer != "N/A" and src_port != -1:
                    connection_key = (
                        f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} [{transport_layer}]"
                    )
                    self.connections.add(connection_key)

                # IoC Checks
                # Malicious IPs
                if src_ip in MALICIOUS_IPS or dst_ip in MALICIOUS_IPS:
                    self.suspicious_events.append(
                        f"Malicious IP detected: {src_ip} -> {dst_ip}"
                    )

                # Suspicious Ports
                if src_port != -1 and (
                    src_port in SUSPICIOUS_PORTS or dst_port in SUSPICIOUS_PORTS
                ):
                    self.suspicious_events.append(
                        f"Suspicious port used: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                    )

                # Suspicious Protocols
                if transport_layer in SUSPICIOUS_PROTOCOLS:
                    self.suspicious_events.append(
                        f"Suspicious protocol detected: {transport_layer} ({src_ip} -> {dst_ip})"
                    )

                # Oversized Packets
                if frame_len > MAX_PACKET_SIZE:
                    self.suspicious_events.append(
                        f"Oversized packet: {src_ip} -> {dst_ip} ({frame_len} bytes)"
                    )

                # Large Packets (Generic)
                if frame_len > 1500:
                    self.suspicious_events.append(
                        f"Large packet observed: {src_ip} -> {dst_ip} ({frame_len} bytes)"
                    )

            # Data Exfiltration Detection
            for ip, total_bytes in self.ip_traffic.items():
                if total_bytes > MAX_BYTES_PER_IP:
                    self.suspicious_events.append(
                        f"Possible data exfiltration from {ip} ({total_bytes / 1024:.2f} KB)"
                    )

            # Generate Report
            self._generate_report(source)

        except FileNotFoundError as e:
            print(f"[FATAL ERROR] {e}")
        except TSharkCrashException:
            print("[ERROR] TShark has crashed. Check your TShark/Wireshark installation.")
        except Exception as e:
            print(f"[ERROR] An unexpected error occurred: {e}")

    def _generate_report(self, capture_source):

        print("\n" + "=" * 50)
        print(f"Traffic Analysis Report (Source: {capture_source})")
        print("=" * 50)
        print(f"Total Packets Analyzed: {self.total_packets}")
        print(f"Total Bytes Transferred: {self.total_bytes / 1024:.2f} KB")
        print(f"Unique Connections: {len(self.connections)}")

        protocol_df = pd.DataFrame(
            list(self.protocol_counts.items()), columns=["Protocol", "Count"]
        )

        talkers_df = pd.DataFrame(
            list(self.ip_traffic.items()), columns=["IP Address", "Total Bytes"]
        )
        talkers_df["Total KB"] = talkers_df["Total Bytes"] / 1024
        talkers_df = talkers_df.sort_values(by="Total Bytes", ascending=False)

        report_filename = (
            os.path.splitext(os.path.basename(capture_source))[0]
            + "_summary_report.csv"
        )

        try:
            with open(report_filename, "w") as f:
                f.write(f"Traffic Analysis Summary for: {capture_source}\n")
                f.write("==============================================\n")
                f.write(f"Total Packets,{self.total_packets}\n")
                f.write(f"Total Bytes Transferred,{self.total_bytes}\n")
                f.write(f"Unique Connections,{len(self.connections)}\n")
                f.write(f"Suspicious Events Detected,{len(self.suspicious_events)}\n\n")

                f.write("--- Protocol Counts ---\n")
                protocol_df.to_csv(f, index=False)

                f.write("\n--- Top Talkers (Bytes) ---\n")
                talkers_df.to_csv(f, index=False)

                f.write("\n--- Suspicious Events ---\n")
                for event in self.suspicious_events:
                    f.write(f"'{event}'\n")

            print(f"\n[SUCCESS] Detailed report saved to: {report_filename}")

        except Exception as e:
            print(f"[WARNING] Could not save report file: {e}")
