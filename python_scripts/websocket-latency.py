import pyshark

def calculate_tcp_latency(pcap_file):
    try:
        capture = pyshark.FileCapture(pcap_file)
        request_timestamps = {}
        latencies = []
        packet_count = 0

        for packet in capture:
            try:
                if 'TCP' in packet:
                    tcp_layer = packet.tcp
                    flags = tcp_layer.flags
                    timestamp = float(packet.sniff_timestamp)

                    # Check for SYN flag (request)
                    if '0x0002' in flags:  # SYN flag
                        seq_num = int(tcp_layer.seq)
                        request_timestamps[seq_num] = timestamp
                        print(f"TCP request recorded: Seq={seq_num} at {timestamp}")

                    # Check for SYN, ACK flag (response)
                    elif '0x0012' in flags:  # SYN, ACK flag
                        ack_num = int(tcp_layer.ack) - 1  # Adjust for sequence number
                        print(f"TCP response found: Ack={ack_num} at {timestamp}")
                        print(f"Request timestamps: {request_timestamps}")
                        if ack_num in request_timestamps:
                            request_time = request_timestamps.pop(ack_num)
                            latency = (timestamp - request_time) * 1000  # Convert to milliseconds
                            latencies.append(latency)
                            print(f"TCP response recorded: Ack={ack_num} at {timestamp}, Latency: {latency} ms")
                        else:
                            print(f"ACK packet number: {packet.number}, Ack: {ack_num} not found in request_timestamps")
                    else:
                        print(f"TCP packet with flags {flags} not processed")

                packet_count += 1
                print(f"Processed packet count: {packet_count}")

            except Exception as e:
                print(f"Error processing packet: {e}")

        capture.close()
        print(f"TCP Latencies: {latencies}")
        print(f"Average Latency: {sum(latencies) / len(latencies) if latencies else 'No Latency data'} ms")
    except Exception as e:
        print(f"Error processing pcap file: {e}")

# Example usage
pcap_file = 'websocket_100mb.pcapng'
calculate_tcp_latency(pcap_file)