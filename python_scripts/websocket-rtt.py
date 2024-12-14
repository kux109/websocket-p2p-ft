import pyshark

print("Starting TCP Latency Calculator script")  # Debug statement to confirm script start

pcap_file = 'websocket_100mb.pcapng'
ports = [445, 51845, 3000]
packet_limit = 20

# Create a display filter for the specified ports
display_filter = 'tcp'
port_filter = ' || '.join([f'tcp.port == {port}' for port in ports])
display_filter += f' && ({port_filter})'

print(f"Opening pcap file: {pcap_file}")
try:
    capture = pyshark.FileCapture(pcap_file, display_filter=display_filter)
    print("Pcap file opened successfully")
except Exception as e:
    print(f"Error opening pcap file: {e}")
    capture = None

if capture is not None:
    request_timestamps = {}
    latencies = []
    packet_count = 0
    print(f"Processing {pcap_file}...")

    try:
        for packet in capture:
            packet_count += 1
            if packet_count > packet_limit:
                break
            print(f"Processing packet {packet_count}...")  # Debug statement to confirm loop entry
            if hasattr(packet, 'tcp'):
                tcp_layer = packet.tcp
                src_port = int(tcp_layer.srcport)
                dst_port = int(tcp_layer.dstport)
                flags = tcp_layer.flags
                timestamp = float(packet.sniff_timestamp)

                # Check if the packet is on one of the specified ports
                if src_port in ports or dst_port in ports:
                    print(f"TCP packet found on port {src_port} or {dst_port}")

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
    except Exception as e:
        print(f"Error processing packets: {e}")

    capture.close()
    print(f"TCP Latencies: {latencies}")
    print(f"Average Latency: {sum(latencies) / len(latencies) if latencies else 'No Latency data'} ms")
else:
    print("Failed to process pcap file")