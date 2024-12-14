import pyshark

def calculate_websocket_jitter(pcap_file, ports):
    try:
        # Create a display filter for the specified ports
        port_filter = ' || '.join([f'tcp.port == {port}' for port in ports])
        display_filter = f'tcp && ({port_filter})'
        
        capture = pyshark.FileCapture(pcap_file, display_filter=display_filter)
        arrival_times = []
        packet_count = 0

        for packet in capture:
            packet_count += 1
            print(f"Processing packet {packet_count}...")  # Debug statement to confirm loop entry

            if hasattr(packet, 'tcp'):
                arrival_times.append(float(packet.sniff_time.timestamp()))
                print(f"Packet {packet_count} arrival time: {packet.sniff_time.timestamp()}")

        capture.close()
        jitters = [abs(arrival_times[i] - arrival_times[i - 1]) for i in range(1, len(arrival_times))]
        return jitters

    except Exception as e:
        print(f"Error processing pcap file: {e}")
        return []

# Example usage
pcap_file = 'websocket_100mb.pcapng'
ports = [51845, 44, 3000]  # Correct ports
jitter_websocket = calculate_websocket_jitter(pcap_file, ports)
print(f"WebSocket Jitter Values: {jitter_websocket}")