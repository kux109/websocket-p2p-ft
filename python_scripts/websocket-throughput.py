import pyshark

def calculate_websocket_throughput(pcap_file, websocket_port):
    try:
        capture = pyshark.FileCapture(pcap_file, display_filter=f'tcp.port == {websocket_port}')
        total_data_bytes = 0
        start_time, end_time = None, None
        packet_count = 0

        for packet in capture:
            packet_count += 1
            print(f"Processing packet {packet_count}...")  # Debug statement to confirm loop entry

            if hasattr(packet, 'tcp'):
                if start_time is None:
                    start_time = float(packet.sniff_timestamp)
                end_time = float(packet.sniff_timestamp)
                total_data_bytes += int(packet.length)
                print(f"Packet length: {packet.length}, Total bytes: {total_data_bytes}")

        capture.close()

        if start_time and end_time and end_time > start_time:
            duration_seconds = end_time - start_time
            throughput_bps = (total_data_bytes * 8) / duration_seconds  # Convert bytes to bits
            print(f"Duration: {duration_seconds} seconds, Total bytes: {total_data_bytes}, Throughput: {throughput_bps} bps")
            return throughput_bps
        else:
            print("No valid data or duration")
            return 0

    except Exception as e:
        print(f"Error processing pcap file: {e}")
        return 0

# Example usage
pcap_file = 'websocket_100mb.pcapng'
websocket_port = 3000  # Example port
throughput = calculate_websocket_throughput(pcap_file, websocket_port)
print(f"WebSocket Throughput: {throughput} bps")