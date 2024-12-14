import pyshark

def calculate_websocket_connection_time(pcap_file, ports):
    try:
        # Create a display filter for the specified ports
        port_filter = ' || '.join([f'tcp.port == {port}' for port in ports])
        display_filter = f'tcp && ({port_filter})'
        
        capture = pyshark.FileCapture(pcap_file, display_filter=display_filter)
        start_time, end_time = None, None
        packet_count = 0

        for packet in capture:
            packet_count += 1
            print(f"Processing packet {packet_count}...")  # Debug statement to confirm loop entry

            if hasattr(packet, 'tcp'):
                flags = packet.tcp.flags
                timestamp = float(packet.sniff_timestamp)

                if '0x0002' in flags and start_time is None:  # SYN flag
                    start_time = timestamp
                    print(f"SYN packet detected. Connection start time: {start_time}")

                if '0x0010' in flags and start_time is not None:  # ACK flag
                    end_time = timestamp
                    print(f"ACK packet detected. Connection end time: {end_time}")
                    break

        capture.close()
        connection_time = end_time - start_time if start_time and end_time else None
        print(f"Connection Establishment Time: {connection_time} seconds")
        return connection_time

    except Exception as e:
        print(f"Error processing pcap file: {e}")
        return None

# Example usage
pcap_file = 'websocket_100mb.pcapng'
ports = [51845, 44, 3000]  # Correct ports
conn_time_websocket = calculate_websocket_connection_time(pcap_file, ports)
print(f"WebSocket Connection Establishment Time: {conn_time_websocket:.2f} seconds")