import pyshark

def calculate_websocket_retransmissions(pcap_file, ports):
    try:
        # Create a display filter for the specified ports
        port_filter = ' || '.join([f'tcp.port == {port}' for port in ports])
        display_filter = f'tcp && ({port_filter})'
        
        capture = pyshark.FileCapture(pcap_file, display_filter=display_filter)
        retransmissions = 0
        packet_count = 0

        for packet in capture:
            packet_count += 1
            print(f"Processing packet {packet_count}...")  # Debug statement to confirm loop entry

            if hasattr(packet, 'tcp'):
                flags = packet.tcp.flags
                if '0x0004' in flags:  # RST flag indicating retransmission
                    retransmissions += 1
                    print(f"Retransmission detected. Total retransmissions: {retransmissions}")

        capture.close()
        return retransmissions

    except Exception as e:
        print(f"Error processing pcap file: {e}")
        return 0

# Example usage
pcap_file = 'websocket_100mb.pcapng'
ports = [51845, 44, 3000]  # Correct ports
retrans_websocket = calculate_websocket_retransmissions(pcap_file, ports)
print(f"WebSocket Retransmissions: {retrans_websocket}")