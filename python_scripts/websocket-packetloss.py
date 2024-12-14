import pyshark

def calculate_websocket_packet_loss(pcap_file, ports):
    try:
        # Create a display filter for the specified ports
        port_filter = ' || '.join([f'tcp.port == {port}' for port in ports])
        display_filter = f'tcp && ({port_filter})'
        
        capture = pyshark.FileCapture(pcap_file, display_filter=display_filter)
        sent_packets = 0
        retransmitted_packets = 0
        packet_count = 0

        for packet in capture:
            packet_count += 1
            print(f"Processing packet {packet_count}...")  # Debug statement to confirm loop entry

            if hasattr(packet, 'tcp'):
                flags = packet.tcp.flags
                print(f"Packet {packet_count} TCP flags: {flags}")

                if '0x0002' in flags:  # SYN flag
                    sent_packets += 1
                    print(f"SYN packet detected. Total sent packets: {sent_packets}")

                if '0x0004' in flags:  # RST flag
                    retransmitted_packets += 1
                    print(f"RST packet detected. Total retransmitted packets: {retransmitted_packets}")

            else:
                print(f"Packet {packet_count} does not have a TCP layer")

            print(f"Sent packets: {sent_packets}, Retransmitted packets: {retransmitted_packets}")

        capture.close()
        loss_rate = (retransmitted_packets / sent_packets) * 100 if sent_packets > 0 else 0
        return loss_rate

    except Exception as e:
        print(f"Error processing pcap file: {e}")
        return 0

# Example usage
pcap_file = 'websocket_100mb.pcapng'
ports = [51845, 44, 3000]  # Correct ports
loss_websocket = calculate_websocket_packet_loss(pcap_file, ports)
print(f"WebSocket Packet Loss Rate: {loss_websocket:.2f}%")