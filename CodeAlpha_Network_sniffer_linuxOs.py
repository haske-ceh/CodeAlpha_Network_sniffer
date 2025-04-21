#Basic Network Sniffer in Python

import socket
import struct

# Create a raw socket and bind it
def create_socket():
    try:
        # AF_PACKET is used for Linux. Use AF_INET on Windows.
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        return s
    except Exception as e:
        print("Socket could not be created. Error:", e)
        return None

# Ethernet header parser
def parse_ethernet_header(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Helper: convert MAC address to readable format
def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))

# Main loop
def sniff():
    s = create_socket()
    if not s:
        return

    print("Sniffing started... Press CTRL+C to stop.")
    try:
        while True:
            raw_data, addr = s.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = parse_ethernet_header(raw_data)
            print(f'\nEthernet Frame:')
            print(f'Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}')
    except KeyboardInterrupt:
        print("\nSniffing stopped.")

# Run the sniffer
if __name__ == "__main__":
    sniff()
