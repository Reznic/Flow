from scapy.all import rdpcap
from net_scanner import NetScanner


INPUT_PCAP = 'net.pcap'


def main():
    scanner = NetScanner()
    packets = rdpcap(INPUT_PCAP)
    for pkt_num, packet in enumerate(packets):
        scanner.parse_packet(packet, pkt_num)

    scanner.connections_graph.print_table()


if __name__ == "__main__":
    main()

