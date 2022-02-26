from scapy.all import rdpcap
from net_scanner import NetScanner


INPUT_PCAP = 'net.pcap'


def main():
    scanner = NetScanner()
    packets = rdpcap(INPUT_PCAP)
    for pkt_num, packet in enumerate(packets):
        scanner.parse_packet(packet, pkt_num)

    scanner.flow_graph.print_table()
    scanner.flow_graph.plot_graph()


if __name__ == "__main__":
    main()

