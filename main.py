"""Main module - try NetScanner on example pcap."""
from os import mkdir
from os.path import exists
from scapy.all import rdpcap

from net_scanner import NetScanner


INPUT_PCAP = 'net.pcap'
OUTPUT_GRAPH_FILE = "plots/Flow Graph.html"
OUTPUT_TABLE_FILE = "plots/table.html"


def main():
    scanner = NetScanner()
    packets = rdpcap(INPUT_PCAP)
    for pkt_num, packet in enumerate(packets):
        scanner.parse_packet(packet, pkt_num)

    if not exists("plots"):
        mkdir("plots")
    scanner.flow_graph.print_table()
    scanner.flow_graph.plot_table(OUTPUT_TABLE_FILE)
    scanner.flow_graph.plot_graph(OUTPUT_GRAPH_FILE)


if __name__ == "__main__":
    main()

