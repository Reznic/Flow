"""Utililty methods for testing."""
from scapy.all import *


def tcp_packet(src, dst, flag, payload=None):
    """Build tcp packet with given parameters.

    src: tuple. ip (str) and port (int) of source.
    dst: tuple. ip (str) and port (int) of destination.
    payload: bytearray. payload of the tcp layer.
        If None, no payload added

    returns: scapy packet with ethernet, ip, tcp, and payload (optional)
    """
    src_ip, src_port = src
    dst_ip, dst_port = dst
    packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port,
                                                        dport=dst_port,
                                                        flags=flag)
    if payload:
        packet /= payload
    return packet
