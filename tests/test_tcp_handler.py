from scapy.all import *
from time import sleep
import pytest

from tcp_handler import TCPHandler


# Ip & Port of 3 example users
A = ("1.1.1.1", 10)
B = ("2.2.2.2", 20)
C = ("3.3.3.3", 10)


def tcp_packet(src, dst, flag, payload=None):
    """Build tcp packet with given parameters."""
    src_ip, src_port = src
    dst_ip, dst_port = dst
    packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port,
                                                        dport=dst_port,
                                                        flags=flag)
    if payload:
        packet /= payload
    return packet


def test_session_aggregation():
    """Test unification of fragmented data from multiple tcp session packets.

    * Generate packets of an example tcp session between side A and B,
      in which side A sends 3 payload strings to side B.
    * Parse the packets with TCPHandler.
    * Assert the parser returned single string,
      equal to aggregation of all payloads.
    """
    SESSIONS_NUM = 1

    packets = [tcp_packet(A, B, "S"),
               tcp_packet(B, A, "SA"),
               tcp_packet(A, B, "A"),
               tcp_packet(A, B, "P", payload="data..."),
               tcp_packet(B, A, "A"),
               tcp_packet(A, B, "P", payload="some more data..."),
               tcp_packet(B, A, "A"),
               tcp_packet(A, B, "P", payload="and more data..."),
               tcp_packet(B, A, "A"),
               tcp_packet(A, B, "FA"),
               tcp_packet(B, A, "FA"),
               tcp_packet(A, B, "A")]

    parser = TCPHandler(session_timeout=10)

    data = [parser.handle_tcp_packet(packet) for packet in packets]
    data = list(filter(lambda x: x is not None, data))
    assert len(data) == SESSIONS_NUM, \
        f"TCP parser detected {len(data)} sessions instead of {SESSIONS_NUM}."

    assert data[0] == b"data...some more data...and more data...", \
        "TCP parser did not aggregate session packet correctly."


def test_multiple_sessions():
    """Test correct separation of data sent over different tcp sessions.

    * Parse packets of 2 different tcp sessions, interchangeably
    * Assert the creation of 2 payloads, matching the payloads of 2 sessions
    """
    SESSIONS_NUM = 2
    parser = TCPHandler(session_timeout=10)
    packets = [tcp_packet(A, B, "S"),
               tcp_packet(A, C, "S"),
               tcp_packet(B, A, "SA"),
               tcp_packet(C, A, "SA"),
               tcp_packet(A, B, "A"),
               tcp_packet(A, C, "A"),
               tcp_packet(A, B, "P", payload="data from A to B"),
               tcp_packet(B, A, "A"),
               tcp_packet(A, C, "P", payload="data from A to C"),
               tcp_packet(C, A, "A"),
               tcp_packet(A, B, "FA"),
               tcp_packet(A, C, "FA"),
               tcp_packet(B, A, "FA"),
               tcp_packet(C, A, "FA"),
               tcp_packet(A, C, "A"),
               tcp_packet(A, B, "A")]

    data = [parser.handle_tcp_packet(packet) for packet in packets]
    data = list(filter(lambda x: x is not None, data))

    assert len(data) == SESSIONS_NUM, \
        f"TCP parser detected {len(data)} sessions instead of {SESSIONS_NUM}."

    assert data[0] == b"data from A to B", \
        f"TCP parser did not parse correctly payload of session"

    assert data[1] == b"data from A to C", \
        f"TCP parser did not parse correctly payload of session"


def test_resources_cleanup():
    """Test the freeing of sessions stream buffers.

    * Simulate packets of a tcp session with missing closing FIN packet.
    * Parse the packets with TCPHandler, configured with 2 seconds session timeout.
    * Check that the TCPHandler allocated session streams in memory.
    * sleep for 2.5 seconds - timeout for the unclosed session should expire.
    * Simulate and parse packets of normal tcp session, with terminating FIN packet.
    * Assert that all session streams freed from memory:
        the unclosed session, should be freed due to Timeout
        the normal session due to closing (FIN packet)
    """
    TIMEOUT = 2  # seconds

    unclosed_session = [tcp_packet(A, B, "S"),
                        tcp_packet(B, A, "SA"),
                        tcp_packet(A, B, "A"),
                        tcp_packet(A, B, "P", payload="data..."),
                        tcp_packet(B, A, "A"),
                        tcp_packet(A, B, "P", payload="some more data..."),
                        tcp_packet(B, A, "A"),
                        tcp_packet(A, B, "P", payload="and more data..."),
                        tcp_packet(B, A, "A")]

    normal_session = [tcp_packet(A, C, "S"),
                      tcp_packet(C, A, "SA"),
                      tcp_packet(A, C, "A"),
                      tcp_packet(A, C, "P", payload="data..."),
                      tcp_packet(C, A, "A"),
                      tcp_packet(A, C, "P", payload="some more data..."),
                      tcp_packet(C, A, "A"),
                      tcp_packet(A, C, "P", payload="and more data..."),
                      tcp_packet(C, A, "A"),
                      tcp_packet(A, C, "FA"),
                      tcp_packet(C, A, "FA")]

    tcp_handler = TCPHandler(session_timeout=TIMEOUT)

    for packet in unclosed_session:
        tcp_handler.handle_tcp_packet(packet)

    assert len(tcp_handler.session_streams) > 0, \
        "TCP unexpectedly did not hold session data"

    sleep(TIMEOUT + 0.5)

    for packet in normal_session:
        tcp_handler.handle_tcp_packet(packet)

    assert len(tcp_handler.session_streams) == 0, \
        "TCP handler failed to clean session data " \
        "after session timeout expiration"
