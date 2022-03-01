from scapy.all import Ether

from net_scanner import NetScanner
from utils import tcp_packet

def test_net_scanner_parse_http_session():
    """Call NetScanner.parse_packet on single HTTP packet with json payload.

    * Build a full http packet, with json data.
    * Build a basic tcp session, including the http packet
    * Pass all session packets to NetScanner parse_packet
    * Assert NetScanner generated the correct flow-graph object,
        containing one connection, between the relevant IP addresses,
        and with the correct keys metadata, sent inside the json payload.
    """
    json_data = b'{"key1": "value1", "key2": "value2"}'
    EXPECTED_KEYS = set(["key1", "key2"])
    EXPECTED_SRC_IP = "172.18.0.13"
    EXPECTED_DST_IP = "172.18.0.10"
    A = (EXPECTED_SRC_IP, 80)
    B = (EXPECTED_DST_IP, 49494)

    http_packet = Ether(bytearray(
             b"\x02\x42\xac\x12\x00\x0a\x02\x42\xac\x12\x00\x0d\x08\x00\x45"
             b"\x00\x01\xe1\x7f\x26\x40\x00\x40\x06\x61\xb5\xac\x12\x00\x0d"
             b"\xac\x12\x00\x0a\x00\x50\xc1\x56\xc2\xca\xdb\xfb\x56\x02\x4d"
             b"\x25\x80\x18\x01\xfd\x5a\x0f\x00\x00\x01\x01\x08\x0a\xc7\xc9"
             b"\xbf\xff\x49\xa4\x73\x4cHTTP/1.1 200 OK\x0d\x0aContent-Type:"
             b" application/json; charset=utf-8\x0d\x0aDate: Sat, 04 Dec 20"
             b"21 09:38:36 GMT\x0d\x0aContent-Length: 286\x0d\x0aConnection"
             b": close\x0d\x0a\x0d\x0a" + json_data))

    session = [tcp_packet(A, B, "S"),
               tcp_packet(B, A, "SA"),
               tcp_packet(A, B, "A"),
               http_packet,
               tcp_packet(B, A, "A"),
               tcp_packet(A, B, "FA"),
               tcp_packet(B, A, "FA"),
               tcp_packet(A, B, "A")]

    net_scanner = NetScanner()
    for i, packet in enumerate(session):
        net_scanner.parse_packet(packet, i)

    connections = net_scanner.flow_graph.connections
    assert len(connections) == 1, \
        f"NetScanner detected {len(connections)} sessions instead of 1"

    session_key = (EXPECTED_SRC_IP, EXPECTED_DST_IP)
    assert session_key in connections, \
        "NetScanner did not detect session correctly"
    con = connections.get((EXPECTED_SRC_IP, EXPECTED_DST_IP))

    assert con.keys == EXPECTED_KEYS, \
        "NetScanner did not extract data keys correctly"

