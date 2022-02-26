from scapy.all import *
import json
import logging
import coloredlogs

from tcp_handler import TCPHandler
from http_handler import HTTPHandler
from flow_graph import FlowGraph


coloredlogs.install()
logger = logging.getLogger("NetScanner")
logger.setLevel(logging.DEBUG)


class NetScanner:
    TCP_SESSION_TIMEOUT = 10  # seconds

    def __init__(self):
        self.flow_graph = FlowGraph()
        self.tcp_handler = TCPHandler(self.TCP_SESSION_TIMEOUT)
        self.workers = []

    def parse_packet(self, packet, packet_num):
        """Extract json keys from http packets and build connection objects."""
        try:
            if TCP in packet:
                payload = self.tcp_handler.handle_tcp_packet(packet)

                if payload and b"HTTP" in payload:
                    connection = \
                        self.flow_graph.get_connection(packet[IP].src,
                                                              packet[IP].dst)
                    http_stream = HTTPHandler.parse_http_stream(payload, content_filter=b"json")
                    for content_type, http_content in http_stream:
                        if content_type and b"json" in content_type:
                            try:
                                json_dict = json.loads(http_content)

                            except BaseException as e:
                                # Json parsing failed.
                                logger.exception(f"Failed to parse Json in packet {packet_num}")
                                logger.warning(payload)
                                logger.error(http_content)
                                return None
                            else:
                                connection.add_keys(json_dict)

        except BaseException as e:
            logger.exception(f"Failed to parse packet {packet_num}")


