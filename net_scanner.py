from scapy.all import *
import json
import logging
import coloredlogs
from functools import lru_cache

coloredlogs.install()
logger = logging.getLogger("NetScanner")
logger.setLevel(logging.DEBUG)


class NetScanner:
    def __init__(self):
        self.connections_graph = ConnectionsGraph()
        self.tcp_handler = TCPHandler()
        self.workers = []

    def parse_packet(self, packet, packet_num):
        """Extract json keys from http packets and build connection objects."""
        try:
            if TCP in packet:
                payload = self.tcp_handler.handle_tcp_packet(packet)

                if payload and b"HTTP" in payload:
                    connection = \
                        self.connections_graph.get_connection(packet[IP].src,
                                                              packet[IP].dst)
                    http_stream = HTTPHandler.parse_http_stream(payload)
                    for content_type, content_len, http_content in http_stream:
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


class HTTPHandler:
    """Parser for HTTP application layer."""
    HEADER_DELIMITER = b"\r\n\r\n"
    CONTENT_DELIMITER = b"\r\n"
    CONTENT_LEN = b'Content-Length:'
    CONTENT_TYPE = b'Content-Type:'
    ENCODING = b'Transfer-Encoding:'

    @classmethod
    def parse_http_stream(cls, packet):
        while packet and b"HTTP" in packet:
            parse = cls.parse_http_packet(packet)
            if not parse:
                break
            content_type, content, tail = parse
            yield content_type, content
            packet = tail

    @classmethod
    def parse_http_packet(cls, packet):
        """Parse http header and return payload."""
        if cls.HEADER_DELIMITER not in packet:
            logger.error("HTTP packet does not contain header delimiter")
            return None

        else:
            header, tail = packet.split(cls.HEADER_DELIMITER)
            content_len, content_type, encoding = cls._parse_header(header)

            if content_len:
                content = tail[:content_len]
                tail = tail[content_len:]

            elif b"chunked" in encoding:
                # Todo: yield from
                cls._parse_chunked_transfer_stream(tail)

            else:
                # Content length not specified in http header.
                logger.error("Packet with no content length and not chunked.")
                return None
                # header, tail = packet.split(cls.HEADER_DELIMITER, maxsplit=1)
                # sections = tail.split(cls.CONTENT_DELIMITER)
                # max_section_len, section_index = \
                #     max([(len(sec), i) for i, sec in enumerate(sections)])
                # content = sections[section_index]
                # tail = None

            return content_type, content, tail

    @classmethod
    def _parse_chunked_transfer_stream(cls, stream):
        """Parse of chunked transfer encoding stream."""
        while stream:
            # Parse chunk size
            chunk_size, _, stream = stream.partition(cls.CONTENT_DELIMITER)
            chunk_size = int(chunk_size, base=16)
            if chunk_size == 0:
                # Chunk size 0 means end of stream
                return stream
            chunk_size += 2  # chunk ends with carriage return
            content = stream[:chunk_size]
            stream = stream[chunk_size:]
            yield content

    @classmethod
    def _parse_header(cls, header):
        content_len = None
        content_type = None
        for line in header.splitlines():
            if line.startswith(cls.CONTENT_LEN):
                content_len = int(line[len(cls.CONTENT_LEN):].strip())
            elif line.startswith(cls.CONTENT_TYPE):
                content_type = line[len(cls.CONTENT_TYPE):].strip()
            elif line.startswith(cls.ENCODING):
                encoding = line[len(cls.ENCODING):].strip()
        return content_len, content_type, encoding


class TCPHandler:
    """Handle tcp packets and manage tcp sessions parsing."""
    TCP_FIN = 0x11  # Fin-Ack flag

    def __init__(self):
        self.session_streams = {}

    def handle_tcp_packet(self, packet):
        """Parse TCP packet. Aggregate payload and return tcp stream if session finished.

        Return:
            str: session data  -  If last tcp packet in stream (FIN-ACK).
            None: if tcp packet is not the last in the stream.
        """
        session_key = self._generate_session_key(packet)

        if packet[TCP].fields["flags"] == self.TCP_FIN:
            # TCP FIN received - Close finished session and return stream data
            stream = self.session_streams[session_key]
            self._close_session(session_key)
            return stream
        else:
            if session_key in self.session_streams:
                # Session already opened. aggregate payload
                payload = self._get_tcp_payload(packet)
                self.session_streams[session_key].extend(payload)
            else:
                # New session
                self._create_session(session_key, packet)

        # packet is in the middle of a session. nothing to return yet.
        return None

    def _get_tcp_payload(self, packet):
        return bytearray(bytes(packet[TCP].payload))

    def _generate_session_key(self, packet):
        return (packet[IP].src, packet[TCP].sport,
                packet[IP].dst, packet[TCP].dport)

    def _create_session(self, session_key, packet):
        self.session_streams[session_key] = self._get_tcp_payload(packet)
        # Todo: create timeout handler to clean session.

    def _close_session(self, session_key):
        """Clean session stream"""
        if session_key in self.session_streams:
            self.session_streams.pop(session_key)


class ConnectionsGraph:
    """Represent all data flows between services in the system."""
    def __init__(self):
        self.connections = {}

    def get_connection(self, src_ip, dst_ip):
        key = (src_ip, dst_ip)
        con = self.connections.get(key, Connection(*key))
        self.connections[key] = con
        return con

    def print_table(self):
        print(list(self.connections.values()))


class Connection:
    """Represent a data flow between 2 entities in the system."""
    def __init__(self, src, dst):
        self.src = Entity(src)
        self.dst = Entity(dst)
        self.keys = set()

    def add_keys(self, json):
        if json:
            if type(json) is dict:
                self.keys.update(json.keys())
            elif type(json) is list:
                for item in json:
                    self.add_keys(item)

    def __repr__(self):
        return f"{self.src} -> {self.dst}: {self.keys}\n"


class Entity:
    """Represent a service in the system."""
    SERVICES_TABLE_FILE = "services.txt"

    def __init__(self, ip):
        self.ip = ip
        self.name = self.fetch_service_name()

    def fetch_service_name(self):
        """Lookup the service name that uses this ip. if not found return the ip."""
        return self.get_ip_to_name_table().get(self.ip, self.ip)

    @classmethod
    @lru_cache(100)
    def get_ip_to_name_table(cls):
        """Load translation table of ip to service name."""
        with open(cls.SERVICES_TABLE_FILE, "rb") as ip_to_name:
            lines = ip_to_name.readlines()

        ip_to_name_table = {}
        for line in lines:
            table_line = line.decode("ascii").split(" ")
            ip = table_line[-1].strip()
            name = table_line[0].strip()
            ip_to_name_table[ip] = name

        return ip_to_name_table

    def __repr__(self):
        return self.name


