from scapy.all import *
import json
import logging
import coloredlogs
from functools import lru_cache

from tcp_handler import TCPHandler
from http_handler import HTTPHandler


coloredlogs.install()
logger = logging.getLogger("NetScanner")
logger.setLevel(logging.DEBUG)


class NetScanner:
    TCP_SESSION_TIMEOUT = 10  # seconds

    def __init__(self):
        self.connections_graph = ConnectionsGraph()
        self.tcp_handler = TCPHandler(self.TCP_SESSION_TIMEOUT)
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


