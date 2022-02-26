from functools import lru_cache
import networkx as nx
from pyvis.network import Network


class FlowGraph:
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

    def _get_adjacency_dict(self):
        network = dict()
        for connection in self.connections.values():
            src = connection.src.name
            dst = connection.dst.name
            neighbours = network.get(src, [])
            neighbours.append(dst)
            network[src] = neighbours

        return network

    def plot_graph(self):
        """Create an HTML file with plotting of the flow graph."""
        net = Network(notebook=True)
        network_dict = self._get_adjacency_dict()
        net.from_nx(nx.from_dict_of_lists(network_dict))
        net.show("Flow Graph.html")


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


