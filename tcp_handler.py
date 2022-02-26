"""Parsing of TCP layer"""
from time import time
from scapy.all import *
from blist import sorteddict


class TCPHandler:
    """Handle tcp packets and manage tcp sessions parsing."""
    TCP_FIN = 0x1
    TCP_FINACK = 0x11

    def __init__(self, session_timeout):
        self.session_streams = {}
        self.session_timeouts = \
            Timeouts(session_timeout, expiration_handler=self._close_session)

    def handle_tcp_packet(self, packet):
        """Parse TCP packet. Aggregate payload and return tcp stream if session finished.

        Return:
            str: session data  -  If last tcp packet in stream (FIN-ACK).
            None: if tcp packet is not the last in the stream.
        """
        # Check and remove expired sessions data
        self.session_timeouts.periodic_check()

        session_key = self._generate_session_key(packet)
        tcp_flag = packet[TCP].fields["flags"]

        if tcp_flag == self.TCP_FINACK or tcp_flag == self.TCP_FIN:
            # TCP FIN received - Close finished session and return stream data
            if session_key in self.session_streams:
                stream = self.session_streams[session_key]
                self._close_session(session_key)
                self.session_timeouts.remove_timeout(session_key)
                if stream:
                    return stream
        else:
            if session_key in self.session_streams:
                # Session already opened. aggregate payload
                payload = self._get_tcp_payload(packet)
                self.session_streams[session_key].extend(payload)
            else:
                # New session
                self._create_session(session_key, packet)

            self.session_timeouts.reset_timeout(session_key)

        # packet is in the middle of a session. nothing to return yet.
        return None

    def _get_tcp_payload(self, packet):
        return bytearray(bytes(packet[TCP].payload))

    def _generate_session_key(self, packet):
        return (packet[IP].src, packet[TCP].sport,
                packet[IP].dst, packet[TCP].dport)

    def _create_session(self, session_key, packet):
        self.session_streams[session_key] = self._get_tcp_payload(packet)

    def _close_session(self, session_key):
        """Clean session stream"""
        if session_key in self.session_streams:
            del self.session_streams[session_key]


class Timeouts:
    """Manage timeouts of sessions."""
    def __init__(self, timeout, expiration_handler):
        self.timeout = timeout
        self.expiration_handler = expiration_handler
        self.timestamps = sorteddict()
        self.key_to_ts = dict()

    def reset_timeout(self, key):
        """Refresh/set the timeout countdown for the given key item."""
        current_time = time.time()

        if key in self.key_to_ts:
            old_timestamp = self.key_to_ts[key]
            self.key_to_ts[key] = current_time
            del self.timestamps[old_timestamp]
            self.timestamps[current_time] = key

        else:
            self.key_to_ts[key] = current_time
            self.timestamps[current_time] = key

    def remove_timeout(self, key):
        """Delete the timeout countdown for the given key item."""
        timestamp = self.key_to_ts[key]
        del self.key_to_ts[key]
        del self.timestamps[timestamp]

    def periodic_check(self):
        """Check which timeouts expired and call expiration handlers for them.

        This method should be called periodically, as often as possible.
        """
        num_of_timers = len(self.timestamps)
        for _ in range(num_of_timers):
            oldest_timestamp = self.timestamps.keys()[0]
            if time.time() - oldest_timestamp > self.timeout:
                expired_key = self.timestamps.pop(oldest_timestamp)
                self.expiration_handler(expired_key)
                del self.key_to_ts[expired_key]

            else:
                break
