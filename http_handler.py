"""Parsing of HTTP protocol"""

class HttpHandler:
    """Parser for HTTP application layer."""
    HEADER_DELIMITER = b"\r\n\r\n"
    CONTENT_DELIMITER = b"\r\n"
    CONTENT_LEN = b'content-length:'
    CONTENT_TYPE = b'content-type:'
    ENCODING = b'transfer-encoding:'

    @classmethod
    def parse_http_stream(cls, packet, content_filter):
        """Extract and return payload or payloads from http layer of packet.

        packet: str. http layer to be parsed
        content_filter: str. Return payload only for packets with content type
         containing this substring.
        """
        while packet and b"HTTP" in packet:
            if cls.HEADER_DELIMITER not in packet:
                raise HttpParseError("HTTP packet does not "
                                     "contain header delimiter")

            header, tail = packet.split(cls.HEADER_DELIMITER, maxsplit=1)
            content_len, content_type, encoding = cls._parse_header(header)
            if content_filter and content_type and content_filter not in content_type:
                break

            if content_len:
                content = tail[:content_len]
                packet = tail[content_len:]
                yield content

            elif encoding and b"chunked" in encoding:
                packet = yield from cls._parse_chunked_transfer_stream(tail)

            else:
                # Empty http packet.
                _, packet = packet.split(cls.HEADER_DELIMITER, maxsplit=1)

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

        return None

    @classmethod
    def _parse_header(cls, header):
        content_len = None
        content_type = None
        encoding = None
        for line in header.splitlines():
            line = line.lower()
            if line.startswith(cls.CONTENT_LEN):
                content_len = int(line[len(cls.CONTENT_LEN):].strip())
            elif line.startswith(cls.CONTENT_TYPE):
                content_type = line[len(cls.CONTENT_TYPE):].strip()
            elif line.startswith(cls.ENCODING):
                encoding = line[len(cls.ENCODING):].strip()
        return content_len, content_type, encoding


class HttpParseError(BaseException):
    pass
