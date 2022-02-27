from http_handler import HttpHandler


def test_normal_http_parse():
    """Test correct extraction of payload from a normal http layer."""
    http_layer = bytearray(
                 b"HTTP/1.1 200 OK\x0d\x0aContent-Type: application/json;"
                 b"charset=utf-8\x0d\x0aDate: Sat, 04 Dec 2021 09:39:58 G"
                 b"MT\x0d\x0aContent-Length: 60\x0d\x0aConnection: close"
                 b"\x0d\x0a\x0d\x0a")

    payload = bytearray(b'{"id":"819e1fbf","name":"Figueroa", '
                        b'"price":14,"count":808}\x0a')

    pyaload_generator = HttpHandler.parse_http_stream(http_layer + payload,
                                                      content_filter=b"json")
    extracted_payloads = list(pyaload_generator)
    assert len(extracted_payloads) == 1,\
        f"Http handler parsed {len(extracted_payloads)} payloads instead of 1"

    assert extracted_payloads[0] == payload,\
        "Http handler did not parse the payload correctly"


def test_chunk_transfer_mode_http_parse():
    """Test correct extraction of payloads from http layer with chunking mode"""
    http_layer = bytearray(
        b'HTTP/1.1 200 OK\x0d\x0aX-Powered-By: Express\x0d\x0aDate: Sat, 04'
        b' Dec 2021 09:39:54 GMT\x0d\x0aConnection: keep-alive\x0d\x0aTrans'
        b'fer-Encoding: chunked\x0d\x0a\x0d\x0a45\x0d\x0a{"id":"510a0d7e-8e'
        b'83","name":"SuperSport XL","price":15,"count":820}\x0a\x0d\x0a'
        b'12\x0d\x0asecond payload...\x0a\x0d\x0a0\x0d\x0a\x0d\x0a'
    )

    pyaload_generator = HttpHandler.parse_http_stream(http_layer,
                                                      content_filter=b"json")
    extracted_payloads = list(pyaload_generator)
    assert len(extracted_payloads) == 2, \
        f"Http handler parsed {len(extracted_payloads)} chunks instead of 2"

    assert extracted_payloads[0] == b'{"id":"510a0d7e-8e83",' \
                                    b'"name":"SuperSport XL"' \
                                    b',"price":15,"count":820}\x0a\x0d\x0a',\
        "First chunked payload not extracted correctly"

    assert extracted_payloads[1] == b'second payload...\x0a\x0d\x0a',\
        "Second chunked payload not extracted correctly"

