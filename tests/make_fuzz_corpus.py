"""Build libFuzzer seeds from the wire fixtures shared with the integration suite."""
import sys
from pathlib import Path

from test_modern import ANSWER, QUERY, SOA, edns_options, padding_option, query, rr


def main():
    corpus = Path(sys.argv[1])
    corpus.mkdir()
    response = QUERY[:2] + bytes.fromhex('81800001000100000000') + QUERY[12:] + ANSWER
    negative = QUERY[:2] + bytes.fromhex('81830001000000010000') + QUERY[12:] + rr(6, SOA)
    padded_query = edns_options(query(edns=1232), padding_option(11))
    padded_response = response[:11] + b'\1' + response[12:] + padded_query[len(QUERY):]
    seeds = {
        'query': b'Q' + QUERY,
        'query-edns': b'Q' + query(edns=1232),
        'query-padded': b'Q' + padded_query,
        'response': b'R' + response,
        'response-negative': b'R' + negative,
        'response-padded': b'R' + padded_response,
        'headers-public': b'HHTTP/2 200\r\nAge: 7\r\nCache-Control: public, max-age=30\r\n'
        b'Date: Sun, 06 Nov 1994 08:49:37 GMT\r\nVary: Accept\r\n\r\n',
        'headers-private': b'HHTTP/1.1 200 OK\r\nCache-Control: private, no-store\r\n'
        b'Vary: *\r\nSet-Cookie: k=v\r\n\r\n',
    }
    for name, data in seeds.items():
        (corpus / name).write_bytes(data)


if __name__ == '__main__':
    main()
