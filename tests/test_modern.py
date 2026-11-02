#!/usr/bin/env python3
"""Loopback-only integration test: UDP, TCP framing, concurrent queries, malformed input."""
import http.server
import socket
import socketserver
import struct
import subprocess
import threading
import time
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
QUERY = bytes.fromhex('1234010000010000000000000377777706676f6f676c6503636f6d0000010001')

class DoH(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_POST(self):
        n = int(self.headers['Content-Length'])
        data = self.rfile.read(n)
        if self.path != '/dns-query' or self.headers.get('Content-Type') != 'application/dns-message':
            self.send_error(400)
            return
        response = bytearray(data)
        response[2] |= 0x80
        response[3] |= 0x80
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-message')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)
    def log_message(self, *args): pass

class HTTP(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTP(('127.0.0.1', 0), DoH)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = 20000 + (cls.server.server_port % 30000)
        cls.process = subprocess.Popen([str(BASE/'dnsp-modern'), '-p', str(cls.port), '-s',
            'http://127.0.0.1:%d/dns-query' % cls.server.server_port], stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE)
        time.sleep(.2)
        if cls.process.poll() is not None:
            raise RuntimeError('proxy exited: ' + cls.process.stderr.read().decode())
    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)
        cls.server.shutdown()
        cls.server.server_close()

    def test_udp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(QUERY, ('127.0.0.1', self.port))
            out, _ = s.recvfrom(4096)
            self.assertEqual(out[:2], QUERY[:2])
            self.assertTrue(out[2] & 0x80)
            self.assertEqual(out[12:], QUERY[12:])

    def test_tcp(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as s:
            s.settimeout(3)
            s.sendall(struct.pack('!H', len(QUERY)) + QUERY)
            frame = s.recv(2)
            self.assertEqual(struct.unpack('!H', frame)[0], len(QUERY))
            body = b''
            while len(body) < len(QUERY):
                body += s.recv(len(QUERY)-len(body))
            self.assertEqual(body[:2], QUERY[:2])
            self.assertTrue(body[2] & 0x80)

    def test_invalid_udp_does_not_kill(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b'\0\1', ('127.0.0.1', self.port))
        self.test_udp()

    def test_parallel_udp(self):
        errors=[]
        def worker(i):
            try:
                query=bytes([i, 1])+QUERY[2:]
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(5)
                    s.sendto(query, ('127.0.0.1', self.port))
                    out,_=s.recvfrom(4096)
                    assert out[:2] == query[:2]
            except Exception as exc: errors.append(exc)
        threads=[threading.Thread(target=worker,args=(i,)) for i in range(32)]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertFalse(errors,errors)

if __name__ == '__main__': unittest.main(verbosity=2)
