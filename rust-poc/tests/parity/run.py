#!/usr/bin/env python3
"""Differential wire-policy check against the pinned dnsp-modern.c."""
import argparse
import hashlib
import os
from pathlib import Path
import random
import shlex
import struct
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def u16(value):
    return struct.pack('>H', value)


def dns(flags=0x0100, question=b'', answers=(), authority=(), additional=()):
    return (struct.pack('>6H', 0x1234, flags, bool(question), len(answers), len(authority), len(additional))
            + question + b''.join(answers + authority + additional))


def rr(kind, data, *, owner=b'\xc0\x0c', ttl=120, klass=1):
    return owner + struct.pack('>HHIH', kind, klass, ttl, len(data)) + data


def opt(data=b'', size=4096, ttl=0):
    return rr(41, data, owner=b'\x00', klass=size, ttl=ttl)


def cases(seed):
    rng = random.Random(seed)
    name = b'\x03WWW\x07Example\x03COM\x00'
    a = name + struct.pack('>HH', 1, 1)
    positive = rr(1, b'\xc0\x00\x02\x01')
    padded = opt(b'\x00\x0c\x00\x04\x00\x00\x00\x00\x00\x0f\x00\x02\x00\x03')
    base = [(dns(question=a), dns(0x8180, a, (positive,))),
            (dns(question=a, additional=(opt(),)), dns(0x81a0, a, (positive,), additional=(padded,))),
            (dns(question=a), dns(0x8183)), (dns(question=a), b''),
            (dns(question=a), dns(0x8380)), (dns(), dns(0x8180)),
            (dns(question=a, additional=(rr(250, b'\0', ttl=0),)),
             dns(0x8180, a, (positive,), additional=(rr(250, b'\0', ttl=0),)))]
    for kind in (1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 14, 15, 16, 17, 18, 21, 24, 26, 28, 30, 33, 35,
                 39, 43, 46, 48, 52, 64, 65, 249, 250, 251, 252, 255, 65400):
        for klass in (1, 3, 255):
            question = name + struct.pack('>HH', kind, klass)
            rdata = {2: name, 3: name, 4: name, 5: b'\xc0\x0c', 6: name * 2 + bytes(20),
                     7: name, 8: name, 9: name, 12: name, 14: name * 2,
                     15: u16(10) + name, 17: name * 2, 18: u16(10) + name,
                     21: u16(10) + name, 24: bytes(18) + name + b'signature',
                     26: u16(10) + name * 2, 28: bytes(16), 30: name + b'\x01\x40',
                     33: bytes(6) + b'\xc0\x0c', 35: bytes(4) + b'\x01S\x03SIP\x00' + name,
                     39: name}.get(kind, b'\xc0\x00\x02\x01')
            base.append((dns(question=question), dns(0x8180, question, (rr(kind, rdata, klass=klass),))))
    for size in (0, 1, 511, 512, 1232, 1233, 4096, 65535):
        for value in (0, 0x8000, 0x00010000, 0x01000000):
            query = dns(question=a, additional=(opt(size=size, ttl=value),))
            for cap in (512, 1232, 4096):
                yield cap, query, dns(0x8180, a, (positive,), additional=(opt(size=size, ttl=value),))
    for length in (511, 512, 513, 1231, 1232, 1233, 4095, 4096, 4097, 65506, 65507, 65508, 65534, 65535, 65536):
        rdata = bytes(length - 12 - len(a) - 12)
        yield 1232, dns(question=a, additional=(rr(65400, rdata),)), dns(0x8180, a, (rr(65400, rdata),))
    for query, response in base:
        yield 1232, query, response

    for offset, ttl, kind in ((6, 0x01610000, 1), (5, 0x61000000, 1), (6, 0x01610000, 17)):
        pointer = u16(0xc000 | (12 + len(a) + offset))
        first = rr(1, b'\xc0\x00\x02\x01', ttl=ttl)
        second = rr(17, pointer + b'\xc0\x0c') if kind == 17 else rr(1, bytes(4), owner=pointer)
        yield 1232, dns(question=a), dns(0x8180, a, (first, second))

    def mutate(packet):
        out = bytearray(packet)
        for _ in range(rng.randint(1, 8)):
            mode = rng.randrange(5)
            if mode <= 1 and out:
                out[rng.randrange(len(out))] = rng.randrange(256)
            elif mode == 2:
                del out[rng.randrange(len(out) + 1):]
            elif mode == 3:
                offset = rng.randrange(len(out) + 1)
                out[offset:offset] = rng.randbytes(rng.randrange(1, 12))
            elif len(out) >= 2:
                offset = rng.randrange(len(out) - 1)
                out[offset:offset+2] = b'\xc0' + bytes([rng.randrange(256)])
        return bytes(out)

    for index in range(20_000):
        query, response = rng.choice(base)
        if index % 3:
            query = mutate(query)
        if index % 3 != 1:
            response = mutate(response)
        yield rng.choice((512, 1232, 4096)), query, response
    for index in range(4000):
        packet = rng.randbytes(index % 256)
        yield 1232, packet, None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reference', type=Path, help='directory containing the pinned dnsp-modern.c')
    parser.add_argument('--seed', type=int, default=8484)
    args = parser.parse_args()
    revision = (ROOT/'SOURCE_REVISION').read_text().strip()
    reference = args.reference.resolve()
    stamp = reference/'SOURCE_REVISION'
    if stamp.is_file():
        head = stamp.read_text().strip()
    else:
        head = subprocess.check_output(['git', '-C', str(reference), 'rev-parse', 'HEAD'], text=True).strip()
    if head != revision:
        parser.error(f'reference is {head}, expected {revision}')
    corpus = list(cases(args.seed))
    encoded = b''.join(struct.pack('>HIIB', cap, len(q), len(r or b''), r is not None) + q + (r or b'')
                       for cap, q, r in corpus)
    with tempfile.TemporaryDirectory(prefix='dnsp-wire-') as tmp:
        c = Path(tmp)/'c-oracle'
        rust = Path(tmp)/'rust-oracle'
        curl = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', 'libcurl'], text=True))
        cc = shlex.split(os.getenv('CC', 'cc'))
        subprocess.run(cc + ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                             '-I', str(reference), '-o', str(c), str(HERE/'oracle.c')] + curl, check=True)
        subprocess.run(['rustc', '--edition=2024', '-O', '-A', 'dead_code',
                        '-o', str(rust), str(HERE/'oracle.rs')], check=True)
        baseline = subprocess.check_output([c], input=encoded).splitlines()
        port = subprocess.check_output([rust], input=encoded).splitlines()
    if len(baseline) != len(corpus) or len(port) != len(corpus):
        raise SystemExit(f'expected {len(corpus)} outputs, got C {len(baseline)} and Rust {len(port)}')
    for i, (expected, actual) in enumerate(zip(baseline, port)):
        if expected != actual:
            cap, query, response = corpus[i]
            raise SystemExit(f'case {i}, cap {cap}, request {query.hex()}, response {response.hex() if response is not None else None}\n'
                             f'C {expected.decode()}\nRust {actual.decode()}')
    print(f'{len(corpus)} cases matched, seed {args.seed}, corpus sha256 {hashlib.sha256(encoded).hexdigest()}')


if __name__ == '__main__':
    main()
