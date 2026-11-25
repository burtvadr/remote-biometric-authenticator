#!/usr/bin/env python3
"""Independent RFC 8949 / PAF2 wire fixtures; no RBA implementation imports."""
from pathlib import Path
import argparse
import struct


def head(major, n):
    if n < 24:
        return bytes([major * 32 + n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([major * 32 + ai]) + n.to_bytes(width, 'big')
    raise ValueError(n)


def enc(v):
    if type(v) is int:
        return head(0, v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        raw = v.encode('utf-8')
        return head(3, len(raw)) + raw
    if isinstance(v, list):
        return head(4, len(v)) + b''.join(map(enc, v))
    if isinstance(v, dict):
        pairs = sorted((enc(k), enc(x)) for k, x in v.items())
        return head(5, len(pairs)) + b''.join(k + x for k, x in pairs)
    raise TypeError(v)


def frame(t, body, magic=b'PAF2', version=2, flags=0, n=None):
    return struct.pack('>4sBHHI', magic, version, t, flags,
                       len(body) if n is None else n) + body


def generate():
    cases = []
    def add(name, mode, raw):
        cases.append((name, mode, raw.hex()))
    def accept(name, obj):
        add(name, 'accept', frame(10, enc(obj)))
    def reject(name, body):
        add(name, 'reject', frame(10, body))
    accept('empty-structural-map', {})
    accept('uint-boundaries', {'x': [0,23,24,255,256,65535,65536,2**32-1,2**32,2**63,2**64-1]})
    accept('encoded-key-order', {'aa': 2, 'z': 1, 'é': 3})
    accept('utf8-and-byte-string', {'label': 'São Paulo', 'raw': b'PAF2\x00\xff'})
    accept('nested', {'x': [{'y': [1,2]}]})
    accept('array-32', {'x': [0]*32})
    accept('map-32', {f'k{i:02}': i for i in range(32)})
    reject('map-33', enc({f'k{i:02}': i for i in range(33)}))
    accept('supplementary-utf8', {'x': '\U0001f30d'})
    accept('depth-eight', {'x': [[[[[[[0]]]]]]]})
    # Root map + one key + outer array + 31 inner arrays + 990 uints = 1024.
    accept('items-exact-1024', {'x': [[0]*32 for _ in range(30)] + [[0]*30]})
    reject('items-1025', enc({'x': [[0]*32 for _ in range(30)] + [[0]*31]}))
    accept('payload-exact-65536', {'x': b'\x00'*65530})
    for t in list(range(10,25))+list(range(30,39)):
        add(f'type-{t}', 'accept', frame(t, enc({})))
    for name, raw in {
        'negative': 'a1617820', 'bool': 'a16178f4', 'tag': 'a16178c000',
        'float': 'a16178f90000', 'null': 'a16178f6', 'indefinite': 'bf617800ff',
        'duplicate': 'a2617800617801', 'unsorted': 'a262616100617a00',
        'nontext-key': 'a10000', 'nonshort-uint': 'a161781817',
        'nonshort-length': 'a16178580100', 'invalid-utf8': 'a1617861ff',
        'utf8-surrogate': 'a1617863eda080', 'trailing': 'a000',
        'non-map': '8100', 'truncated-map': 'a16178', 'truncated-text': 'a1617863ff',
        'huge-byte-length': 'a161785b0000000100000000',
        'huge-text-length': 'a161787bffffffffffffffff',
        'huge-array-length': 'a161789b0000000100000000',
        'huge-map-length': 'a16178bb0000000100000000',
        'reserved-ai': 'a161781c',
    }.items():
        reject(name, bytes.fromhex(raw))
    reject('array-33', enc({'x':[0]*33}))
    reject('depth-nine', enc({'x': [[[[[[[[0]]]]]]]]}))
    for name, raw in {
        'v1-magic': frame(10,b'',magic=b'PAF1',n=1),
        'v1-version': frame(10,b'',version=1,n=1),
        'future-version': frame(10,b'',version=3,n=1),
        'flags': frame(10,b'',flags=1,n=1),
        'unknown-type': frame(25,b'',n=1),
        'zero-length': frame(10,b''),
        'oversize': frame(10,b'',n=65537),
        'max-u32-length': frame(10,b'',n=2**32-1),
    }.items():
        add(name,'bad-header',raw)
    add('short-header','reject',b'PAF2')
    add('short-body','reject',frame(10,b'\xa0',n=2))
    return '# name\texpectation\tframe hex\n' + ''.join('\t'.join(c)+'\n' for c in cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    dest = Path(__file__).resolve().parents[1] / 'test-vectors' / 'v2-wire.tsv'
    content = generate()
    if args.check:
        assert dest.read_text(encoding='ascii') == content, 'fixture drift'
    else:
        dest.write_text(content, encoding='ascii')
