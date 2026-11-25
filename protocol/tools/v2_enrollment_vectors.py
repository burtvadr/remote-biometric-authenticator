#!/usr/bin/env python3
"""Independent canonical V2 enrollment contexts, no Rust/Kotlin dependency.
Public points are P-256 multiples 1 through 4 for tests only.
"""
import argparse
from pathlib import Path
from v2_message_vectors import P1, P2, P3, t, h
P4=bytes.fromhex('04e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6')

def generate():
    rows=['# direction\tcontext transcript hex\tcontext SHA256\ttransport attestation SHA256\tbiometric attestation SHA256']
    for direction,name in enumerate(['device-types','host-types']):
        base=dict(v=2,enrollment_id=bytes([5])*16,host_id=bytes([3])*16,nonce=bytes([5])*32,channel=bytes([3])*32)
        context=dict(**base,credential_id=bytes([4])*16,expires_at=220,direction=direction,suite='rba-spake2-p256-sha256-v2',host_cert=bytes([8])*32,provisional_client_cert=bytes([9])*32,host_key=P3,provisional_client_key=P4,transport_key=P1,biometric_key=P2)
        values=[t('RBA-V2-ENROLL-CONTEXT',context),h('RBA-V2-ENROLL-CONTEXT',context),h('RBA-V2-ATTEST',dict(**base,role=0)),h('RBA-V2-ATTEST',dict(**base,role=1))]
        rows.append('\t'.join([name]+[v.hex() for v in values]))
    return '\n'.join(rows)+'\n'
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');args=p.parse_args();dest=Path(__file__).resolve().parents[1]/'test-vectors'/'v2-enrollment-context.tsv';content=generate()
    if args.check: assert dest.read_text(encoding='ascii')==content,'fixture drift'
    else: dest.write_text(content,encoding='ascii')
