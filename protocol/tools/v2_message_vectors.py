#!/usr/bin/env python3
"""Independent message fixtures using the Python CBOR encoder, not either validator.
Fixed signatures are generated with Python cryptography/OpenSSL (test keys only).
Normal regeneration needs only the standard library.
"""
import argparse
import copy
import hashlib
from pathlib import Path
from v2_wire_vectors import enc, frame

P1=bytes.fromhex('046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')
P2=bytes.fromhex('047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1')
P3=bytes.fromhex('045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032')
ORDER=int('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',16)
SIG=(1).to_bytes(32,'big')*2 # valid scalar encoding only, not an authentic signature

def t(domain,obj): return domain.encode('ascii')+b'\0'+enc(obj)
def h(domain,obj): return hashlib.sha256(t(domain,obj)).digest()
def data():
    id=lambda n: bytes([n])*16
    b=lambda n: bytes([n])*32
    sid,rid,hid,cid,eid=id(1),id(2),id(3),id(4),id(5)
    cap=['attestation','number-match','strong-biometric','tls-exporter']
    scope=dict(purpose='authenticate',service='rba',operation='authenticate')
    grant=dict(credential_id=cid,approver=id(6),target=id(7),scope=scope)
    policy=dict(revision=1,grants=[grant])
    auth=dict(v=2,session_id=sid,request_id=rid,host_id=hid,credential_id=cid,host_nonce=b(1),device_nonce=b(2),channel=b(3),challenge=b(4),approver=id(6),target=id(7),approver_label='São Paulo',target_label='Local',scope=scope,context=dict(source='rba',detail='Authentication',interaction_id=id(8)),policy_revision=1,issued_at=100,expires_at=160)
    matched=dict(v=2,session_id=sid,request_id=rid,channel=b(3),request_hash=h('RBA-V2-AUTH-REQUEST',auth),matched=1)
    response=dict(v=2,session_id=sid,request_id=rid,channel=b(3),request_hash=matched['request_hash'],match_hash=h('RBA-V2-MATCHED',matched),credential_id=cid,decision=1)
    start=dict(v=2,enrollment_id=eid,host_id=hid,nonce=b(5),expires_at=220,direction=0,suite='rba-spake2-p256-sha256-v2')
    offer=dict(enrollment_id=eid,credential_id=cid,grants=[grant],revision=1,token=b(6),receipt=b(7))
    proof=dict(v=2,enrollment_id=eid,host_id=hid,credential_id=cid,channel=b(3),nonce=b(5),transport_key=P1,biometric_key=P2,role=1)
    attest=dict(v=2,enrollment_id=eid,host_id=hid,nonce=b(5),channel=b(3),role=0)
    ctx=dict(**start,credential_id=cid,channel=b(3),host_cert=b(8),provisional_client_cert=b(9),host_key=P3,provisional_client_key=P3,transport_key=P1,biometric_key=P2)
    messages={10:dict(v=2,host_id=hid,session_id=sid,host_nonce=b(1),capabilities=cap),11:dict(v=2,host_id=hid,session_id=sid,host_nonce=b(1),device_nonce=b(2),credential_id=cid,purpose=0,capabilities=cap),12:dict(core=auth,signature=SIG),13:dict(session_id=sid,request_id=rid,digits='001234'),14:dict(core=matched,signature=SIG),15:dict(core=response,signature=SIG),16:dict(session_id=sid,request_id=rid),17:dict(session_id=sid,request_id=rid,outcome=1),18:dict(session_id=sid,credential_id=cid,token=b(6)),19:dict(session_id=sid,credential_id=cid),20:dict(session_id=sid,**policy,digest=h('RBA-V2-POLICY',policy)),21:dict(session_id=sid,revision=1,digest=h('RBA-V2-POLICY',policy),accepted=0),22:dict(session_id=sid,revision=1,digest=h('RBA-V2-POLICY',policy)),23:dict(session_id=sid,enrollment_id=eid,state=1,receipt=b(7)),24:dict(session_id=sid,enrollment_id=eid,receipt=b(7)),30:start,31:dict(enrollment_id=eid,credential_id=cid,transport_key=P1,biometric_key=P2,share=P3),32:dict(enrollment_id=eid,share=P3,confirmation=b(10)),33:dict(enrollment_id=eid,confirmation=b(11)),34:dict(enrollment_id=eid,transport_chain=[b'opaque-cert-bytes'],biometric_chain=[b'opaque-cert-bytes'],transport_proof=SIG,biometric_proof=SIG,cleanup_tokens=[b(12)]),35:offer,36:dict(enrollment_id=eid,offer_hash=h('RBA-V2-ENROLL-OFFER',offer)),37:dict(enrollment_id=eid,receipt=b(7),offer_hash=h('RBA-V2-ENROLL-OFFER',offer)),38:dict(enrollment_id=eid)}
    domains={'RBA-V2-AUTH-REQUEST':auth,'RBA-V2-MATCHED':matched,'RBA-V2-AUTH-RESPONSE':response,'RBA-V2-ENROLL-KEY-PROOF':proof,'RBA-V2-POLICY':policy,'RBA-V2-ATTEST':attest,'RBA-V2-ENROLL-OFFER':offer,'RBA-V2-ENROLL-CONTEXT':ctx}
    return messages,domains

# Signatures fixed below; created once with ec.derive_private_key(1, SECP256R1())
# and ECDSA(SHA256(), deterministic_signing=True), decoded to raw r||s.
SIGNATURES = {'RBA-V2-AUTH-REQUEST': '6ca46e555fb969059c51f5c9770326598635ce45424bfb02209f38ea95622ef2e97e9be0887c1a344d4671126b20b24b8c08570f84af2de03124411ba7416168', 'RBA-V2-MATCHED': '96924470296dbdf4d2578c8c6a55a1eeb5ecf606c331ab9c9f5fc0e26c2054aab3648d71bafe2c6d49bfbf2e22643ab06a0ceff9e8595d2dcf5c01f35aa60a6e', 'RBA-V2-AUTH-RESPONSE': 'dd101350389c791e8213685fe1258d7ee8b553668ffbd5bd04839312357626a30ed6c4cc3c13c3bd71a15d77c09bf9886c8e9604e809bd7e07eb8ec03bc2b27b', 'RBA-V2-ENROLL-KEY-PROOF': '912eae47dd6b1e980cf98ccfafc65097f892b4b0e45b2a05e83914bce0e7d932f3a09da843f7fd90bc6819de9bc7af90e2c247c1b208bb8648922af58998a022'}

def generate():
    messages,domains=data(); rows=[]
    def add(name,mode,raw,extra='-'): rows.append((name,mode,raw.hex(),extra))
    def msg(name,mode,code,obj): add(name,mode,frame(code,enc(obj)))
    for code,obj in messages.items():
        msg(f'msg-{code}','accept',code,obj)
        msg(f'unknown-{code}','reject',code,dict(obj,unexpected=1))
        for field in obj:
            bad=dict(obj);del bad[field];msg(f'missing-{code}-{field}','reject',code,bad)
            bad=dict(obj);bad[field]=[] if not isinstance(obj[field],list) else 0;msg(f'type-{code}-{field}','reject',code,bad)
    def mutation(code,field,value,name,nested=False):
        bad=copy.deepcopy(messages[code]); (bad['core'] if nested else bad)[field]=value;msg(name,'reject',code,bad)
    for purpose in (1,2,3): msg(f'hello-purpose-{purpose}','accept',11,dict(messages[11],purpose=purpose))
    mutation(11,'purpose',4,'unknown-session-purpose')
    mutation(10,'v',1,'version-v1');mutation(10,'host_id',b'x'*15,'short-id');mutation(10,'capabilities',['attestation','number-match','strong-biometric'],'missing-capability');mutation(10,'capabilities',['number-match','attestation','strong-biometric','tls-exporter'],'unsorted-capabilities');mutation(10,'capabilities',['attestation','attestation','number-match','strong-biometric','tls-exporter'],'duplicate-capability')
    msg('future-capability','accept',10,dict(messages[10],capabilities=sorted(messages[10]['capabilities']+['future-capability'])))
    for field,value,name in [('approver_label','Sa\u0303o','not-nfc'),('target_label','A\u202eB','bidi'),('target_label','A\u200bB','format'),('target_label','A\nB','control'),('target_label','é'*65,'label-byte-limit'),('expires_at',161,'expiry-too-long'),('expires_at',100,'expiry-zero'),('expires_at',99,'expiry-underflow'),('scope',dict(purpose='authenticate',service='rba',operation='*'),'wildcard-scope'),('scope',dict(purpose='authenticate',service='future',operation='auth'),'unknown-scope'),('context',dict(source='rba',detail='é'*129,interaction_id=b'x'*16),'detail-limit'),('channel',b'x'*31,'channel-length')]: mutation(12,field,value,name,True)
    # Explicit profile cases; independent examples, not generated from implementation tables.
    for label,name,allowed in [
        ('São Paulo','latin',True),('Ελληνικά','greek',True),('العربية','arabic',True),
        ('中文','cjk',True),('한국어','hangul',True),('हिन्दी','devanagari',True),
        ('🌍','assigned-supplementary',True),('A B','ascii-space',True),
        ('A\u034fB','combining-grapheme-joiner',False),('A\ufe0f','variation-selector',False),
        ('A\u115fB','hangul-filler',False),('A\ue000B','private-use',False),
        ('A\U000f0000B','supplementary-private-use',False),('A\U0001fae0B','post-unicode-ten',False),
        ('A\u0378B','unassigned',False),('A\ufdd0B','noncharacter',False),
        ('A\u2028B','line-separator',False),('A\u2029B','paragraph-separator',False),
        ('\u212b','noncanonical-angstrom',False),('\u1100\u1161','decomposed-hangul',False),
        ('a\u0301','decomposed-latin',False),('A\U000e0100','supplementary-variation-selector',False),
    ]:
        bad=copy.deepcopy(messages[12]);bad['core']['target_label']=label
        msg('display-text-'+name,'accept' if allowed else 'reject',12,bad)
    mutation(13,'digits','１２３４５６','non-ascii-digits');mutation(13,'digits','12345','short-digits');mutation(14,'matched',0,'not-matched',True);mutation(15,'decision',0,'not-approved',True);mutation(17,'outcome',2,'invalid-outcome');mutation(21,'accepted',2,'invalid-policy-decision');mutation(23,'receipt',bytes(32),'zero-committed-receipt');mutation(23,'state',0,'nonzero-absent-receipt');msg('absent-receipt','accept',23,dict(messages[23],state=0,receipt=bytes(32)))
    mutation(20,'digest',bytes(32),'bad-policy-digest');mutation(20,'grants',[messages[20]['grants'][0]]*2,'duplicate-grants');mutation(30,'direction',2,'bad-direction');mutation(30,'suite','spake2-p256-sha256-v2','wrong-suite');mutation(31,'transport_key',P2,'same-keys');mutation(31,'share',b'\x04'+bytes(64),'off-curve');mutation(31,'share',b'\x04'+b'\xff'*64,'out-of-field');mutation(31,'share',b'\x02'+bytes(32),'compressed-point');mutation(12,'signature',bytes(64),'zero-signature');mutation(12,'signature',ORDER.to_bytes(32,'big')+SIG[32:],'out-of-range-r');mutation(12,'signature',SIG[:32]+ORDER.to_bytes(32,'big'),'out-of-range-s');mutation(12,'signature',SIG[:-1],'short-signature');mutation(34,'transport_chain',[],'empty-chain');mutation(34,'transport_chain',[b'x']*9,'too-many-certs');mutation(34,'biometric_chain',[bytes(8193)],'oversize-cert');mutation(35,'receipt',messages[35]['token'],'token-equals-receipt');mutation(35,'credential_id',bytes(16),'foreign-grant')
    for domain,core in domains.items():
        add(domain,'transcript',enc(core),t(domain,core).hex()+':'+h(domain,core).hex())
        if domain in SIGNATURES:
            sig=bytes.fromhex(SIGNATURES[domain]); alt=sig[:32]+(ORDER-int.from_bytes(sig[32:],'big')).to_bytes(32,'big')
            for suffix,key,raw,mode in [('valid',P1,sig,'verify'),('alternate-s',P1,alt,'verify'),('wrong-key',P2,sig,'bad-signature'),('changed-signature',P1,sig[:63]+bytes([sig[-1]^1]),'bad-signature')]:
                add(domain+'-'+suffix,mode,enc(core),domain+':'+key.hex()+':'+raw.hex())
    return '# name\tmode\tframe or core hex\texpected transcript:hash or domain:key:signature\n'+''.join('\t'.join(r)+'\n' for r in rows)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');args=p.parse_args();dest=Path(__file__).resolve().parents[1]/'test-vectors'/'v2-message.tsv';content=generate()
    if args.check: assert dest.read_text(encoding='ascii')==content,'fixture drift'
    else: dest.write_text(content,encoding='ascii')
