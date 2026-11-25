//! Owned V2 enrollment transitions. TLS and attestation adapters are trusted
//! host components; they must not construct facts from remote assertions.
//! A verifier implementation is required for enrollment. No default verifier.
use super::*;
use rba_enrollment::{PairingCode, Unconfirmed};
use rba_protocol::{cbor::Value as V, v2_message::{self as m, Domain, Kind, Message}, v2_wire};
use p256::elliptic_curve::subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const SUITE: &str = "rba-spake2-p256-sha256-v2";
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EntryDirection { DeviceTypes, HostTypes }
impl EntryDirection { fn wire(self)->u64 { match self { Self::DeviceTypes=>0,Self::HostTypes=>1 } } }
/// Produced locally by the provisional TLS adapter after CertificateVerify.
/// Never accept these values from an RBA payload.
#[derive(Clone)]
pub struct EnrollmentChannel {
    pub channel: Hash, pub host_cert: Hash, pub provisional_client_cert: Hash,
    pub host_key: [u8;65], pub provisional_client_key: [u8;65],
}
pub struct EnrollmentStart { pub message: Message, pub display_code: Option<Zeroizing<[u8;6]>> }
#[derive(Clone)]
pub(super) struct Binding { id:Id, host:Id, nonce:Hash, expiry:i64, direction:EntryDirection, tls:EnrollmentChannel }
pub(super) struct Keys { credential:Id, transport:[u8;65], biometric:[u8;65] }
pub(super) struct Checked { transport_chain:Vec<u8>, biometric_chain:Vec<u8>, validity:AttestationValidity, cleanup:Vec<Hash>, replaces:Vec<Id> }
pub(super) enum Stage {
    Start { binding:Binding, code:Option<PairingCode> },
    Confirm { binding:Binding, keys:Keys, exchange:Unconfirmed },
    Evidence { binding:Binding, keys:Keys },
    Approval { binding:Binding, keys:Keys, checked:Checked, context_hash:Hash },
    Staged { keys:Keys, checked:Checked, offer_hash:Hash, receipt:Zeroizing<Hash>, token_hash:Hash, initial_cli:bool },
}
/// The UI must display actual TLS fingerprints, long-term device key
/// fingerprints and the exact credential IDs proposed for revocation. The returned context hash identifies this exact approval.
pub struct EnrollmentApproval { pub enrollment:Id, pub context_hash:Hash, pub host_cert:Hash, pub provisional_client_cert:Hash, pub host_key_hash:Hash, pub provisional_client_key_hash:Hash, pub transport_key_hash:Hash, pub biometric_key_hash:Hash, pub replaces:Vec<Id> }
/// Exact role-specific inputs to the trusted host attestation verifier. It
/// must check certificate path/revocation, freshness, leaf key, role-specific
/// hardware/biometric properties, application signer and verified boot.
pub struct AttestationRequest<'a> { pub chain:&'a [Vec<u8>], pub expected_key:&'a [u8;65], pub challenge:Hash, pub biometric:bool, pub now:i64 }
#[derive(Clone, Copy)]
pub struct AttestationValidity { pub attested_at:i64, pub assurance_until:i64, pub status_checked_at:i64, pub status_until:i64 }
pub trait AttestationVerifier { fn verify(&mut self, request:AttestationRequest<'_>)->Result<AttestationValidity>; }
fn invalid<T>(r:std::result::Result<T,v2_wire::Invalid>)->Result<T>{r.map_err(|_|Error::Invalid)}
fn b(x:impl AsRef<[u8]>)->V{V::Bytes(x.as_ref().to_vec())}
fn f<'a>(v:&'a V,k:&str)->Result<&'a V>{v.get(k).ok_or(Error::Invalid)}
fn bytes<'a>(v:&'a V,k:&str)->Result<&'a [u8]>{f(v,k)?.as_bytes().ok_or(Error::Invalid)}
fn fixed<const N:usize>(v:&V,k:&str)->Result<[u8;N]>{bytes(v,k)?.try_into().map_err(|_|Error::Invalid)}
fn u(n:i64)->Result<V>{Ok(V::Uint(u64::try_from(n).map_err(|_|Error::Clock)?))}
fn random_hash()->Result<Hash>{let mut h=[0;32];getrandom::getrandom(&mut h).map_err(|_|Error::State)?;if h==[0;32]{return Err(Error::State)} Ok(h)}
fn msg(kind:Kind,fields:impl IntoIterator<Item=(&'static str,V)>)->Result<Message>{invalid(Message::new(kind,V::map(fields)))}
fn exact<'a>(message:&'a Message,kind:Kind,id:Id)->Result<&'a V>{let p=message.payload();if message.kind()!=kind||fixed::<16>(p,"enrollment_id")?!=id{return Err(Error::Denied)} Ok(p)}
fn point(p:&[u8;65])->bool{p[0]==4&&p256::PublicKey::from_sec1_bytes(p).is_ok()}
impl Binding {
    fn base(&self)->[(&'static str,V);5]{[("v",V::Uint(2)),("enrollment_id",b(self.id)),("host_id",b(self.host)),("nonce",b(self.nonce)),("channel",b(self.tls.channel))]}
    fn context(&self,k:&Keys)->Result<V>{Ok(V::map(self.base().into_iter().chain([
        ("credential_id",b(k.credential)),("expires_at",u(self.expiry)?),("direction",V::Uint(self.direction.wire())),("suite",V::text(SUITE)),
        ("host_cert",b(self.tls.host_cert)),("provisional_client_cert",b(self.tls.provisional_client_cert)),("host_key",b(self.tls.host_key)),("provisional_client_key",b(self.tls.provisional_client_key)),("transport_key",b(k.transport)),("biometric_key",b(k.biometric))]))) }
    fn proof(&self,k:&Keys,role:u64)->V{V::map(self.base().into_iter().chain([("credential_id",b(k.credential)),("transport_key",b(k.transport)),("biometric_key",b(k.biometric)),("role",V::Uint(role))]))}
    fn challenge(&self,role:u64)->Result<Hash>{invalid(m::hash(Domain::Attest,&V::map(self.base().into_iter().chain([("role",V::Uint(role))]))))}
}
fn chain(v:&V)->Result<Vec<Vec<u8>>>{let V::Array(a)=v else{return Err(Error::Invalid)}; a.iter().map(|x|x.as_bytes().map(|b|b.to_vec()).ok_or(Error::Invalid)).collect()}
fn checked_validity(a:AttestationValidity,b:AttestationValidity,now:i64)->Result<AttestationValidity>{
    for v in [a,b] { if v.attested_at>now || v.attested_at<0 || v.assurance_until<=now || v.assurance_until.checked_sub(v.attested_at).is_none_or(|x|x>2592000) || v.status_checked_at<v.attested_at || v.status_checked_at>now || v.status_until<=now || v.status_until.checked_sub(v.status_checked_at).is_none_or(|x|x>86400) {return Err(Error::Denied)} }
    let v=AttestationValidity{attested_at:a.attested_at.max(b.attested_at),assurance_until:a.assurance_until.min(b.assurance_until),status_checked_at:a.status_checked_at.min(b.status_checked_at),status_until:a.status_until.min(b.status_until)};
    if v.status_checked_at<v.attested_at || v.status_until.checked_sub(v.status_checked_at).is_none_or(|x|x>86400){return Err(Error::Denied)} Ok(v)
}
impl Authority {
    fn pairing_on(&mut self,conn:ConnectionId)->Result<&mut Pairing>{let p=self.pairing.as_mut().ok_or(Error::Denied)?;if !p.classified||p.connection!=Some(conn){return Err(Error::Denied)}Ok(p)}
    fn enrollment_step<T>(&mut self,conn:ConnectionId,now:i64,mono:Instant,step:impl FnOnce(&mut Self)->Result<T>)->Result<T>{
        let result=(||{self.expire(now,mono)?;self.pairing_on(conn)?;step(self)})();
        if result.is_err(){self.deny_connection(conn);} result
    }
    pub fn enrollment_start(&mut self,owner:Id,conn:ConnectionId,direction:EntryDirection,tls:EnrollmentChannel,now:i64,mono:Instant)->Result<EnrollmentStart>{
        self.enrollment_step(conn,now,mono,|s|{
            let host=as_id(s.store.db.query_row("SELECT host_id FROM host_meta WHERE singleton=1",[],|r|r.get(0))?)?;
            let p=s.pairing_on(conn)?;
            if p.owner!=owner||p.enrollment.is_some()||!point(&tls.host_key)||!point(&tls.provisional_client_key)||tls.host_key==tls.provisional_client_key{return Err(Error::Denied)}
            let binding=Binding{id:p.id,host,nonce:random_hash()?,expiry:p.expires_wall,direction,tls};
            let code=if direction==EntryDirection::DeviceTypes{Some(PairingCode::generate().map_err(|_|Error::State)?)}else{None};
            let display_code=code.as_ref().map(|c|Zeroizing::new(*c.as_ascii()));
            let message=msg(Kind::EnrollStart,[("v",V::Uint(2)),("enrollment_id",b(binding.id)),("host_id",b(host)),("nonce",b(binding.nonce)),("expires_at",u(binding.expiry)?),("direction",V::Uint(direction.wire())),("suite",V::text(SUITE))])?;
            p.enrollment=Some(Stage::Start{binding,code}); Ok(EnrollmentStart{message,display_code})
        })
    }
    /// For HostTypes, code must come from the original trusted local owner;
    /// never from a wire field. DeviceTypes uses the previously generated code.
    pub fn enrollment_share(&mut self,owner:Id,conn:ConnectionId,message:&Message,entered:Option<PairingCode>,now:i64,mono:Instant)->Result<Message>{
        self.enrollment_step(conn,now,mono,|s|{
            let p=s.pairing_on(conn)?; if p.owner!=owner{return Err(Error::Denied)}
            let Some(Stage::Start{binding,code})=p.enrollment.take() else{return Err(Error::Denied)};
            let payload=exact(message,Kind::EnrollShare,p.id)?;
            let keys=Keys{credential:fixed(payload,"credential_id")?,transport:fixed(payload,"transport_key")?,biometric:fixed(payload,"biometric_key")?};
            if !valid_id(&keys.credential)||keys.transport==keys.biometric||[binding.tls.host_key,binding.tls.provisional_client_key].iter().any(|k|*k==keys.transport||*k==keys.biometric){return Err(Error::Denied)}
            let code=match(binding.direction,code,entered){(EntryDirection::DeviceTypes,Some(c),None)|(EntryDirection::HostTypes,None,Some(c))=>c,_=>return Err(Error::Denied)};
            let aad=invalid(m::transcript(Domain::EnrollContext,&binding.context(&keys)?))?;
            let mut rng=rand_core_10::UnwrapErr(getrandom_04::SysRng);
            let (share,state)=rba_enrollment::start_host_v2(code,&binding.host,&keys.credential,&aad,&mut rng).map_err(|_|Error::Denied)?;
            let exchange=state.finish(bytes(payload,"share")?).map_err(|_|Error::Denied)?;
            let reply=msg(Kind::EnrollConfirmA,[("enrollment_id",b(p.id)),("share",b(share)),("confirmation",b(exchange.confirmation()))])?;
            p.enrollment=Some(Stage::Confirm{binding,keys,exchange});Ok(reply)
        })
    }
    pub fn enrollment_confirm(&mut self,conn:ConnectionId,message:&Message,now:i64,mono:Instant)->Result<()> {
        self.enrollment_step(conn,now,mono,|s|{
            let p=s.pairing_on(conn)?; let Some(Stage::Confirm{binding,keys,exchange})=p.enrollment.take() else{return Err(Error::Denied)};
            let payload=exact(message,Kind::EnrollConfirmB,p.id)?;
            let _confirmed=exchange.verify_peer(bytes(payload,"confirmation")?).map_err(|_|Error::Denied)?;
            p.enrollment=Some(Stage::Evidence{binding,keys});Ok(())
        })
    }
    /// Verifier is a trusted concrete platform adapter (B.3); no wire flag can
    /// substitute for verification. Recheck deadline after certificate work.
    pub fn enrollment_evidence(&mut self,conn:ConnectionId,message:&Message,clock:impl FnMut()->Result<(i64,Instant)>)->Result<EnrollmentApproval>{
        let Some(mut verifier)=self.attestation.take() else{self.deny_connection(conn);return Err(Error::Denied)};
        let result=self.enrollment_evidence_with(conn,message,&mut verifier,clock);
        self.attestation=Some(verifier);result
    }
    fn enrollment_evidence_with(&mut self,conn:ConnectionId,message:&Message,verifier:&mut impl AttestationVerifier,mut clock:impl FnMut()->Result<(i64,Instant)>)->Result<EnrollmentApproval>{
        let result=(||{
            let(now,mono)=clock()?; self.expire(now,mono)?;
            let p=self.pairing_on(conn)?;let Some(Stage::Evidence{binding,keys})=p.enrollment.take() else{return Err(Error::Denied)};
            let payload=exact(message,Kind::EnrollEvidence,p.id)?;
            invalid(m::verify(Domain::EnrollKeyProof,&binding.proof(&keys,0),&keys.transport,bytes(payload,"transport_proof")?))?;
            invalid(m::verify(Domain::EnrollKeyProof,&binding.proof(&keys,1),&keys.biometric,bytes(payload,"biometric_proof")?))?;
            let tc=chain(f(payload,"transport_chain")?)?;let bc=chain(f(payload,"biometric_chain")?)?;
            let a=verifier.verify(AttestationRequest{chain:&tc,expected_key:&keys.transport,challenge:binding.challenge(0)?,biometric:false,now})?;
            let bvalid=verifier.verify(AttestationRequest{chain:&bc,expected_key:&keys.biometric,challenge:binding.challenge(1)?,biometric:true,now})?;
            let(now,mono)=clock()?; self.expire(now,mono)?;
            let validity=checked_validity(a,bvalid,now)?;
            let mut cleanup:Vec<Hash>=chain(f(payload,"cleanup_tokens")?)?.iter().map(|x|digest(x)).collect();
            cleanup.sort_unstable(); cleanup.dedup();
            // Every submitted token must identify a retained same-host record.
            // Already revoked records are valid idempotent cleanup, but only
            // active replacements need to be displayed as new revocations.
            let mut matched=Vec::new(); let mut replaces=Vec::new();
            for token in cleanup {
                let old:Option<(Vec<u8>,bool)>=self.store.db.query_row("SELECT id,revoked_at IS NULL FROM credentials WHERE token_hash=?",[&token[..]],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
                let (old,active)=old.ok_or(Error::Denied)?;
                matched.push(token); if active { replaces.push(as_id(old)?); }
            }
            let checked=Checked{transport_chain:invalid(v2_wire::encode_payload(&V::map([("chain",f(payload,"transport_chain")?.clone())])))?,biometric_chain:invalid(v2_wire::encode_payload(&V::map([("chain",f(payload,"biometric_chain")?.clone())])))?,validity,cleanup:matched,replaces:replaces.clone()};
            let context_hash=invalid(m::hash(Domain::EnrollContext,&binding.context(&keys)?))?;
            let approval=EnrollmentApproval{enrollment:binding.id,context_hash,host_cert:binding.tls.host_cert,provisional_client_cert:binding.tls.provisional_client_cert,host_key_hash:digest(&binding.tls.host_key),provisional_client_key_hash:digest(&binding.tls.provisional_client_key),transport_key_hash:digest(&keys.transport),biometric_key_hash:digest(&keys.biometric),replaces};
            self.pairing_on(conn)?.enrollment=Some(Stage::Approval{binding,keys,checked,context_hash});Ok(approval)
        })();if result.is_err(){self.deny_connection(conn);}result
    }
    /// Only the owning local adapter may authorize this exact displayed context.
    /// Initial grant is explicit; no inherited grants.
    pub fn enrollment_approve(&mut self,owner:Id,conn:ConnectionId,approved:Hash,approved_replacements:&[Id],initial_cli:bool,now:i64,mono:Instant)->Result<Message>{
        self.enrollment_step(conn,now,mono,|s|{
            let caller=s.pairing_on(conn)?.caller.clone();
            if !s.store.principal_matches(&caller)? {return Err(Error::Denied)}
            let p=s.pairing_on(conn)?; if p.owner!=owner{return Err(Error::Denied)}
            let Some(Stage::Approval{binding,keys,checked,context_hash})=p.enrollment.take() else{return Err(Error::Denied)};
            if !bool::from(context_hash.ct_eq(&approved))||approved_replacements!=checked.replaces.as_slice()||checked.validity.assurance_until<=now||checked.validity.status_until<=now{return Err(Error::Denied)}
            let token=Zeroizing::new(random_hash()?);let receipt=Zeroizing::new(random_hash()?);
            if *token==*receipt{return Err(Error::State)}
            let grants=if initial_cli{vec![V::map([("credential_id",b(keys.credential)),("approver",b(p.caller.id)),("target",b(p.caller.id)),("scope",V::map([("purpose",V::text("authenticate")),("service",V::text("rba")),("operation",V::text("authenticate"))]))])]}else{vec![]};
            let offer=msg(Kind::EnrollOffer,[("enrollment_id",b(binding.id)),("credential_id",b(keys.credential)),("grants",V::Array(grants)),("revision",V::Uint(1)),("token",b(*token)),("receipt",b(*receipt))])?;
            let offer_hash=invalid(m::hash(Domain::EnrollOffer,offer.payload()))?;
            p.enrollment=Some(Stage::Staged{keys,checked,offer_hash,receipt,token_hash:digest(&*token),initial_cli});Ok(offer)
        })
    }
    pub fn enrollment_staged(&mut self,conn:ConnectionId,message:&Message,mut clock:impl FnMut()->Result<(i64,Instant)>)->Result<Message>{
        let result=(||{
            let(now,mono)=clock()?;self.expire(now,mono)?;
            let p=self.pairing_on(conn)?;let Some(Stage::Staged{keys,checked,offer_hash,receipt,token_hash,initial_cli})=p.enrollment.take() else{return Err(Error::Denied)};
            let payload=exact(message,Kind::EnrollStaged,p.id)?;
            if !bool::from(offer_hash.ct_eq(&fixed::<32>(payload,"offer_hash")?)){return Err(Error::Denied)}
            let(owner,id,principal,deadline,wall)=(p.owner,p.id,p.caller.id,p.expires_mono,p.expires_wall);
            let v=checked.validity;
            let e=Enrollment{id,credential:keys.credential,owner:principal,transport_key:&keys.transport,biometric_key:&keys.biometric,transport_chain:&checked.transport_chain,biometric_chain:&checked.biometric_chain,attested_at:v.attested_at,assurance_until:v.assurance_until,status_checked_at:v.status_checked_at,status_until:v.status_until,token_hash,receipt_hash:digest(&*receipt),offer_hash,initial_cli_grant:initial_cli,cleanup_tokens:&checked.cleanup};
            let reply=msg(Kind::EnrollReceipt,[("enrollment_id",b(id)),("receipt",b(*receipt)),("offer_hash",b(offer_hash))])?;
            self.commit_enrollment(owner,conn,&e,now,mono)?;
            let(after,elapsed)=clock()?;
            // A late commit is durable but the device must recover the receipt
            // on a fresh production channel; never claim uncommitted success.
            if after<now||elapsed<mono||after>=wall||elapsed>=deadline{return Err(Error::Clock)} self.trust_check(after,elapsed)?; self.arm_terminal(conn,keys.credential,Some(owner),&reply,after,elapsed,Some((wall,deadline)))?; Ok(reply)
        })();if result.is_err(){self.deny_connection(conn);}result
    }
    pub fn enrollment_cancel(&mut self,conn:ConnectionId,message:&Message,now:i64,mono:Instant)->Result<()> {
        self.enrollment_step(conn,now,mono,|s|{let p=s.pairing_on(conn)?;exact(message,Kind::EnrollCancel,p.id)?;s.abort_pairing();Ok(())})
    }
    /// Restricted, one-shot receipt recovery on an authenticated production
    /// peer. Wrong receipts and unknown/revoked records receive generic denial.
    pub fn enrollment_status(&mut self,conn:ConnectionId,message:&Message,now:i64,mono:Instant)->Result<Message>{
        let result=(||{
            self.expire(now,mono)?;let p=self.peers.get_mut(&conn).ok_or(Error::Denied)?;
            if p.used||p.access!=PeerState::Active{return Err(Error::Denied)}p.used=true;
            if message.kind()!=Kind::EnrollStatus||fixed::<16>(message.payload(),"session_id")?!=p.peer.session{return Err(Error::Denied)}
            let id=fixed(message.payload(),"enrollment_id")?;let receipt=fixed(message.payload(),"receipt")?;
            self.store.enrollment_status(id,p.peer.credential,&p.peer.key,&receipt,now)?.ok_or(Error::Denied)?;
            let reply=msg(Kind::EnrollStatusResult,[("session_id",b(p.peer.session)),("enrollment_id",b(id)),("state",V::Uint(1)),("receipt",b(receipt))])?;
            Ok((reply,p.peer.credential))
        })();self.deny_connection(conn);
        let (reply,credential)=result?;
        self.arm_terminal(conn,credential,None,&reply,now,mono,None)?;Ok(reply)
    }
}

#[cfg(any(test, fuzzing))]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use std::net::IpAddr;
    const NOW:i64=1000;
    fn id(n:u8)->Id{[n;16]}
    fn signer(n:u8)->SigningKey{let mut k=[0;32];k[31]=n;SigningKey::from_slice(&k).unwrap()}
    fn key(n:u8)->[u8;65]{signer(n).verifying_key().to_encoded_point(false).as_bytes().try_into().unwrap()}
    fn principal()->Principal{Principal{id:id(1),uid:1000,name:"user".into(),generation:id(2)}}
    fn tls()->EnrollmentChannel{EnrollmentChannel{channel:[3;32],host_cert:[8;32],provisional_client_cert:[9;32],host_key:key(3),provisional_client_key:key(4)}}
    fn ready()->Authority{
        let db=Connection::open_in_memory().unwrap();configure(&db,true).unwrap();db.execute_batch(SCHEMA).unwrap();db.execute("INSERT INTO host_meta VALUES(1,?,?)",params![&id(3)[..],NOW]).unwrap();
        let mut store=Store{db,_lock:None};store.add_principal(&principal(),NOW).unwrap();Authority::new(store)
    }
    struct Harness{a:Authority,t:Instant,c:ConnectionId,owner:Id,binding:Binding,keys:Keys}
    impl Harness{
        fn new(direction:EntryDirection)->(Self,EnrollmentStart){
            let mut a=ready();let t=Instant::now();let owner=id(40);
            let e=a.begin_pairing(owner,principal(),NOW,t).unwrap();
            let c=a.connect(IpAddr::from([10,0,0,1]),Carrier::Tcp,Listener::Enrollment,t).unwrap();a.handshake_complete(c,t).unwrap();a.classify_enrollment(c,NOW,t).unwrap();
            let start=a.enrollment_start(owner,c,direction,tls(),NOW,t).unwrap();
            let binding=Binding{id:e,host:id(3),nonce:fixed(start.message.payload(),"nonce").unwrap(),expiry:NOW+120,direction,tls:tls()};
            let keys=Keys{credential:id(4),transport:key(1),biometric:key(2)};
            (Self{a,t,c,owner,binding,keys},start)
        }
        fn share(&mut self,start:&EnrollmentStart,wrong:bool,wrong_context:bool)->(Message,rba_enrollment::DeviceExchange){
            let mut code=start.display_code.as_ref().map(|x|**x).unwrap_or(*b"004827");
            if wrong{code[0]=if code[0]==b'0'{b'1'}else{b'0'};}
            let mut bound=self.binding.clone();if wrong_context{bound.tls.channel[0]^=1;}
            let aad=m::transcript(Domain::EnrollContext,&bound.context(&self.keys).unwrap()).unwrap();
            let mut rng=rand_core_10::UnwrapErr(getrandom_04::SysRng);
            let (share,d)=rba_enrollment::start_device_v2(PairingCode::parse(&code).unwrap(),&bound.host,&self.keys.credential,&aad,&mut rng).unwrap();
            let share=msg(Kind::EnrollShare,[("enrollment_id",b(self.binding.id)),("credential_id",b(self.keys.credential)),("transport_key",b(self.keys.transport)),("biometric_key",b(self.keys.biometric)),("share",b(share))]).unwrap();
            let entered=if self.binding.direction==EntryDirection::HostTypes{Some(PairingCode::parse(b"004827").unwrap())}else{None};
            (self.a.enrollment_share(self.owner,self.c,&share,entered,NOW,self.t).unwrap(),d)
        }
        fn confirm(&mut self,start:&EnrollmentStart){
            let (a,d)=self.share(start,false,false);
            let tag=rba_enrollment::finish_device(d,bytes(a.payload(),"share").unwrap(),bytes(a.payload(),"confirmation").unwrap()).unwrap();
            let confirm=msg(Kind::EnrollConfirmB,[("enrollment_id",b(self.binding.id)),("confirmation",b(tag))]).unwrap();
            self.a.enrollment_confirm(self.c,&confirm,NOW,self.t).unwrap();
        }
        fn evidence(&self,wrong:bool)->Message{
            let transport:Signature=signer(1).sign(&m::transcript(Domain::EnrollKeyProof,&self.binding.proof(&self.keys,0)).unwrap());
            let biometric:Signature=signer(if wrong{1}else{2}).sign(&m::transcript(Domain::EnrollKeyProof,&self.binding.proof(&self.keys,1)).unwrap());
            msg(Kind::EnrollEvidence,[("enrollment_id",b(self.binding.id)),("transport_chain",V::Array(vec![b([1])])),("biometric_chain",V::Array(vec![b([2])])),("transport_proof",b(transport.to_bytes())),("biometric_proof",b(biometric.to_bytes())),("cleanup_tokens",V::Array(vec![]))]).unwrap()
        }
        fn approval(&mut self,start:&EnrollmentStart)->EnrollmentApproval{
            self.confirm(start);let evidence=self.evidence(false);let mut v=Verifier{binding:self.binding.clone(),count:0,deny:false};let t=self.t;
            let a=self.a.enrollment_evidence_with(self.c,&evidence,&mut v,||Ok((NOW,t))).unwrap();assert_eq!(v.count,2);a
        }
        fn offer(&mut self,start:&EnrollmentStart,initial:bool)->Message{let approval=self.approval(start);self.a.enrollment_approve(self.owner,self.c,approval.context_hash,&approval.replaces,initial,NOW,self.t).unwrap()}
        fn staged(&self,offer:&Message)->Message{msg(Kind::EnrollStaged,[("enrollment_id",b(self.binding.id)),("offer_hash",b(m::hash(Domain::EnrollOffer,offer.payload()).unwrap()))]).unwrap()}
        fn assert_absent(&self){assert_eq!(self.a.store().peer_state(&self.keys.transport,&self.keys.credential,NOW).unwrap(),PeerState::Unknown);}
    }
    // Test-only verifier checks the exact role/challenge/key supplied by the
    // state machine. Does NOT claim certificate/attestation verification.
    struct Verifier{binding:Binding,count:usize,deny:bool}
    impl AttestationVerifier for Verifier{
        fn verify(&mut self,r:AttestationRequest<'_>)->Result<AttestationValidity>{
            self.count+=1;let role=if r.biometric {1u64}else{0u64};
            assert_eq!(r.challenge,self.binding.challenge(role).unwrap());assert_eq!(*r.expected_key,key(role as u8+1));assert_eq!(r.chain,&[vec![role as u8+1]]);assert_eq!(r.now,NOW);
            if self.deny{return Err(Error::Denied)}
            Ok(AttestationValidity{attested_at:NOW,assurance_until:NOW+86400,status_checked_at:NOW,status_until:NOW+3600})
        }
    }
    pub(super) fn trace(data:&[u8]) {
        let at=|i:usize|data.get(i).copied().unwrap_or(0);
        let direction=if at(0)&1==0{EntryDirection::DeviceTypes}else{EntryDirection::HostTypes};
        let fault=at(1)%8;
        let(mut h,start)=Harness::new(direction);let t=h.t;
        if fault==1||fault==2 {
            let(a,d)=h.share(&start,fault==1,fault==2);
            assert!(rba_enrollment::finish_device(d,bytes(a.payload(),"share").unwrap(),bytes(a.payload(),"confirmation").unwrap()).is_err());
            let bad=msg(Kind::EnrollConfirmB,[("enrollment_id",b(h.binding.id)),("confirmation",b([0;32]))]).unwrap();
            assert!(h.a.enrollment_confirm(h.c,&bad,NOW,t).is_err());h.assert_absent();
            return;
        }
        h.confirm(&start);
        let e=h.evidence(fault==3);
        let mut verifier=Verifier{binding:h.binding.clone(),count:0,deny:fault==4};
        let a=h.a.enrollment_evidence_with(h.c,&e,&mut verifier,||Ok((NOW,t)));
        if fault==3||fault==4 {assert!(a.is_err());h.assert_absent();return;}
        let a=a.unwrap();assert_eq!(verifier.count,2);
        let offer=h.a.enrollment_approve(h.owner,h.c,a.context_hash,&a.replaces,true,NOW,t).unwrap();
        h.assert_absent();let good=h.staged(&offer);
        let bad=msg(Kind::EnrollStaged,[("enrollment_id",b(h.binding.id)),("offer_hash",b([0;32]))]).unwrap();
        let result=match fault {
            5=>h.a.enrollment_staged(h.c,&bad,||Ok((NOW,t))),
            6=>{assert!(h.a.cancel_pairing_local(h.owner,h.binding.id));h.a.enrollment_staged(h.c,&good,||Ok((NOW,t)))},
            7=>h.a.enrollment_staged(h.c,&good,||Ok((NOW+120,t+Duration::from_secs(120)))),
            _=>h.a.enrollment_staged(h.c,&good,||Ok((NOW,t))),
        };
        assert_eq!(result.is_ok(),fault==0);
        if fault==0 {assert_eq!(result.unwrap().kind(),Kind::EnrollReceipt);assert_eq!(h.a.store().peer_state(&h.keys.transport,&h.keys.credential,NOW).unwrap(),PeerState::Active);}else{h.assert_absent();}
        for &op in data.get(2..).unwrap_or_default().iter().take(32){match op%3{0=>assert!(h.a.enrollment_staged(h.c,&good,||Ok((NOW,t))).is_err()),1=>assert!(!h.a.cancel_pairing_local(h.owner,h.binding.id)),_=>h.a.close(h.c)}}
        assert!(h.a.enrollment_staged(h.c,&good,||Ok((NOW,t))).is_err());
        let commits=h.a.store().read_audit(256).unwrap().iter().filter(|e|e.kind=="enroll").count();
        assert_eq!(commits,if fault==0{1}else{0});
    }
    #[test] fn state_trace_enrollment_seeds(){for direction in 0..2{for fault in 0..8{trace(&[direction,fault,0,1,2,0]);}}}
    #[test]
    fn v2_enrollment_both_directions_and_receipt_recovery(){
        for direction in [EntryDirection::DeviceTypes,EntryDirection::HostTypes]{
            let (mut h,start)=Harness::new(direction);assert_eq!(start.display_code.is_some(),direction==EntryDirection::DeviceTypes);
            let offer=h.offer(&start,true);h.assert_absent();let staged=h.staged(&offer);let t=h.t;
            let receipt=h.a.enrollment_staged(h.c,&staged,||Ok((NOW,t))).unwrap();assert_eq!(receipt.kind(),Kind::EnrollReceipt);assert_eq!(bytes(receipt.payload(),"receipt").unwrap(),bytes(offer.payload(),"receipt").unwrap());
            assert!(h.a.connection_denied(h.c));let(frame,_)=h.a.claim_terminal(h.c,NOW,t).unwrap();assert_eq!(frame.as_slice(),receipt.encode().unwrap().as_slice());
            assert_eq!(h.a.store().policy(h.keys.credential).unwrap().1,vec![Grant{approver:id(1),target:id(1),scope:Scope::Cli}]);
            assert!(h.a.enrollment_staged(h.c,&staged,||Ok((NOW,t))).is_err());h.a.close(h.c);
            let c=h.a.connect(IpAddr::from([10,0,0,1]),Carrier::Tcp,Listener::Production,t).unwrap();h.a.handshake_complete(c,t).unwrap();
            let peer=Peer{credential:h.keys.credential,key:h.keys.transport,session:id(8),channel:[6;32],host_nonce:[7;32],device_nonce:[8;32]};h.a.classify_production(c,peer,NOW,t).unwrap();
            let status=msg(Kind::EnrollStatus,[("session_id",b(id(8))),("enrollment_id",b(h.binding.id)),("receipt",b(bytes(offer.payload(),"receipt").unwrap()))]).unwrap();
            let answer=h.a.enrollment_status(c,&status,NOW,t).unwrap();assert_eq!(answer.kind(),Kind::EnrollStatusResult);assert_eq!(bytes(answer.payload(),"receipt").unwrap(),bytes(offer.payload(),"receipt").unwrap());
            let(frame,_)=h.a.claim_terminal(c,NOW,t).unwrap();assert_eq!(frame.as_slice(),answer.encode().unwrap().as_slice());assert!(h.a.enrollment_status(c,&status,NOW,t).is_err());assert!(!h.a.terminal_writing(c,NOW,t));
        }
    }
    #[test]
    fn v2_enrollment_wrong_code_or_channel_does_not_confirm(){
        for (wrong,context) in [(true,false),(false,true)]{
            let (mut h,start)=Harness::new(EntryDirection::DeviceTypes);let (a,d)=h.share(&start,wrong,context);
            assert!(rba_enrollment::finish_device(d,bytes(a.payload(),"share").unwrap(),bytes(a.payload(),"confirmation").unwrap()).is_err());
            let bad=msg(Kind::EnrollConfirmB,[("enrollment_id",b(h.binding.id)),("confirmation",b([0;32]))]).unwrap();
            assert!(h.a.enrollment_confirm(h.c,&bad,NOW,h.t).is_err());assert!(h.a.connection_denied(h.c));h.assert_absent();
        }
    }
    #[test]
    fn v2_enrollment_attestation_and_role_proof_are_mandatory(){
        for wrong in [true,false]{
            let(mut h,start)=Harness::new(EntryDirection::DeviceTypes);h.confirm(&start);let e=h.evidence(wrong);let mut verifier=Verifier{binding:h.binding.clone(),count:0,deny:true};let t=h.t;
            assert!(h.a.enrollment_evidence_with(h.c,&e,&mut verifier,||Ok((NOW,t))).is_err());assert_eq!(verifier.count,if wrong{0}else{1});h.assert_absent();assert!(h.a.connection_denied(h.c));
        }
    }
    #[test]
    fn v2_enrollment_out_of_order_and_wrong_offer_never_commit(){
        let(mut h,start)=Harness::new(EntryDirection::HostTypes);let t=h.t;let offer=h.offer(&start,false);
        let bad=msg(Kind::EnrollStaged,[("enrollment_id",b(h.binding.id)),("offer_hash",b([0;32]))]).unwrap();
        assert!(h.a.enrollment_staged(h.c,&bad,||Ok((NOW,t))).is_err());let staged=h.staged(&offer);assert!(h.a.enrollment_staged(h.c,&staged,||Ok((NOW,t))).is_err());h.assert_absent();
        let(mut h,_)=Harness::new(EntryDirection::DeviceTypes);let t=h.t;let bad=msg(Kind::EnrollStaged,[("enrollment_id",b(h.binding.id)),("offer_hash",b([1;32]))]).unwrap();assert!(h.a.enrollment_staged(h.c,&bad,||Ok((NOW,t))).is_err());h.assert_absent();
    }
    #[test]
    fn v2_enrollment_commit_rollback_and_expiry(){
        let(mut h,start)=Harness::new(EntryDirection::DeviceTypes);let offer=h.offer(&start,true);let staged=h.staged(&offer);let t=h.t;
        h.a.store().db.execute_batch("CREATE TRIGGER fail_enroll BEFORE INSERT ON audit_outbox WHEN NEW.kind='enroll' BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
        assert!(h.a.enrollment_staged(h.c,&staged,||Ok((NOW,t))).is_err());h.assert_absent();
        let(mut h,start)=Harness::new(EntryDirection::HostTypes);let offer=h.offer(&start,false);let staged=h.staged(&offer);let t=h.t+Duration::from_secs(120);
        assert!(h.a.enrollment_staged(h.c,&staged,||Ok((NOW+120,t))).is_err());h.assert_absent();
    }
    #[test]
    fn v2_enrollment_context_matches_independent_fixture(){
        let keys=Keys{credential:id(4),transport:key(1),biometric:key(2)};
        for (i,row) in include_str!("../../../../../protocol/test-vectors/v2-enrollment-context.tsv").lines().filter(|l|!l.starts_with('#')).enumerate(){
            let f:Vec<_>=row.split('\t').collect();let binding=Binding{id:id(5),host:id(3),nonce:[5;32],expiry:220,direction:if i==0{EntryDirection::DeviceTypes}else{EntryDirection::HostTypes},tls:tls()};
            assert_eq!(hex::encode(m::transcript(Domain::EnrollContext,&binding.context(&keys).unwrap()).unwrap()),f[1]);
            assert_eq!(hex::encode(m::hash(Domain::EnrollContext,&binding.context(&keys).unwrap()).unwrap()),f[2]);
            assert_eq!(hex::encode(binding.challenge(0).unwrap()),f[3]);assert_eq!(hex::encode(binding.challenge(1).unwrap()),f[4]);
        }
    }
}

#[cfg(fuzzing)]
pub(in crate::v2_store) fn trace_enrollment(data:&[u8]) { tests::trace(data); }
