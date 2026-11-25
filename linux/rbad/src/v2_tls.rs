//! V2 TCP TLS primitive. Production pins come from the local Authority, not the
//! network. Enrollment TLS is intentionally provisional and is never an auth
//! transport. TLS CertificateVerify is mandatory even for provisional peers.
use crate::v2_store::{authority::{Authority,Carrier,ConnectionId,Listener,Peer,EnrollmentChannel}, Error, Hash, Id, PeerState, Result};
use openssl::{asn1::Asn1Time, bn::BigNumContext, ec::PointConversionForm, nid::Nid, x509::X509};
use rustls::{pki_types::{CertificateDer, PrivateKeyDer, UnixTime}, server::danger::{ClientCertVerified, ClientCertVerifier}, client::danger::HandshakeSignatureValid, DigitallySignedStruct, DistinguishedName, SignatureScheme};
use sha2::{Digest,Sha256};
use std::{collections::BTreeMap, io, pin::Pin, sync::{Arc,Mutex}, task::{Context,Poll}, time::{Duration,Instant,SystemTime,UNIX_EPOCH}};
use tokio::{io::{AsyncRead,AsyncWrite,AsyncReadExt,AsyncWriteExt,ReadBuf},net::TcpStream,time::timeout_at};
use rba_protocol::{cbor::Value as V,v2_message::{Kind,Message},v2_wire};

pub(crate) mod dispatch;
pub mod candidate;


const EXPORTER: &[u8] = b"EXPORTER-Channel-Binding";
const FRAME_TIME: Duration = Duration::from_secs(5);
const MAX_PRECLASS: usize = 256*1024;
const MAX_CERT: usize = 8192;
const MAX_TERMINAL_TLS_BYTES: usize = 16*1024;
fn reject() -> rustls::Error { rustls::Error::General("V2 peer rejected".into()) }
fn io_denied() -> io::Error { io::Error::new(io::ErrorKind::PermissionDenied,"V2 connection rejected") }
fn wall() -> Result<i64> { SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|Error::Clock)?.as_secs().try_into().map_err(|_|Error::Clock) }
fn alpn(mode:Listener)->&'static [u8] {match mode{Listener::Production=>b"rba/2",Listener::Enrollment=>b"rba-enroll/2"}}
fn hash(x:&[u8])->Hash{Sha256::digest(x).into()}
fn point_cert(der:&[u8], now:i64, self_signed:bool)->Option<[u8;65]>{
    if der.is_empty()||der.len()>MAX_CERT{return None}
    let cert=X509::from_der(der).ok()?;
    if cert.to_der().ok()?.as_slice()!=der{return None}
    let time=Asn1Time::from_unix(now).ok()?;
    if cert.not_before().compare(&time).ok()?.is_gt()||!cert.not_after().compare(&time).ok()?.is_gt(){return None}
    let key=cert.public_key().ok()?; let ec=key.ec_key().ok()?;
    if ec.group().curve_name()!=Some(Nid::X9_62_PRIME256V1)||ec.check_key().is_err(){return None}
    if self_signed && (cert.subject_name().to_der().ok()?!=cert.issuer_name().to_der().ok()?||!cert.verify(&key).ok()?){return None}
    let mut ctx=BigNumContext::new().ok()?;
    ec.public_key().to_bytes(ec.group(),PointConversionForm::UNCOMPRESSED,&mut ctx).ok()?.try_into().ok()
}
// The enrolled certificate is only a public-key carrier: the exact pin and
// current attestation/registry policy confer trust, not its issuer. Send only
// a leaf in TLS; complete attestation chains are exchanged during enrollment.
#[derive(Debug)]
struct ClientVerifier { mode:Listener, pins:BTreeMap<[u8;65],Id> }
impl ClientCertVerifier for ClientVerifier {
    fn root_hint_subjects(&self)->&[DistinguishedName]{&[]}
    fn verify_client_cert(&self,end:&CertificateDer<'_>,intermediate:&[CertificateDer<'_>],now:UnixTime)->std::result::Result<ClientCertVerified,rustls::Error>{
        if !intermediate.is_empty(){return Err(reject())}
        let p=point_cert(end.as_ref(),now.as_secs().try_into().map_err(|_|reject())?,self.mode==Listener::Enrollment).ok_or_else(reject)?;
        if self.mode==Listener::Production&&!self.pins.contains_key(&p){return Err(reject())}
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(&self,_:&[u8],_:&CertificateDer<'_>,_:&DigitallySignedStruct)->std::result::Result<HandshakeSignatureValid,rustls::Error>{Err(reject())}
    fn verify_tls13_signature(&self,message:&[u8],cert:&CertificateDer<'_>,sig:&DigitallySignedStruct)->std::result::Result<HandshakeSignatureValid,rustls::Error>{
        if sig.scheme!=SignatureScheme::ECDSA_NISTP256_SHA256{return Err(reject())}
        rustls::crypto::verify_tls13_signature(message,cert,sig,&rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self)->Vec<SignatureScheme>{vec![SignatureScheme::ECDSA_NISTP256_SHA256]}
}
/// Host identity must be the same P-256 key used to sign V2 AUTH_REQUEST and
/// MATCHED. The caller owns private state provisioning; no second TLS key.
pub struct Identity { cert:CertificateDer<'static>,key:PrivateKeyDer<'static>,point:[u8;65] }
impl Identity {
    pub fn new(cert:CertificateDer<'static>,key:PrivateKeyDer<'static>,expected:[u8;65])->Result<Self>{
        if point_cert(cert.as_ref(),wall()?,true)!=Some(expected){return Err(Error::Denied)}
        // rustls validates certificate/private-key agreement while building config.
        Ok(Self{cert,key,point:expected})
    }
    fn config(&self,mode:Listener,pins:BTreeMap<[u8;65],Id>)->Result<rustls::ServerConfig>{
        if mode==Listener::Enrollment&&!pins.is_empty(){return Err(Error::Invalid)}
        let mut cfg=rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13]).map_err(|_|Error::State)?
            .with_client_cert_verifier(Arc::new(ClientVerifier{mode,pins}))
            .with_single_cert(vec![self.cert.clone()],self.key.clone_key()).map_err(|_|Error::State)?;
        cfg.alpn_protocols=vec![alpn(mode).to_vec()];
        cfg.send_tls13_tickets=0;cfg.max_early_data_size=0;
        cfg.session_storage=Arc::new(rustls::server::NoServerSessionStorage{});
        Ok(cfg)
    }
}
pub type Owner=Arc<Mutex<Authority>>;
// Socket is dropped before the authority releases the slot, including future
// cancellation or handshake error. The count covers both directions before
// classification. Each async TLS/read/write operation has its own deadline.
struct Charged { socket:Option<TcpStream>,owner:Owner,id:ConnectionId,preclass:bool,bytes:usize,terminal:bool,terminal_bytes:usize }
impl Charged {
    fn charge(&mut self,n:usize)->io::Result<()> {
        if self.terminal{return Err(io_denied())}
        let mut a=self.owner.lock().map_err(|_|io_denied())?;
        if a.connection_denied(self.id){return Err(io_denied())}
        if self.preclass{
            self.bytes=self.bytes.checked_add(n).ok_or_else(io_denied)?;
            if self.bytes>MAX_PRECLASS{return Err(io_denied())}
            a.preclass_bytes(self.id,n,Instant::now()).map_err(|_|io_denied())?;
        } Ok(())
    }
}
impl Drop for Charged {fn drop(&mut self){drop(self.socket.take());if let Ok(mut a)=self.owner.lock(){a.close(self.id)}}}
impl AsyncRead for Charged {
    fn poll_read(mut self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&mut ReadBuf<'_>)->Poll<io::Result<()>>{
        if let Err(e)=self.charge(0){return Poll::Ready(Err(e))}
        if buf.remaining()==0{return Poll::Ready(Ok(()))}
        let mut temp=[0u8;8192];
        let limit=if self.preclass{MAX_PRECLASS-self.bytes}else{temp.len()};
        let n=limit.min(temp.len()).min(buf.remaining());
        if n==0{return Poll::Ready(Err(io_denied()))}
        let mut chunk=ReadBuf::new(&mut temp[..n]);
        let Some(socket)=self.socket.as_mut() else{return Poll::Ready(Err(io_denied()))};
        match Pin::new(socket).poll_read(cx,&mut chunk){
            Poll::Ready(Ok(()))=>{if let Err(e)=self.charge(chunk.filled().len()){return Poll::Ready(Err(e))}buf.put_slice(chunk.filled());Poll::Ready(Ok(()))},other=>other}
    }
}
impl AsyncWrite for Charged {
    fn poll_write(mut self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&[u8])->Poll<io::Result<usize>>{
        if self.terminal {
            // Hold the serialized authority during this *nonblocking* poll,
            // never across an await. Revocation cannot race the socket check.
            let owner=self.owner.clone();
            let Ok(a)=owner.lock() else{return Poll::Ready(Err(io_denied()))};
            let Ok(now)=wall() else{return Poll::Ready(Err(io_denied()))};
            if !a.terminal_writing(self.id,now,Instant::now()){return Poll::Ready(Err(io_denied()))}
            if buf.is_empty(){return Poll::Ready(Ok(0))}
            let n=(MAX_TERMINAL_TLS_BYTES-self.terminal_bytes).min(buf.len());
            if n==0{return Poll::Ready(Err(io_denied()))}
            let Some(socket)=self.socket.as_mut() else{return Poll::Ready(Err(io_denied()))};
            let result=Pin::new(socket).poll_write(cx,&buf[..n]);
            if let Poll::Ready(Ok(written))=&result{self.terminal_bytes+=*written;}
            return result
        }
        if let Err(e)=self.charge(0){return Poll::Ready(Err(e))}
        if buf.is_empty(){return Poll::Ready(Ok(0))}
        let n=if self.preclass{(MAX_PRECLASS-self.bytes).min(buf.len())}else{buf.len()};
        if n==0{return Poll::Ready(Err(io_denied()))}
        let Some(socket)=self.socket.as_mut() else{return Poll::Ready(Err(io_denied()))};
        match Pin::new(socket).poll_write(cx,&buf[..n]){Poll::Ready(Ok(n))=>Poll::Ready(self.charge(n).map(|_|n)),other=>other}
    }
    fn poll_flush(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>>{
        if self.terminal {
            let owner=self.owner.clone();
            let Ok(a)=owner.lock() else{return Poll::Ready(Err(io_denied()))};
            let Ok(now)=wall() else{return Poll::Ready(Err(io_denied()))};
            if !a.terminal_writing(self.id,now,Instant::now()){return Poll::Ready(Err(io_denied()))}
            return match self.socket.as_mut(){Some(s)=>Pin::new(s).poll_flush(cx),None=>Poll::Ready(Err(io_denied()))}
        }
        if let Err(e)=self.charge(0){return Poll::Ready(Err(e))}
        match self.socket.as_mut(){Some(s)=>Pin::new(s).poll_flush(cx),None=>Poll::Ready(Err(io_denied()))}
    }
    fn poll_shutdown(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>>{match self.socket.as_mut(){Some(s)=>Pin::new(s).poll_shutdown(cx),None=>Poll::Ready(Ok(()))}}
}
/// A channel is returned only after mutual TLS and production HELLO or
/// provisional enrollment classification. Drop closes its own connection.
/// The protected HELLO_ACK selects exactly one local operation class. It is
/// routing information, never authorization to initiate a host operation.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum Purpose { Authentication, Policy, Recovery, Revocation }
impl Purpose {
    fn parse(v:&V)->Result<Self>{match v.get("purpose") {
        Some(V::Uint(0))=>Ok(Self::Authentication),Some(V::Uint(1))=>Ok(Self::Policy),
        Some(V::Uint(2))=>Ok(Self::Recovery),Some(V::Uint(3))=>Ok(Self::Revocation),_=>Err(Error::Denied)
    }}
    fn permitted(self,access:PeerState)->bool{match access{
        PeerState::Active=>true,PeerState::RevocationOnly=>self==Self::Revocation,PeerState::Unknown=>false
    }}
    fn inbound(self,k:Kind)->bool{use Kind::*;match self{
        Self::Authentication=>matches!(k,NumberEntry|AuthResponse|Cancel),Self::Policy=>k==PolicyDecision,
        Self::Recovery=>k==EnrollStatus,Self::Revocation=>k==Revoke
    }}
    fn outbound(self,k:Kind)->bool{use Kind::*;match self{
        Self::Authentication=>matches!(k,AuthRequest|Matched|Cancel),Self::Policy=>k==PolicyOffer,
        Self::Recovery|Self::Revocation=>false
    }}
}
pub struct Channel { stream:tokio_rustls::server::TlsStream<Charged>, mode:Listener, binding:EnrollmentChannel, credential:Option<Id>, access:Option<PeerState>,purpose:Option<Purpose>,busy:bool }
impl Channel {
    pub fn id(&self)->ConnectionId{self.stream.get_ref().0.id}
    pub fn credential(&self)->Option<Id>{self.credential}
    pub(crate) fn purpose(&self)->Option<Purpose>{self.purpose}
    pub fn exporter(&self)->Hash{self.binding.channel}
    pub fn enrollment_binding(&self)->Result<EnrollmentChannel>{if self.mode!=Listener::Enrollment{return Err(Error::Denied)}Ok(self.binding.clone())}
    fn start_io(&mut self)->Result<()> {
        if self.busy||self.stream.get_ref().0.socket.is_none()||self.stream.get_mut().0.charge(0).is_err(){self.deny();return Err(Error::Denied)}
        self.busy=true;Ok(())
    }
    fn allow_in(&self,k:Kind)->bool {
        use Kind::*;
        match (self.mode,self.access){
            (Listener::Enrollment,_)=>matches!(k,EnrollShare|EnrollConfirmB|EnrollEvidence|EnrollStaged|EnrollCancel),
            (Listener::Production,None)=>k==HelloAck,
            (Listener::Production,Some(access))=>self.purpose.is_some_and(|p|p.permitted(access)&&p.inbound(k)),
            _=>false,
        }
    }
    fn allow_out(&self,k:Kind)->bool {
        use Kind::*;
        match (self.mode,self.access){
            (Listener::Enrollment,_)=>matches!(k,EnrollStart|EnrollConfirmA|EnrollOffer|EnrollCancel),
            (Listener::Production,None)=>k==Hello,
            (Listener::Production,Some(access))=>self.purpose.is_some_and(|p|p.permitted(access)&&p.outbound(k)),
            _=>false,
        }
    }
    pub async fn read(&mut self)->Result<Message>{
        self.read_until(tokio::time::Instant::now()+Duration::from_secs(30)).await
    }
    /// A human wait may use the owned operation deadline, not a refreshed
    /// timeout. Once the first byte arrives the entire frame has five seconds.
    pub async fn read_until(&mut self,deadline:tokio::time::Instant)->Result<Message>{
        self.start_io()?;
        let res=async{
            let mut header=[0u8;13];
            timeout_at(deadline,self.stream.read_exact(&mut header[..1])).await.map_err(|_|io_denied())??;
            let end=deadline.min(tokio::time::Instant::now()+FRAME_TIME);
            timeout_at(end,async{
                self.stream.read_exact(&mut header[1..]).await?;
                let h=v2_wire::parse_header(&header).map_err(|_|io_denied())?;
                let mut payload=vec![0;h.payload_len];self.stream.read_exact(&mut payload).await?;
                let v=v2_wire::decode_payload(&payload).map_err(|_|io_denied())?;
                Message::new(Kind::from_code(h.message_type).map_err(|_|io_denied())?,v).map_err(|_|io_denied())
            }).await.map_err(|_|io_denied())?
        }.await;
        self.busy=false;
        match res{Ok(m) if self.allow_in(m.kind())&&self.stream.get_mut().0.charge(0).is_ok()=>Ok(m),_=>{self.deny();Err(Error::Denied)}}
    }
    pub async fn write(&mut self,msg:&Message)->Result<()>{
        self.start_io()?;
        if !self.allow_out(msg.kind()){self.deny();return Err(Error::Denied)}
        let bytes=match msg.encode(){Ok(x)=>x,Err(_)=>{self.deny();return Err(Error::Invalid)}};
        let result=tokio::time::timeout(FRAME_TIME,async{self.stream.write_all(&bytes).await?;self.stream.flush().await}).await;
        self.busy=false;
        match result{Ok(Ok(()))=>Ok(()),_=>{self.deny();Err(Error::Denied)}}
    }
    /// Consume this TLS channel and write only the frame authorized by the
    /// completed operation. No external message, no retry, no normal read.
    /// Dropping this future closes the socket and clears the authority slot.
    pub async fn finish(mut self)->Result<()> {
        let inner=self.stream.get_ref().0;
        if self.busy||inner.preclass||inner.socket.is_none(){return Err(Error::Denied)}
        let (frame,deadline)={
            let mut a=inner.owner.lock().map_err(|_|Error::State)?;
            a.claim_terminal(inner.id,wall()?,Instant::now())?
        };
        self.stream.get_mut().0.terminal=true;
        let result=timeout_at(tokio::time::Instant::from_std(deadline),async{
            self.stream.write_all(frame.as_slice()).await?;
            self.stream.flush().await?;
            self.stream.shutdown().await
        }).await;
        self.deny(); // close only this original socket, even on partial write
        match result{Ok(Ok(()))=>Ok(()),_=>Err(Error::Denied)}
    }
    fn deny(&mut self){
        let inner=self.stream.get_mut().0;
        drop(inner.socket.take());
        if let Ok(mut a)=inner.owner.lock(){a.reject_tls(inner.id);a.close(inner.id)}
    }

}
fn bytes<const N:usize>(v:&V,k:&str)->Result<[u8;N]>{v.get(k).and_then(V::as_bytes).ok_or(Error::Denied)?.try_into().map_err(|_|Error::Denied)}
fn caps()->V{V::Array(["attestation","number-match","strong-biometric","tls-exporter"].into_iter().map(V::text).collect())}
fn random<const N:usize>()->Result<[u8;N]>{let mut b=[0u8;N];getrandom::getrandom(&mut b).map_err(|_|Error::State)?;if b==[0;N]{return Err(Error::State)}Ok(b)}
fn b(x:impl AsRef<[u8]>)->V{V::Bytes(x.as_ref().to_vec())}
/// Caller must bind separate explicitly configured production/enrollment
/// listeners. Charge the actual TCP source before creating a TLS configuration.
pub async fn accept(socket:TcpStream,owner:Owner,identity:&Identity,mode:Listener)->Result<Channel>{
    let source=socket.peer_addr()?.ip();
    let (id,started)={let mut a=owner.lock().map_err(|_|Error::State)?;let mono=Instant::now();(a.connect(source,Carrier::Tcp,mode,mono)?,mono)};
    let charged=Charged{socket:Some(socket),owner:owner.clone(),id,preclass:true,bytes:0,terminal:false,terminal_bytes:0};
    let (host,pins)={let mut a=owner.lock().map_err(|_|Error::State)?;a.tls_pins(mode,wall()?,Instant::now())?};
    let cfg=identity.config(mode,pins.clone())?;
    let stream=timeout_at(tokio::time::Instant::from_std(started+FRAME_TIME),tokio_rustls::TlsAcceptor::from(Arc::new(cfg)).accept(charged)).await.map_err(|_|Error::Denied)??;
    let tls=stream.get_ref().1;
    if tls.alpn_protocol()!=Some(alpn(mode))||tls.protocol_version()!=Some(rustls::ProtocolVersion::TLSv1_3)||!matches!(tls.handshake_kind(),Some(rustls::HandshakeKind::Full|rustls::HandshakeKind::FullWithHelloRetryRequest)){return Err(Error::Denied)}
    let peer=tls.peer_certificates().and_then(|c|if c.len()==1{c.first()}else{None}).ok_or(Error::Denied)?;
    let peer_key=point_cert(peer.as_ref(),wall()?,mode==Listener::Enrollment).ok_or(Error::Denied)?;
    if peer_key==identity.point{return Err(Error::Denied)}
    let channel=tls.export_keying_material([0u8;32],EXPORTER,Some(&[])).map_err(|_|Error::Denied)?;
    if channel==[0;32]{return Err(Error::Denied)}
    let binding=EnrollmentChannel{channel,host_cert:hash(identity.cert.as_ref()),provisional_client_cert:hash(peer.as_ref()),host_key:identity.point,provisional_client_key:peer_key};
    {owner.lock().map_err(|_|Error::State)?.handshake_complete(id,Instant::now())?;}
    let mut out=Channel{stream,mode,binding,credential:None,access:None,purpose:None,busy:false};
    let hello_deadline=tokio::time::Instant::now()+FRAME_TIME;
    if mode==Listener::Enrollment {
        owner.lock().map_err(|_|Error::State)?.classify_enrollment(id,wall()?,Instant::now())?;
    }else{
        let credential=*pins.get(&peer_key).ok_or(Error::Denied)?;let session=random::<16>()?;let host_nonce=random::<32>()?;
        let hello=Message::new(Kind::Hello,V::map([("v",V::Uint(2)),("host_id",b(host)),("session_id",b(session)),("host_nonce",b(host_nonce)),("capabilities",caps())])).map_err(|_|Error::Invalid)?;
        timeout_at(hello_deadline,out.write(&hello)).await.map_err(|_|Error::Denied)??;
        let ack=timeout_at(hello_deadline,out.read()).await.map_err(|_|Error::Denied)??;let p=ack.payload();
        if ack.kind()!=Kind::HelloAck||bytes::<16>(p,"host_id")?!=host||bytes::<16>(p,"session_id")?!=session||bytes::<32>(p,"host_nonce")?!=host_nonce||bytes::<16>(p,"credential_id")?!=credential{return Err(Error::Denied)}
        let device_nonce=bytes::<32>(p,"device_nonce")?;if device_nonce==[0;32]{return Err(Error::Denied)}
        let access=owner.lock().map_err(|_|Error::State)?.classify_production(id,Peer{credential,key:peer_key,session,channel,host_nonce,device_nonce},wall()?,Instant::now())?;
        let purpose=Purpose::parse(p)?;if !purpose.permitted(access){return Err(Error::Denied)}
        out.credential=Some(credential);out.access=Some(access);out.purpose=Some(purpose);
    }
    out.stream.get_mut().0.preclass=false;Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn material()->(CertificateDer<'static>,PrivateKeyDer<'static>,[u8;65]){
        let cert=rcgen::generate_simple_self_signed(vec!["rbad".into()]).unwrap();
        let der=cert.cert.der().clone();let point=point_cert(der.as_ref(),wall().unwrap(),true).unwrap();
        (der,PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),point)
    }
    async fn handshake(mode:Listener,client_key:bool,correct_pin:bool,protocol:&[u8])->Option<(Hash,Hash)>{
        let (server_cert,server_key,server_point)=material();let (client_cert,client_priv,client_point)=material();
        let host=Identity::new(server_cert.clone(),server_key,server_point).unwrap();
        let mut pins=BTreeMap::new();if mode==Listener::Production{pins.insert(if correct_pin{client_point}else{server_point},[1;16]);}
        let server=Arc::new(host.config(mode,pins).unwrap());
        let mut roots=rustls::RootCertStore::empty();roots.add(server_cert).unwrap();
        let builder=rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_root_certificates(roots);
        let mut client=if client_key{builder.with_client_auth_cert(vec![client_cert],client_priv).unwrap()}else{builder.with_no_client_auth()};
        // An omitted ALPN extension is represented by an empty list, not
        // by an invalid zero-length ProtocolName (RFC 7301).
        client.alpn_protocols=if protocol.is_empty(){Vec::new()}else{vec![protocol.to_vec()]};client.resumption=rustls::client::Resumption::disabled();
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let run=async{
            let (server,client)=tokio::join!(async{let (tcp,_)=listener.accept().await.ok()?;tokio_rustls::TlsAcceptor::from(server).accept(tcp).await.ok()},async{let tcp=TcpStream::connect(address).await.ok()?;tokio_rustls::TlsConnector::from(Arc::new(client)).connect(rustls::pki_types::ServerName::try_from("rbad").unwrap(),tcp).await.ok()});
            let server=server?;let client=client?;
            if server.get_ref().1.alpn_protocol()!=Some(alpn(mode)){return None}
            let a=server.get_ref().1.export_keying_material([0u8;32],EXPORTER,Some(&[])).ok()?;
            let b=client.get_ref().1.export_keying_material([0u8;32],EXPORTER,Some(&[])).ok()?;Some((a,b))
        };
        tokio::time::timeout(FRAME_TIME,run).await.ok().flatten()
    }
    #[tokio::test]
    async fn real_mutual_tls_exporters_agree_and_are_fresh(){
        let (a,b)=handshake(Listener::Production,true,true,b"rba/2").await.unwrap();assert_eq!(a,b);assert_ne!(a,[0;32]);
        let (c,d)=handshake(Listener::Production,true,true,b"rba/2").await.unwrap();assert_eq!(c,d);assert_ne!(a,c);
    }
    #[tokio::test]
    async fn production_requires_exact_pinned_client_certificate_and_alpn(){
        assert!(handshake(Listener::Production,false,true,b"rba/2").await.is_none());
        assert!(handshake(Listener::Production,true,false,b"rba/2").await.is_none());
        assert!(handshake(Listener::Production,true,true,b"rba-enroll/2").await.is_none());
        assert!(handshake(Listener::Production,true,true,b"").await.is_none());
    }
    #[tokio::test]
    async fn provisional_listener_requires_certificate_and_separate_alpn(){
        let (a,b)=handshake(Listener::Enrollment,true,false,b"rba-enroll/2").await.unwrap();assert_eq!(a,b);
        assert!(handshake(Listener::Enrollment,false,false,b"rba-enroll/2").await.is_none());
        assert!(handshake(Listener::Enrollment,true,false,b"rba/2").await.is_none());
    }
    async fn client_read(stream:&mut tokio_rustls::client::TlsStream<TcpStream>)->Message{
        let mut head=[0;13];stream.read_exact(&mut head).await.unwrap();
        let h=v2_wire::parse_header(&head).unwrap();let mut p=vec![0;h.payload_len];stream.read_exact(&mut p).await.unwrap();
        Message::new(Kind::from_code(h.message_type).unwrap(),v2_wire::decode_payload(&p).unwrap()).unwrap()
    }
    /// Exercises accept/HELLO, the real authority commit, finish, exact receipt
    /// and EOF on a real rustls loopback. Synthetic attestation is test-only.
    async fn terminal_loopback(commit:bool){
        let (server_cert,server_key,server_point)=material();let (client_cert,client_key,client_point)=material();let (_,_,bio)=material();
        let store=crate::v2_store::tls_test_store(&client_point,&bio,wall().unwrap());
        let owner=Arc::new(Mutex::new(Authority::new(store)));
        let host=Identity::new(server_cert.clone(),server_key,server_point).unwrap();
        let mut roots=rustls::RootCertStore::empty();roots.add(server_cert).unwrap();
        let mut client=rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_root_certificates(roots).with_client_auth_cert(vec![client_cert],client_key).unwrap();
        client.alpn_protocols=vec![b"rba/2".to_vec()];client.resumption=rustls::client::Resumption::disabled();
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let server=async{
            let(tcp,_)=listener.accept().await.unwrap();let mut channel=accept(tcp,owner.clone(),&host,Listener::Production).await.unwrap();
            if commit{
                channel.peer_terminal().await.unwrap();
            }else{
                let request=channel.read().await.unwrap();assert_eq!(request.kind(),Kind::Revoke);
                // A receipt of the same shape without an authority commit
                // is not allowed through ordinary write or finish.
                let forged=Message::new(Kind::RevokeReceipt,V::map([("session_id",request.payload().get("session_id").unwrap().clone()),("credential_id",b([4;16]))])).unwrap();
                assert!(channel.write(&forged).await.is_err());
                assert!(channel.finish().await.is_err());
            }
        };
        let device=async{
            let tcp=TcpStream::connect(address).await.unwrap();let mut stream=tokio_rustls::TlsConnector::from(Arc::new(client)).connect(rustls::pki_types::ServerName::try_from("rbad").unwrap(),tcp).await.unwrap();
            let hello=client_read(&mut stream).await;assert_eq!(hello.kind(),Kind::Hello);let hp=hello.payload();
            let session=bytes::<16>(hp,"session_id").unwrap();
            let ack=Message::new(Kind::HelloAck,V::map([("v",V::Uint(2)),("host_id",hp.get("host_id").unwrap().clone()),("session_id",b(session)),("host_nonce",hp.get("host_nonce").unwrap().clone()),("device_nonce",b([9;32])),("credential_id",b([4;16])),("purpose",V::Uint(3)),("capabilities",caps())])).unwrap();
            stream.write_all(&ack.encode().unwrap()).await.unwrap();stream.flush().await.unwrap();
            let revoke=Message::new(Kind::Revoke,V::map([("session_id",b(session)),("credential_id",b([4;16])),("token",b([5;32]))])).unwrap();
            stream.write_all(&revoke.encode().unwrap()).await.unwrap();stream.flush().await.unwrap();
            if commit{let receipt=client_read(&mut stream).await;assert_eq!(receipt.kind(),Kind::RevokeReceipt);assert_eq!(bytes::<16>(receipt.payload(),"session_id").unwrap(),session);assert_eq!(bytes::<16>(receipt.payload(),"credential_id").unwrap(),[4;16]);}
            let mut byte=[0u8;1];let end=stream.read(&mut byte).await;
            if commit{assert_eq!(end.unwrap(),0)}else{assert!(matches!(end,Ok(0)|Err(_)))}
        };
        tokio::time::timeout(Duration::from_secs(15),async{tokio::join!(server,device);}).await.unwrap();
        assert_eq!(owner.lock().unwrap().store().peer_state(&client_point,&[4;16],wall().unwrap()).unwrap(),if commit{PeerState::RevocationOnly}else{PeerState::Active});
    }
    #[tokio::test] async fn terminal_receipt_real_tls_commit_then_eof(){terminal_loopback(true).await}
    #[tokio::test] async fn terminal_receipt_real_tls_uncommitted_rejected(){terminal_loopback(false).await}
    /// Exercise the complete routed challenge and response over actual TLS.
    /// All keys and local presentation events in this test are synthetic.
    async fn routed_auth_loopback(correct_number:bool){
        use crate::v2_store::{Principal, Scope, authority::{LocalIntent, Origin}};
        use dispatch::{LocalEvent, ReceiptDelivery, scheduler::AuthScheduler};
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use rba_protocol::v2_message::{self as m, Domain};
        let (server_cert,server_key,server_point)=material();
        let private=openssl::pkey::PKey::private_key_from_der(server_key.secret_der()).unwrap();
        let scalar=zeroize::Zeroizing::new(private.ec_key().unwrap().private_key().to_vec_padded(32).unwrap());
        let signer=SigningKey::from_slice(scalar.as_slice()).unwrap();
        let (client_cert,client_key,client_point)=material();
        let mut bio_scalar=[0u8;32];bio_scalar[31]=13;
        let bio=SigningKey::from_slice(&bio_scalar).unwrap();
        let bio_point:[u8;65]=bio.verifying_key().to_encoded_point(false).as_bytes().try_into().unwrap();
        let owner=Arc::new(Mutex::new(Authority::new(crate::v2_store::tls_test_store(&client_point,&bio_point,wall().unwrap()))));
        let principal=Principal{id:[1;16],uid:1000,name:"user1000".into(),generation:[2;16]};
        let local_id=[11;16];let interaction=[12;16];
        let scheduler=AuthScheduler::new(owner.clone());
        let (request,mut events)=scheduler.submit(LocalIntent{owner:local_id,interaction,caller:principal.clone(),approver:principal.clone(),target:principal,scope:Scope::Cli,origin:Origin::SelfCli{peer_uid:1000}},[4;16],30,"local-cli".into(),"authentication".into()).unwrap();
        let host=Identity::new(server_cert.clone(),server_key,server_point).unwrap();
        let mut roots=rustls::RootCertStore::empty();roots.add(server_cert).unwrap();
        let mut client=rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_root_certificates(roots).with_client_auth_cert(vec![client_cert],client_key).unwrap();
        client.alpn_protocols=vec![b"rba/2".to_vec()];client.resumption=rustls::client::Resumption::disabled();
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let (shown_number,number)=tokio::sync::oneshot::channel();
        let server=async{
            let(tcp,_)=listener.accept().await.unwrap();let channel=accept(tcp,owner.clone(),&host,Listener::Production).await.unwrap();
            assert!(owner.lock().unwrap().auth_route([42;16],interaction,request,channel.id()).is_err());
            let result=scheduler.serve(channel,&signer).await;
            if correct_number{assert_eq!(result.unwrap(),ReceiptDelivery::Sent)}else{assert!(result.is_err())}
        };
        let ui=async{
            match events.recv().await.unwrap(){LocalEvent::DisplayNumber{digits,shown}=>{shown.send(()).unwrap();shown_number.send(*digits).unwrap()},_=>panic!("unexpected local event")}
            if correct_number{match events.recv().await.unwrap(){LocalEvent::Authenticated{interaction:actual,expires_wall,expires_mono}=>{assert_eq!(actual,interaction);assert!(wall().unwrap()<expires_wall&&Instant::now()<expires_mono)},_=>panic!("unexpected result")}}
            else{assert!(events.recv().await.is_none())}
        };
        let device=async{
            let tcp=TcpStream::connect(address).await.unwrap();let mut stream=tokio_rustls::TlsConnector::from(Arc::new(client)).connect(rustls::pki_types::ServerName::try_from("rbad").unwrap(),tcp).await.unwrap();
            let hello=client_read(&mut stream).await;let hp=hello.payload();let session=bytes::<16>(hp,"session_id").unwrap();
            let ack=Message::new(Kind::HelloAck,V::map([("v",V::Uint(2)),("host_id",hp.get("host_id").unwrap().clone()),("session_id",b(session)),("host_nonce",hp.get("host_nonce").unwrap().clone()),("device_nonce",b([9;32])),("credential_id",b([4;16])),("purpose",V::Uint(0)),("capabilities",caps())])).unwrap();
            stream.write_all(&ack.encode().unwrap()).await.unwrap();stream.flush().await.unwrap();
            let challenge=client_read(&mut stream).await;assert_eq!(challenge.kind(),Kind::AuthRequest);
            let core=challenge.payload().get("core").unwrap();
            m::verify(Domain::AuthRequest,core,&server_point,challenge.payload().get("signature").unwrap().as_bytes().unwrap()).unwrap();
            let exporter=stream.get_ref().1.export_keying_material([0u8;32],EXPORTER,Some(&[])).unwrap();
            assert_eq!(bytes::<32>(core,"channel").unwrap(),exporter);assert_eq!(bytes::<16>(core,"request_id").unwrap(),request);
            let mut digits=number.await.unwrap();if !correct_number{digits[0]=if digits[0]==b'9'{b'0'}else{digits[0]+1};}
            let entry=Message::new(Kind::NumberEntry,V::map([("session_id",b(session)),("request_id",b(request)),("digits",V::text(std::str::from_utf8(&digits).unwrap()))])).unwrap();
            stream.write_all(&entry.encode().unwrap()).await.unwrap();stream.flush().await.unwrap();
            if correct_number{
                let matched=client_read(&mut stream).await;assert_eq!(matched.kind(),Kind::Matched);let mc=matched.payload().get("core").unwrap();
                m::verify(Domain::Matched,mc,&server_point,matched.payload().get("signature").unwrap().as_bytes().unwrap()).unwrap();
                let response=V::map([("v",V::Uint(2)),("session_id",b(session)),("request_id",b(request)),("channel",b(exporter)),("request_hash",b(m::hash(Domain::AuthRequest,core).unwrap())),("match_hash",b(m::hash(Domain::Matched,mc).unwrap())),("credential_id",b([4;16])),("decision",V::Uint(1))]);
                let sig:Signature=bio.sign(&m::transcript(Domain::AuthResponse,&response).unwrap());
                let response=Message::new(Kind::AuthResponse,V::map([("core",response),("signature",b(sig.to_bytes()))])).unwrap();
                stream.write_all(&response.encode().unwrap()).await.unwrap();stream.flush().await.unwrap();
                let receipt=client_read(&mut stream).await;assert_eq!(receipt.kind(),Kind::AuthResult);assert_eq!(receipt.payload().get("outcome"),Some(&V::Uint(1)));
                assert_eq!(bytes::<16>(receipt.payload(),"request_id").unwrap(),request);
            }
            let mut byte=[0u8;1];let end=stream.read(&mut byte).await;if correct_number{assert_eq!(end.unwrap(),0)}else{assert!(matches!(end,Ok(0)|Err(_)))}
        };
        tokio::time::timeout(Duration::from_secs(15),async{tokio::join!(server,ui,device);}).await.unwrap();
        let audit=owner.lock().unwrap().store().read_audit(100).unwrap();
        assert_eq!(audit.iter().filter(|e|e.kind=="auth-success").count(),if correct_number{1}else{0});
    }
    #[tokio::test] async fn routed_auth_real_tls_success(){routed_auth_loopback(true).await}
    #[tokio::test] async fn routed_auth_real_tls_wrong_number(){routed_auth_loopback(false).await}
    #[test]
    fn scheduler_rejects_duplicate_and_prunes_disconnected_caller() {
        use crate::v2_store::{Principal,Scope,authority::{LocalIntent,Origin}};
        let (_,_,transport)=material();let (_,_,bio)=material();
        let owner=Arc::new(Mutex::new(Authority::new(crate::v2_store::tls_test_store(&transport,&bio,wall().unwrap()))));
        let scheduler=dispatch::scheduler::AuthScheduler::new(owner.clone());
        let principal=Principal{id:[1;16],uid:1000,name:"user1000".into(),generation:[2;16]};
        let intent=|n:u8|LocalIntent{owner:[n;16],interaction:[n+1;16],caller:principal.clone(),approver:principal.clone(),target:principal.clone(),scope:Scope::Cli,origin:Origin::SelfCli{peer_uid:1000}};
        let (_,events)=scheduler.submit(intent(11),[4;16],30,"local-cli".into(),"authentication".into()).unwrap();
        assert!(scheduler.submit(intent(21),[4;16],30,"local-cli".into(),"authentication".into()).is_err());
        drop(events);
        let (_,events)=scheduler.submit(intent(21),[4;16],30,"local-cli".into(),"authentication".into()).unwrap();
        assert!(!owner.lock().unwrap().store().read_audit(100).unwrap().iter().any(|e|e.kind=="prompt"));
        drop(events);
    }
    #[test]
    fn purpose_routing_is_disjoint() {
        let purposes=[Purpose::Authentication,Purpose::Policy,Purpose::Recovery,Purpose::Revocation];
        let inbounds=[Kind::NumberEntry,Kind::PolicyDecision,Kind::EnrollStatus,Kind::Revoke];
        for (i,p) in purposes.iter().enumerate(){
            assert_eq!(Purpose::parse(&V::map([("purpose",V::Uint(i as u64))])).unwrap(),*p);
            assert!(p.permitted(PeerState::Active));assert_eq!(p.permitted(PeerState::RevocationOnly),i==3);
            for (j,k) in inbounds.iter().enumerate(){assert_eq!(p.inbound(*k),i==j);}
            assert_eq!(p.outbound(Kind::AuthRequest),i==0);
            assert_eq!(p.outbound(Kind::PolicyOffer),i==1);
        }
        assert!(Purpose::parse(&V::map([("purpose",V::Uint(4))])).is_err());
    }
    #[test]
    fn wrong_host_identity_is_rejected(){
        let (cert,key,point)=material();let mut wrong=point;wrong[64]^=1;assert!(Identity::new(cert,key,wrong).is_err());
    }
}
