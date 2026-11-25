//! V2 host authentication lifecycle, owned by the existing serialized authority.
//! Adapters must display the number to the verified local interaction before
//! sending its challenge, supply the actual HELLO nonces and TLS host signer,
//! and deliver success only to the original live IPC interaction.
use super::*;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::subtle::ConstantTimeEq;
use rba_protocol::{cbor::Value as V, v2_message::{self as m, Domain, Kind, Message}};
use zeroize::Zeroizing;

pub(super) enum Stage {
    Number { digits: Zeroizing<[u8; 6]>, request_hash: Hash, host_key: Vec<u8> },
    Response { expected: V },
}
/// Secret number is local-only; never encode or log this object. Adapter must
/// present it through the owning interaction before transmitting the message.
pub struct AuthDispatch { pub number: Zeroizing<[u8;6]>, pub message: Message }
/// Internal routing information, not a transferable credential or wire token.
/// Must be returned synchronously to the original IPC owner by the adapter.
pub struct AuthAccepted { pub owner: Id, pub interaction: Id, pub result: Message }
fn invalid<T>(r: std::result::Result<T, rba_protocol::v2_wire::Invalid>) -> Result<T> { r.map_err(|_| Error::Invalid) }
fn b(v: impl AsRef<[u8]>) -> V { V::Bytes(v.as_ref().to_vec()) }
fn u(v: i64) -> Result<V> { Ok(V::Uint(u64::try_from(v).map_err(|_| Error::Clock)?)) }
fn field<'a>(v:&'a V,k:&str)->Result<&'a V>{v.get(k).ok_or(Error::Invalid)}
fn signed(kind: Kind, domain: Domain, core: V, signer: &SigningKey) -> Result<Message> {
    let sig: Signature = signer.try_sign(&invalid(m::transcript(domain,&core))?).map_err(|_| Error::State)?;
    invalid(Message::new(kind,V::map([("core",core),("signature",b(sig.to_bytes()))])))
}
fn number() -> Result<Zeroizing<[u8;6]>> {
    // Rejection sampling avoids modulo bias. 4,294,000,000 is divisible by 10^6.
    let mut raw=Zeroizing::new([0u8;4]);
    for _ in 0..128 {
        getrandom::getrandom(&mut *raw).map_err(|_| Error::State)?;
        let n=u32::from_be_bytes(*raw);
        if n>=4_294_000_000 { continue; }
        let mut n=n%1_000_000;
        let mut out=Zeroizing::new([b'0';6]);
        for digit in out.iter_mut().rev() { *digit += (n%10) as u8; n/=10; }
        return Ok(out);
    }
    Err(Error::State)
}
fn bound_fields(session:Id, request:Id, channel:Hash)->[(&'static str,V);4] {
    [("v",V::Uint(2)),("session_id",b(session)),("request_id",b(request)),("channel",b(channel))]
}
impl Authority {
    /// Starts exactly one request on the selected enrolled channel. The context
    /// strings are adapter-verified facts, not arbitrary IPC request fields.
    pub fn start_auth(&mut self, owner:Id, request:Id, conn:ConnectionId, signer:&SigningKey,
        source:&str, detail:&str, now:i64, mono:Instant)->Result<AuthDispatch> {
        let d=self.dispatch(owner,request,conn,now,mono)?;
        let result=(|| {
            let peer=&self.peers.get(&conn).ok_or(Error::State)?.peer;
            let r=self.requests.get_mut(&request).ok_or(Error::State)?;
            let host:Vec<u8>=self.store.db.query_row("SELECT host_id FROM host_meta WHERE singleton=1",[],|row|row.get(0))?;
            let mut challenge=[0;32]; getrandom::getrandom(&mut challenge).map_err(|_|Error::State)?;
            let (service,operation)=r.intent.scope.parts();
            let core=V::map(bound_fields(d.session,request,d.channel).into_iter().chain([
                ("host_id",b(host)),("credential_id",b(r.credential)),("host_nonce",b(peer.host_nonce)),("device_nonce",b(peer.device_nonce)),("challenge",b(challenge)),
                ("approver",b(r.intent.approver.id)),("target",b(r.intent.target.id)),("approver_label",V::text(r.intent.approver.name.clone())),("target_label",V::text(r.intent.target.name.clone())),
                ("scope",V::map([("purpose",V::text("authenticate")),("service",V::text(service)),("operation",V::text(operation))])),
                ("context",V::map([("source",V::text(source)),("detail",V::text(detail)),("interaction_id",b(r.intent.interaction))])),
                ("policy_revision",u(d.revision)?),("issued_at",u(now)?),("expires_at",u(d.expires_at)?),
            ]));
            let request_hash=invalid(m::hash(Domain::AuthRequest,&core))?;
            let message=signed(Kind::AuthRequest,Domain::AuthRequest,core,signer)?;
            let digits=number()?;
            r.auth=Some(Stage::Number{digits:digits.clone(),request_hash,host_key:signer.verifying_key().to_encoded_point(false).as_bytes().to_vec()});
            Ok(AuthDispatch{number:digits,message})
        })();
        if result.is_err(){self.deny_connection(conn);} result
    }
    fn auth_request_on(&self,conn:ConnectionId)->Result<Id>{
        self.requests.iter().find_map(|(id,r)|(r.connection==Some(conn)).then_some(*id)).ok_or(Error::Denied)
    }
    /// Consume number stage before examining input. Wrong, duplicate or
    /// out-of-order input invalidates the connection and request.
    pub fn auth_number(&mut self,conn:ConnectionId,message:&Message,signer:&SigningKey,now:i64,mono:Instant)->Result<Message>{
        let result=(||{
            self.expire(now,mono)?; self.ingress(conn,mono)?;
            let request=self.auth_request_on(conn)?;
            let r=self.requests.get_mut(&request).ok_or(Error::Denied)?;
            let Some(Stage::Number{digits,request_hash,host_key})=r.auth.take() else{return Err(Error::Denied)};
            let p=&self.peers.get(&conn).ok_or(Error::Denied)?.peer;
            let payload=message.payload();
            if message.kind()!=Kind::NumberEntry || field(payload,"session_id")?!=&b(p.session) || field(payload,"request_id")?!=&b(request)
                || host_key.as_slice()!=signer.verifying_key().to_encoded_point(false).as_bytes(){return Err(Error::Denied)}
            let entry=field(payload,"digits")?.as_text().ok_or(Error::Invalid)?.as_bytes();
            if !bool::from(digits.as_slice().ct_eq(entry)){return Err(Error::Denied)}
            if !authorized(&self.store.db,r,Some(p),now)?{return Err(Error::Denied)}
            let core=V::map(bound_fields(p.session,request,p.channel).into_iter().chain([("request_hash",b(request_hash)),("matched",V::Uint(1))]));
            let match_hash=invalid(m::hash(Domain::Matched,&core))?;
            let expected=V::map(bound_fields(p.session,request,p.channel).into_iter().chain([("request_hash",b(request_hash)),("match_hash",b(match_hash)),("credential_id",b(r.credential)),("decision",V::Uint(1))]));
            let reply=signed(Kind::Matched,Domain::Matched,core,signer)?;
            r.auth=Some(Stage::Response{expected}); Ok(reply)
        })();
        if result.is_err(){self.deny_connection(conn);} result
    }
    /// Typed remote cancellation, restricted to the request on this channel.
    /// Malformed or mismatched cancellation also closes only this channel.
    pub fn auth_cancel(&mut self,conn:ConnectionId,message:&Message,now:i64,mono:Instant)->Result<()> {
        let result=(||{
            self.expire(now,mono)?; self.ingress(conn,mono)?;
            let id=self.auth_request_on(conn)?;
            let p=&self.peers.get(&conn).ok_or(Error::Denied)?.peer;
            if message.kind()!=Kind::Cancel || field(message.payload(),"session_id")?!=&b(p.session) || field(message.payload(),"request_id")?!=&b(id) {return Err(Error::Denied)}
            Ok(())
        })();
        self.deny_connection(conn); result
    }
    /// Consume attempt before checking evidence. The exact current biometric key,
    /// caller generation, grant, revision and assurance are checked in the same
    /// transaction as the success audit. Transport key is never used here.
    pub fn auth_response(&mut self,conn:ConnectionId,message:&Message,mut clock:impl FnMut()->Result<(i64,Instant)>)->Result<AuthAccepted>{
        let result=(||{
            let (now,mono)=clock()?;
            self.expire(now,mono)?; self.ingress(conn,mono)?;
            let request=self.auth_request_on(conn)?;
            let mut r=self.requests.remove(&request).ok_or(Error::Denied)?;
            let Some(Stage::Response{expected})=r.auth.take() else{return Err(Error::Denied)};
            let p=&self.peers.get(&conn).ok_or(Error::Denied)?.peer;
            let payload=message.payload();
            if message.kind()!=Kind::AuthResponse || field(payload,"core")?!=&expected{return Err(Error::Denied)}
            let sig=field(payload,"signature")?.as_bytes().ok_or(Error::Invalid)?;
            let trust=self.trust_window;let trust_failed=self.trust_failed;
            let t=self.store.tx()?; observe(&t,now)?;
            if !authorized(&t,&r,Some(p),now)?{return Err(Error::Denied)}
            let key:Vec<u8>=t.query_row("SELECT biometric_key FROM credentials WHERE id=? AND revoked_at IS NULL",[&r.credential[..]],|row|row.get(0))?;
            invalid(m::verify(Domain::AuthResponse,&expected,&key,sig)).map_err(|_|Error::Denied)?;
            let reply=invalid(Message::new(Kind::AuthResult,V::map([("session_id",b(p.session)),("request_id",b(request)),("outcome",V::Uint(1))])))?;
            // Re-sample trusted clocks after potentially blocking database work
            // and cryptographic verification, immediately before the commit.
            let (end_wall,end_mono)=clock()?;
            if end_wall<now || end_mono<mono || end_wall>=r.expires_wall || end_mono>=r.expires_mono {return Err(Error::Clock)}
            check_trust(trust,trust_failed,end_wall,end_mono)?;
            observe(&t,end_wall)?;
            if !authorized(&t,&r,Some(p),end_wall)? {return Err(Error::Denied)}
            audit(&t,"auth-success",&r.credential,end_wall)?; t.commit()?;
            // A commit that outlasts the request cannot release local success.
            let (delivered_wall,delivered_mono)=clock()?;
            if delivered_wall<end_wall || delivered_mono<end_mono || delivered_wall>=r.expires_wall || delivered_mono>=r.expires_mono {return Err(Error::Clock)}
            check_trust(trust,trust_failed,delivered_wall,delivered_mono)?;
            Ok((AuthAccepted{owner:r.intent.owner,interaction:r.intent.interaction,result:reply},r.credential,delivered_wall,delivered_mono,r.expires_wall,r.expires_mono))
        })();
        self.deny_connection(conn);
        let (accepted,credential,now,mono,wall,deadline)=result?;
        self.arm_terminal(conn,credential,Some(accepted.owner),&accepted.result,now,mono,Some((wall,deadline)))?;
        Ok(accepted)
    }
}
