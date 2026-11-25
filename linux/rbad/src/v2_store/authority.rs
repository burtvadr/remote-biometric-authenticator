//! Serialized Linux V2 authorization and admission boundary. Not an IPC or
//! TLS implementation. Trusted facts must originate in the actual adapters;
//! no network message may construct caller/peer identity. No authentication
//! success is exposed here: B.2.4 must verify the owned signed transcript and
//! perform the final check in this same authority before delivering success.
use super::*;
use super::admission::Resources;
use super::attestation::{AndroidAttestationVerifier,RefreshReport};
pub use super::admission::{Carrier, ConnectionId, Listener};
use std::{collections::HashMap, net::IpAddr, time::{Duration, Instant}};

mod authentication;
mod enrollment;
mod terminal;
mod policy_sync;
#[cfg(fuzzing)]
pub(super) use enrollment::trace_enrollment;
pub use enrollment::{EnrollmentChannel, EntryDirection, EnrollmentStart, EnrollmentApproval, AttestationRequest, AttestationValidity, AttestationVerifier};
pub use authentication::{AuthDispatch, AuthAccepted};

const MAX_REQUESTS: usize = 32;
const AUTH_SECONDS: u64 = 60;
const PAIR_SECONDS: u64 = 120;

/// Only constructed by the trusted local adapter after peer credentials,
/// service provenance and an interactive number-display path are verified.
/// These are internal facts, not fields of the IPC request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin { SelfCli { peer_uid: u32 }, TrustedService(Scope) }
#[derive(Clone)]
pub struct LocalIntent {
    pub owner: Id, // daemon-assigned unique IPC connection identity
    pub interaction: Id, // daemon-assigned verified interaction identity
    pub caller: Principal,
    pub approver: Principal,
    pub target: Principal,
    pub scope: Scope,
    pub origin: Origin,
}
/// Produced after a full local TLS handshake and verified HELLO binding. The
/// exporter and key MUST be taken from TLS, not claimed by the remote peer.
#[derive(Clone)]
pub struct Peer {
    pub credential: Id,
    pub key: [u8;65],
    pub session: Id,
    pub channel: Hash,
    pub host_nonce: Hash,
    pub device_nonce: Hash,
}
struct BoundPeer { peer: Peer, access: PeerState, used: bool }
struct Pairing {
    classified: bool,
    enrollment: Option<enrollment::Stage>,
    id: Id,
    owner: Id,
    caller: Principal,
    expires_wall: i64,
    expires_mono: Instant,
    connection: Option<ConnectionId>,
}
struct Request {
    intent: LocalIntent,
    credential: Id,
    revision: i64,
    digest: Hash,
    expires_wall: i64,
    expires_mono: Instant,
    connection: Option<ConnectionId>,
    auth: Option<authentication::Stage>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dispatch {
    pub request: Id,
    pub session: Id,
    pub channel: Hash,
    pub revision: i64,
    pub policy_digest: Hash,
    pub expires_at: i64,
}

/// Single owner of mutable V2 storage and live admission. A daemon must use
/// one instance for all V2 listeners and local adapters. Public methods never
/// accept deserialized client claims as trusted adapter facts.
pub struct Authority {
    store: Store,
    resources: Resources,
    peers: HashMap<ConnectionId, BoundPeer>,
    requests: HashMap<Id, Request>,
    wall_high: Option<i64>,
    pairing: Option<Pairing>,
    terminals: HashMap<ConnectionId, terminal::Terminal>,
    policy_offers: HashMap<ConnectionId, policy_sync::Offer>,
    // Every normal V2 runtime starts closed until freshly provisioned. The
    // verifier is owned here, not supplied per enrollment by a network adapter.
    attestation: Option<AndroidAttestationVerifier>,
    trust_window: Option<(i64,i64,Instant)>,
    trust_failed: bool,
}
fn caller_allowed(db: &Connection, i: &LocalIntent) -> Result<bool> {
    if !valid_id(&i.owner) || !valid_id(&i.interaction) || !principal_matches(db, &i.caller)? { return Ok(false); }
    Ok(match i.origin {
        Origin::SelfCli { peer_uid } => i.scope == Scope::Cli && peer_uid == i.caller.uid && i.caller == i.target,
        // The service adapter must already have established trustworthy
        // provenance. Scope cannot be selected by an unprivileged IPC caller.
        Origin::TrustedService(scope) => scope != Scope::Cli && scope == i.scope,
    })
}
fn random_id() -> Result<Id> {
    let mut id=ZERO; getrandom::getrandom(&mut id).map_err(|_|Error::State)?;
    if !valid_id(&id) { return Err(Error::State); } Ok(id)
}
fn grant(i: &LocalIntent) -> Grant { Grant { approver: i.approver.id, target: i.target.id, scope: i.scope } }
fn authorized(db: &Connection, r: &Request, peer: Option<&Peer>, now: i64) -> Result<bool> {
    if !caller_allowed(db, &r.intent)? || !principal_matches(db, &r.intent.approver)? || !principal_matches(db, &r.intent.target)? || !eligible(db, &r.credential, &grant(&r.intent), r.revision, now)? { return Ok(false); }
    if policy(db, &r.credential)?.0.digest != r.digest { return Ok(false); }
    if let Some(p) = peer {
        if p.credential != r.credential { return Ok(false); }
        let exact: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM credentials WHERE id=? AND transport_key=? AND revoked_at IS NULL)", params![&p.credential[..],&p.key[..]], |row| row.get(0))?;
        if !exact { return Ok(false); }
    }
    Ok(true)
}
fn check_trust(window:Option<(i64,i64,Instant)>,failed:bool,now:i64,mono:Instant)->Result<()> {
    if failed{return Err(Error::Denied);}
    match window {
        Some((at,until,deadline)) if at<=now && now<until && mono<deadline && Instant::now()<deadline=>Ok(()),
        // Synthetic state tests and the isolated fuzz build use their own
        // verifier. Normal production builds cannot use this branch.
        #[cfg(any(test,fuzzing))]
        None=>Ok(()),
        _=>Err(Error::Denied),
    }
}
impl Authority {
    pub fn new(store: Store) -> Self { Self { store, resources: Resources::new(), peers: HashMap::new(), requests: HashMap::new(), wall_high: None, pairing: None, terminals: HashMap::new(), policy_offers: HashMap::new(), attestation:None, trust_window:None, trust_failed:false } }
    pub fn store(&self) -> &Store { &self.store }
    /// Snapshot of the durable inventory and currently classified production
    /// links. Connection state is informational, never an authorization result.
    pub(crate) fn inventory(&self, uid: u32) -> Result<Vec<(super::InventoryRecord, bool)>> {
        Ok(self.store.inventory(uid)?.into_iter().map(|record| {
            let linked = !record.revoked && self.peers.iter().any(|(conn, peer)|
                peer.peer.credential == record.id && peer.access == PeerState::Active
                && !self.resources.denied(*conn));
            (record, linked)
        }).collect())
    }


    /// Routing is based on the original locally admitted operation and the
    /// actual classified connection, never on a request ID supplied by a peer.
    pub(crate) fn auth_route(&self, owner: Id, interaction: Id, request: Id, conn: ConnectionId) -> Result<(i64, Instant)> {
        let r = self.requests.get(&request).ok_or(Error::Denied)?;
        let p = self.peers.get(&conn).ok_or(Error::Denied)?;
        if r.intent.owner != owner || r.intent.interaction != interaction || r.connection.is_some()
            || p.access != PeerState::Active || p.used || p.peer.credential != r.credential {
            return Err(Error::Denied);
        }
        Ok((r.expires_wall, r.expires_mono))
    }
    pub(crate) fn pairing_route(&self, owner: Id, enrollment: Id, conn: ConnectionId) -> Result<Instant> {
        let p = self.pairing.as_ref().ok_or(Error::Denied)?;
        if p.owner != owner || p.id != enrollment || p.connection != Some(conn) || !p.classified || p.enrollment.is_some() {
            return Err(Error::Denied);
        }
        Ok(p.expires_mono)
    }

    pub fn cleanup_tombstones(&mut self, now: i64) -> Result<usize> { self.store.cleanup_tombstones(now) }
    pub fn acknowledge_audit(&mut self, through: i64) -> Result<()> { self.store.acknowledge_audit(through) }
    /// Administrative mutations are serialized with requests. Invalidate every
    /// affected live request, even if it has not sent a biometric challenge.
    /// Store methods enforce DB invariants; local administrative authority and
    /// authenticated device consent remain mandatory at the IPC/session layer.
    pub fn revoke(&mut self, credential: Id, now: i64) -> Result<()> {
        self.store.revoke(credential, now)?; self.invalidate_credential(credential);
        let peers: Vec<_>=self.peers.iter().filter_map(|(c,p)|(p.peer.credential==credential).then_some(*c)).collect();
        for c in peers { self.deny_connection(c); } Ok(())
    }
    pub fn disable_principal(&mut self, id: Id, now: i64) -> Result<()> {
        self.store.disable_principal(id, now)?;
        // Delegated-grant removal increments the credential revision and may
        // invalidate requests for other targets; conservatively cancel all.
        self.invalidate_all(); self.abort_pairing(); self.invalidate_peers(); Ok(())
    }
    #[cfg(any(test,fuzzing))]
    pub fn replace_policy(&mut self, credential: Id, expected: i64, grants: &[Grant], accepted: Option<Hash>, now: i64) -> Result<Policy> {
        let p=self.store.replace_policy(credential, expected, grants, accepted, now)?;
        self.invalidate_credential(credential); Ok(p)
    }
    pub fn add_principal(&mut self, p: &Principal, now: i64) -> Result<()> { self.store.add_principal(p, now) }
    /// Install only a verifier constructed by the fixed-origin provisioner.
    /// Invoke after fetching on a worker; no network I/O in the authority.
    /// Any failed installation blocks the V2 path until a newer valid update.
    pub fn install_attestation(&mut self, mut verifier:AndroidAttestationVerifier, now:i64, mono:Instant)->Result<RefreshReport>{
        self.invalidate_all();self.abort_pairing();self.invalidate_peers();
        self.attestation=None;self.trust_failed=true;
        let window=verifier.status_window(now)?;
        if self.trust_window.is_some_and(|old|window.0<=old.0) || mono>=window.2 || Instant::now()>=window.2 {return Err(Error::Denied);}
        let report=self.store.revalidate_attestation(&mut verifier,now)?;
        verifier.status_window(now)?;
        self.trust_window=Some(window);self.attestation=Some(verifier);self.trust_failed=false;Ok(report)
    }
    fn trust_check(&self,now:i64,mono:Instant)->Result<()> { check_trust(self.trust_window,self.trust_failed,now,mono) }
    /// Enrollment commit is exclusively reachable through the admitted pairing
    /// slot. The B.2.4 state machine must first verify PAKE, attestation, exact
    /// offer acknowledgement and explicit local approval. These checks are
    /// not supplied by this storage/admission API.
    fn commit_enrollment(&mut self, owner: Id, conn: ConnectionId, e: &Enrollment<'_>, now: i64, mono: Instant) -> Result<()> {
        self.expire(now,mono)?;
        let p=self.pairing.as_ref().ok_or(Error::Denied)?;
        if !p.classified || p.owner!=owner || p.connection!=Some(conn) || p.id!=e.id || p.caller.id!=e.owner { return Err(Error::Denied); }
        let p=self.pairing.take().ok_or(Error::State)?;
        let result=(|| {
            if !self.store.principal_matches(&p.caller)? { return Err(Error::Denied); }
            self.store.commit_enrollment(e,now)
        })();
        // Receipt may be sent on the existing transport after successful commit;
        // no further pairing or authentication is permitted on it.
        self.deny_connection(conn);
        if result.is_ok() { self.invalidate_all(); self.invalidate_peers(); }
        result
    }
    /// Explicit trusted local pairing intent (caller established by IPC adapter).
    /// One admitted pairing globally, independent durable pairing budget.
    pub fn begin_pairing(&mut self, owner: Id, caller: Principal, now: i64, mono: Instant) -> Result<Id> {
        self.expire(now,mono)?;
        if !valid_id(&owner) || !self.store.principal_matches(&caller)? { return Err(Error::Denied); }
        self.resources.local(caller.id,mono)?;
        if self.pairing.is_some() || self.requests.values().any(|r|r.intent.owner==owner) { return Err(Error::Denied); }
        let expires_wall=now.checked_add(PAIR_SECONDS as i64).ok_or(Error::Clock)?;
        let expires_mono=mono.checked_add(Duration::from_secs(PAIR_SECONDS)).ok_or(Error::Clock)?;
        let id=random_id()?;
        if self.store.reserve_pairing(caller.id,now)?!=Reservation::Granted { return Err(Error::Denied); }
        self.pairing=Some(Pairing{classified:false,enrollment:None,id,owner,caller,expires_wall,expires_mono,connection:None}); Ok(id)
    }
    fn abort_pairing(&mut self) {
        if let Some(p)=self.pairing.take() { if let Some(c)=p.connection { self.deny_connection(c); } }
    }
    pub fn cancel_pairing_local(&mut self, owner: Id, pairing: Id) -> bool {
        if self.pairing.as_ref().is_some_and(|p|p.owner==owner && p.id==pairing) { self.abort_pairing(); true } else { false }
    }
    pub fn cancel_pairing_peer(&mut self, conn: ConnectionId, pairing: Id) -> bool {
        if self.pairing.as_ref().is_some_and(|p|p.connection==Some(conn) && p.id==pairing) { self.abort_pairing(); true } else { false }
    }
    fn invalidate_credential(&mut self, credential: Id) {
        self.terminals.retain(|_,t|t.credential!=credential);
        let offers:Vec<_>=self.policy_offers.iter().filter_map(|(c,o)|(o.credential==credential).then_some(*c)).collect();
        for c in offers { self.deny_connection(c); }
        let ids: Vec<_>=self.requests.iter().filter_map(|(id,r)|(r.credential==credential).then_some(*id)).collect();
        for id in ids { self.invalidate_request(id); }
    }
    fn invalidate_peers(&mut self) {
        let peers:Vec<_>=self.peers.keys().copied().collect();
        for conn in peers { self.deny_connection(conn); }
    }
    fn invalidate_all(&mut self) {
        self.terminals.clear();
        let offers:Vec<_>=self.policy_offers.keys().copied().collect();
        for c in offers { self.deny_connection(c); }
        let ids: Vec<_>=self.requests.keys().copied().collect();
        for id in ids { self.invalidate_request(id); }
    }
    fn invalidate_request(&mut self, id: Id) {
        if let Some(r)=self.requests.remove(&id) { if let Some(c)=r.connection { self.deny_connection(c); } }
    }
    fn deny_connection(&mut self, conn: ConnectionId) {
        self.terminals.remove(&conn);
        self.policy_offers.remove(&conn);
        self.resources.deny(conn); self.peers.remove(&conn); self.requests.retain(|_,r|r.connection!=Some(conn));
        if self.pairing.as_ref().is_some_and(|p|p.connection==Some(conn)) { self.pairing=None; }
    }
    /// Snapshot only locally eligible key pins. A fresh database/trust check
    /// at HELLO classification is mandatory; snapshots cannot confer rights.
    pub(crate) fn tls_pins(&mut self, listener:Listener, now:i64, mono:Instant)->Result<(Id,std::collections::BTreeMap<[u8;65],Id>)> {
        self.expire(now,mono)?;
        let host=as_id(self.store.db.query_row("SELECT host_id FROM host_meta WHERE singleton=1",[],|r|r.get(0))?)?;
        let mut pins=std::collections::BTreeMap::new();
        if listener==Listener::Production {
            let mut stmt=self.store.db.prepare("SELECT c.id,c.transport_key FROM credentials c JOIN principals p ON p.id=c.owner WHERE (c.revoked_at IS NULL AND c.assurance_until>?1 AND c.status_until>?1 AND p.active=1) OR (c.revoked_at IS NOT NULL AND c.retry_until>?1) LIMIT 4097")?;
            let mut rows=stmt.query([now])?;
            while let Some(row)=rows.next()? {
                let id=as_id(row.get(0)?)?;
                let key:Vec<u8>=row.get(1)?;
                let key:[u8;65]=key.try_into().map_err(|_|Error::State)?;
                if p256::PublicKey::from_sec1_bytes(&key).is_err() || pins.insert(key,id).is_some() || pins.len()>4096 {return Err(Error::State)}
            }
        }
        Ok((host,pins))
    }
    pub(crate) fn reject_tls(&mut self,conn:ConnectionId){self.deny_connection(conn)}
    pub fn connect(&mut self, source: IpAddr, carrier: Carrier, listener: Listener, mono: Instant) -> Result<ConnectionId> {
        let conn=self.resources.connect(source,carrier,listener,mono)?;
        if listener==Listener::Enrollment {
            match self.pairing.as_mut() {
                Some(p) if p.connection.is_none() && mono<p.expires_mono => p.connection=Some(conn),
                _ => {
                    // No slot escapes to the adapter; it must close the rejected
                    // accepted socket before accepting another one.
                    self.resources.close(conn); return Err(Error::Denied);
                }
            }
        }
        Ok(conn)
    }
    pub fn preclass_bytes(&mut self, conn: ConnectionId, bytes: usize, mono: Instant) -> Result<()> {
        let r=self.resources.preclass_bytes(conn,bytes,mono); if r.is_err() { self.deny_connection(conn); } r
    }
    pub fn handshake_complete(&mut self, conn: ConnectionId, mono: Instant) -> Result<()> {
        let r=self.resources.handshake_complete(conn,mono); if r.is_err() { self.deny_connection(conn); } r
    }
    /// Adapter must close denied sockets, releasing the actual slot only after close.
    pub fn connection_denied(&self, conn: ConnectionId) -> bool { self.resources.denied(conn) }
    /// Enrollment never enters the production authentication peer map.
    pub fn classify_enrollment(&mut self, conn: ConnectionId, now: i64, mono: Instant) -> Result<Id> {
        let result=(|| {
            self.expire(now,mono)?;
            self.resources.classify(conn,Listener::Enrollment,mono)?;
            let p=self.pairing.as_mut().ok_or(Error::Denied)?;
            if p.connection!=Some(conn) || p.classified || !self.store.principal_matches(&p.caller)? { return Err(Error::Denied); }
            p.classified=true; Ok(p.id)
        })();
        if result.is_err() { self.deny_connection(conn); } result
    }
    pub fn classify_production(&mut self, conn: ConnectionId, peer: Peer, now: i64, mono: Instant) -> Result<PeerState> {
        let result=(|| {
            self.expire(now,mono)?;
            self.resources.classify(conn,Listener::Production,mono)?;
            if !valid_id(&peer.session) || !valid_id(&peer.credential) { return Err(Error::Denied); }
            let access=self.store.peer_state(&peer.key,&peer.credential,now)?;
            if access==PeerState::Unknown { return Err(Error::Denied); }
            if self.peers.values().any(|p| p.peer.session == peer.session || p.peer.channel == peer.channel) { return Err(Error::Denied); }
            self.peers.insert(conn,BoundPeer{peer,access,used:false}); Ok(access)
        })();
        if result.is_err() { self.deny_connection(conn); } result
    }
    /// Charge independently before processing an enrolled authentication frame.
    pub fn ingress(&mut self, conn: ConnectionId, mono: Instant) -> Result<()> {
        if !self.peers.get(&conn).is_some_and(|p|p.access==PeerState::Active) { self.deny_connection(conn); return Err(Error::Denied); }
        let result=self.resources.ingress(conn,mono); if result.is_err() { self.deny_connection(conn); } result
    }
    /// Transport adapter calls only after actual socket closure. Denied slots
    /// remain charged until then, preventing a cap bypass by malformed traffic.
    pub fn close(&mut self, conn: ConnectionId) { self.deny_connection(conn); self.resources.close(conn); }
    pub fn close_local(&mut self, owner: Id) {
        self.terminals.retain(|_,t|t.owner!=Some(owner));
        let offers:Vec<_>=self.policy_offers.iter().filter_map(|(c,o)|(o.owner==owner).then_some(*c)).collect();
        for c in offers { self.deny_connection(c); }
        let ids: Vec<_>=self.requests.iter().filter_map(|(id,r)|(r.intent.owner==owner).then_some(*id)).collect();
        for id in ids { self.invalidate_request(id); }
        if self.pairing.as_ref().is_some_and(|p|p.owner==owner) { self.abort_pairing(); }
    }
    /// Restrict revocation-only credentials to this exact key/token operation.
    /// No biometric admission is available on that channel. The caller sends
    /// the receipt only after commit and closes the transport.
    pub fn revoke_peer(&mut self, conn: ConnectionId, message: &rba_protocol::v2_message::Message, now: i64, mono: Instant) -> Result<()> {
        use rba_protocol::{cbor::Value as V,v2_message::{Kind,Message}};
        let result=(|| {
            self.expire(now,mono)?;
            let p=self.peers.get(&conn).ok_or(Error::Denied)?;
            if p.used || message.kind()!=Kind::Revoke { return Err(Error::Denied); }
            let peer=p.peer.clone(); let payload=message.payload();
            if payload.get("session_id").and_then(V::as_bytes)!=Some(&peer.session[..]) || payload.get("credential_id").and_then(V::as_bytes)!=Some(&peer.credential[..]) {return Err(Error::Denied)}
            let token:Hash=payload.get("token").and_then(V::as_bytes).ok_or(Error::Denied)?.try_into().map_err(|_|Error::Denied)?;
            let receipt=Message::new(Kind::RevokeReceipt,V::map([("session_id",V::Bytes(peer.session.to_vec())),("credential_id",V::Bytes(peer.credential.to_vec()))])).map_err(|_|Error::Invalid)?;
            self.store.revoke_with_token(peer.credential,&peer.key,&token,now)?;
            Ok((peer,receipt))
        })();
        self.deny_connection(conn);
        let (peer,receipt)=result?;
        self.invalidate_credential(peer.credential);
        let others:Vec<_>=self.peers.iter().filter_map(|(c,p)|(p.peer.credential==peer.credential).then_some(*c)).collect();
        for c in others { self.deny_connection(c); }
        self.arm_terminal(conn,peer.credential,None,&receipt,now,mono,None)
    }
    /// Periodic runtime tick: invalidate idle connections on trust expiry even
    /// when no new messages or local requests arrive.
    pub(crate) fn maintenance(&mut self, now:i64, mono:Instant)->Result<()> {
        let result=self.expire(now,mono);
        if result.is_err(){self.invalidate_peers();}
        result
    }
    fn expire(&mut self, now: i64, mono: Instant) -> Result<()> {
        if let Err(e)=self.trust_check(now,mono){self.invalidate_all();self.abort_pairing();self.invalidate_peers();return Err(e);}
        if let Err(e)=self.resources.tick(mono) { self.invalidate_all(); self.abort_pairing(); return Err(e); }
        if self.wall_high.is_some_and(|last|now<last) { self.invalidate_all(); self.abort_pairing(); return Err(Error::Clock); }
        if let Err(e)=check_clock(&self.store.db,now) { self.invalidate_all(); self.abort_pairing(); return Err(e); }
        self.wall_high=Some(now);
        let offers:Vec<_>=self.policy_offers.iter().filter_map(|(c,o)|(now>=o.expires_wall || mono>=o.expires_mono).then_some(*c)).collect();
        for c in offers { self.deny_connection(c); }
        self.terminals.retain(|_,t|now>=t.issued_wall && now<t.until_wall && mono>=t.issued_mono && mono<t.until_mono);
        let ids:Vec<_>=self.requests.iter().filter_map(|(id,r)|(now>=r.expires_wall || mono>=r.expires_mono).then_some(*id)).collect();
        for id in ids { self.invalidate_request(id); }
        if self.pairing.as_ref().is_some_and(|p|now>=p.expires_wall || mono>=p.expires_mono) { self.abort_pairing(); } Ok(())
    }
    /// Begin an explicitly verified local interaction. Failed grant lookup still
    /// consumes the independently charged local caller budget; no prompt charge.
    pub fn begin(&mut self, intent: LocalIntent, credential: Id, seconds: u64, now: i64, mono: Instant) -> Result<Id> {
        self.expire(now,mono)?;
        if !caller_allowed(&self.store.db,&intent)? { return Err(Error::Denied); }
        self.resources.local(intent.caller.id,mono)?;
        if !(1..=AUTH_SECONDS).contains(&seconds) || !valid_id(&credential) { return Err(Error::Invalid); }
        if self.pairing.as_ref().is_some_and(|p|p.owner==intent.owner) || self.requests.len()>=MAX_REQUESTS || self.requests.values().any(|r| r.intent.owner==intent.owner || r.intent.interaction==intent.interaction || r.intent.target.id==intent.target.id || r.credential==credential) { return Err(Error::Denied); }
        let (p,_)=self.store.policy(credential)?;
        let expires_wall=now.checked_add(seconds as i64).ok_or(Error::Clock)?;
        let expires_mono=mono.checked_add(Duration::from_secs(seconds)).ok_or(Error::Clock)?;
        let r=Request{intent,credential,revision:p.revision,digest:p.digest,expires_wall,expires_mono,connection:None,auth:None};
        if !authorized(&self.store.db,&r,None,now)? { return Err(Error::Denied); }
        let id=random_id()?;
        if self.requests.contains_key(&id) { return Err(Error::State); }
        self.requests.insert(id,r); Ok(id)
    }
    /// Charge a potential prompt atomically with exact current authorization.
    /// Any failure after reservation keeps the charge. Only the original local
    /// owner can dispatch; a channel can be used for at most one request.
    pub fn dispatch(&mut self, owner: Id, request: Id, conn: ConnectionId, now: i64, mono: Instant) -> Result<Dispatch> {
        self.expire(now,mono)?;
        let r=self.requests.get(&request).ok_or(Error::Denied)?;
        if r.intent.owner!=owner || r.connection.is_some() { return Err(Error::Denied); }
        let p=self.peers.get(&conn).ok_or(Error::Denied)?;
        if p.used || p.access!=PeerState::Active || p.peer.credential!=r.credential { return Err(Error::Denied); }
        // From this point every failure is terminal for this request and channel.
        let mut r=self.requests.remove(&request).ok_or(Error::State)?;
        let p=self.peers.get_mut(&conn).ok_or(Error::State)?; p.used=true;
        let result=(|| {
            let t=self.store.tx()?; observe(&t,now)?;
            if !authorized(&t,&r,Some(&p.peer),now)? { return Err(Error::Denied); }
            let reservation=reserve(&t,&admission::prompt_budgets(r.intent.target.id,r.credential,r.intent.scope!=Scope::Cli),now)?;
            if reservation==Reservation::Granted { audit(&t,"prompt",&r.credential,now)?; }
            t.commit()?;
            if reservation!=Reservation::Granted { return Err(Error::Denied); }
            Ok(Dispatch{request,session:p.peer.session,channel:p.peer.channel,revision:r.revision,policy_digest:r.digest,expires_at:r.expires_wall})
        })();
        match result { Ok(d)=>{r.connection=Some(conn); self.requests.insert(request,r); Ok(d)}, Err(e)=>{self.deny_connection(conn); Err(e)} }
    }
    /// Check current authorization of an owned live request. NOT a biometric
    /// result. B.2.4 must verify signed response and use the same `authorized` predicate
    /// inside its final serialized commit, not check here and commit elsewhere.
    pub fn recheck_authorization(&mut self, owner: Id, request: Id, conn: ConnectionId, now: i64, mono: Instant) -> Result<()> {
        self.expire(now,mono)?;
        let r=self.requests.get(&request).ok_or(Error::Denied)?;
        if r.intent.owner!=owner || r.connection!=Some(conn) { return Err(Error::Denied); }
        let result=(|| {
            let p=self.peers.get(&conn).ok_or(Error::Denied)?;
            let t=self.store.tx()?; observe(&t,now)?;
            if !authorized(&t,r,Some(&p.peer),now)? { return Err(Error::Denied); }
            t.commit()?; Ok(())
        })();
        if result.is_err() { self.deny_connection(conn); } result
    }
    pub fn cancel_local(&mut self, owner: Id, request: Id) -> bool {
        if self.requests.get(&request).is_some_and(|r|r.intent.owner==owner) { self.invalidate_request(request); true } else { false }
    }
    pub fn cancel_peer(&mut self, conn: ConnectionId, request: Id) -> bool {
        if self.requests.get(&request).is_some_and(|r|r.connection==Some(conn)) { self.invalidate_request(request); true } else { false }
    }
}
