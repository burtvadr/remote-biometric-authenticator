//! V2 admission policy. Monotonic, bounded transport/local ingress accounting
//! is separate from durable prompt and pairing reservations. Linux daemon only.
use super::{Error, Id, Result, ZERO};
use std::{collections::{HashMap, VecDeque}, net::IpAddr, time::{Duration, Instant}};

#[derive(Clone, Copy)]
pub(super) struct Limit { count: usize, seconds: u64 }
impl Limit {
    const fn new(count: usize, seconds: u64) -> Self { Self { count, seconds } }
    fn expire(self, q: &mut VecDeque<Instant>, now: Instant) {
        while q.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(self.seconds)) { q.pop_front(); }
    }
    fn charge(self, q: &mut VecDeque<Instant>, now: Instant) -> bool {
        self.expire(q, now);
        if q.len() >= self.count { return false; }
        q.push_back(now); true
    }
    fn durable(self, kind: i64, subject: Id) -> (i64, Id, i64, i64) {
        (kind, subject, self.count as i64, self.seconds as i64)
    }
}
const GLOBAL_CONN: Limit = Limit::new(120, 60);
const SOURCE_CONN: Limit = Limit::new(12, 60);
const LOCAL: Limit = Limit::new(30, 60);
const TCP_INGRESS: Limit = Limit::new(30, 60);
const BLE_INGRESS: Limit = Limit::new(15, 120);
const GLOBAL_PROMPT: Limit = Limit::new(6, 60);
const PRINCIPAL_PROMPT: Limit = Limit::new(3, 60);
const CREDENTIAL_PROMPT: Limit = Limit::new(3, 60);
const ELEVATED: Limit = Limit::new(1, 60);
const PAIRING: Limit = Limit::new(5, 300);
pub(super) const DURABLE_RETENTION: i64 = PAIRING.seconds as i64;
const MAX_SOURCES: usize = 1024;
const MAX_CALLERS: usize = 4096; // managed principal capacity
const MAX_CONNECTIONS: usize = 32;
const MAX_PER_SOURCE: usize = 4;
const MAX_ENROLLMENT: usize = 2;
const MAX_PRECLASS_BYTES: usize = 256 * 1024;
const HANDSHAKE: Duration = Duration::from_secs(5);

pub(super) fn prompt_budgets(target: Id, credential: Id, elevated: bool) -> Vec<(i64, Id, i64, i64)> {
    let mut b = vec![GLOBAL_PROMPT.durable(1, ZERO), PRINCIPAL_PROMPT.durable(2, target), CREDENTIAL_PROMPT.durable(3, credential)];
    if elevated { b.extend([ELEVATED.durable(4, target), ELEVATED.durable(5, credential)]); }
    b
}
pub(super) fn pairing_budgets(initiator: Id) -> [(i64, Id, i64, i64); 2] {
    [PAIRING.durable(6, ZERO), PAIRING.durable(7, initiator)]
}

/// Internal handle, never sent over the wire or treated as bearer authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier { Tcp, Ble }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener { Production, Enrollment }
struct Connection {
    source: IpAddr,
    carrier: Carrier,
    listener: Listener,
    started: Instant,
    handshake: Option<Instant>,
    bytes: usize,
    classified: bool,
    invalid: bool,
    ingress: VecDeque<Instant>,
}
/// Owned by the single serialized daemon authority. All times and source
/// addresses come from the local OS, never frame fields. No network I/O here.
pub(super) struct Resources {
    last: Option<Instant>,
    serial: u64,
    global: VecDeque<Instant>,
    sources: HashMap<IpAddr, VecDeque<Instant>>,
    callers: HashMap<Id, VecDeque<Instant>>,
    connections: HashMap<ConnectionId, Connection>,
}
impl Resources {
    pub(super) fn new() -> Self { Self { last: None, serial: 0, global: VecDeque::new(), sources: HashMap::new(), callers: HashMap::new(), connections: HashMap::new() } }
    pub(super) fn tick(&mut self, now: Instant) -> Result<()> {
        if self.last.is_some_and(|last| now < last) { return Err(Error::Clock); }
        self.last = Some(now); Ok(())
    }
    pub(super) fn connect(&mut self, source: IpAddr, carrier: Carrier, listener: Listener, now: Instant) -> Result<ConnectionId> {
        self.tick(now)?;
        // Normalize IPv4-mapped IPv6 to prevent two counters for one address.
        let source = match source { IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(source), _ => source };
        // Charge global attempts even if per-source or concurrent caps reject.
        if !GLOBAL_CONN.charge(&mut self.global, now) { return Err(Error::Denied); }
        self.sources.retain(|_, q| { SOURCE_CONN.expire(q, now); !q.is_empty() });
        if !self.sources.contains_key(&source) && self.sources.len() >= MAX_SOURCES { return Err(Error::Denied); }
        if !SOURCE_CONN.charge(self.sources.entry(source).or_default(), now) { return Err(Error::Denied); }
        if self.connections.len() >= MAX_CONNECTIONS || self.connections.values().filter(|c| c.source == source).count() >= MAX_PER_SOURCE || (listener == Listener::Enrollment && self.connections.values().filter(|c| c.listener == Listener::Enrollment).count() >= MAX_ENROLLMENT) { return Err(Error::Denied); }
        // Only TCP is presently an admitted carrier; BLE remains disabled until
        // a real ordered, mutually authenticated stream/source adapter exists.
        if carrier != Carrier::Tcp { return Err(Error::Denied); }
        self.serial = self.serial.checked_add(1).ok_or(Error::State)?;
        let id = ConnectionId(self.serial);
        self.connections.insert(id, Connection { source, carrier, listener, started: now, handshake: None, bytes: 0, classified: false, invalid: false, ingress: VecDeque::new() });
        Ok(id)
    }
    pub(super) fn preclass_bytes(&mut self, id: ConnectionId, bytes: usize, now: Instant) -> Result<()> {
        self.tick(now)?;
        let c = self.connections.get_mut(&id).ok_or(Error::Denied)?;
        if c.invalid || c.classified || now.duration_since(c.handshake.unwrap_or(c.started)) >= HANDSHAKE { return Err(Error::Denied); }
        c.bytes = c.bytes.checked_add(bytes).ok_or(Error::Denied)?;
        if c.bytes > MAX_PRECLASS_BYTES { return Err(Error::Denied); }
        Ok(())
    }
    /// Called once after the adapter verifies a completed TLS handshake.
    pub(super) fn handshake_complete(&mut self, id: ConnectionId, now: Instant) -> Result<()> {
        self.tick(now)?;
        let c=self.connections.get_mut(&id).ok_or(Error::Denied)?;
        if c.invalid || c.handshake.is_some() || c.classified || now.duration_since(c.started)>=HANDSHAKE || c.bytes>MAX_PRECLASS_BYTES { return Err(Error::Denied); }
        c.handshake=Some(now); Ok(())
    }
    pub(super) fn classify(&mut self, id: ConnectionId, listener: Listener, now: Instant) -> Result<()> {
        self.tick(now)?;
        let c = self.connections.get_mut(&id).ok_or(Error::Denied)?;
        if c.invalid || c.classified || c.listener != listener || c.bytes > MAX_PRECLASS_BYTES || c.handshake.is_none_or(|t| now.duration_since(t) >= HANDSHAKE) { return Err(Error::Denied); }
        c.classified = true; Ok(())
    }
    pub(super) fn ingress(&mut self, id: ConnectionId, now: Instant) -> Result<()> {
        self.tick(now)?;
        let c = self.connections.get_mut(&id).ok_or(Error::Denied)?;
        if c.invalid || !c.classified || c.listener != Listener::Production { return Err(Error::Denied); }
        let limit = match c.carrier { Carrier::Tcp => TCP_INGRESS, Carrier::Ble => BLE_INGRESS };
        if !limit.charge(&mut c.ingress, now) { return Err(Error::Denied); } Ok(())
    }
    pub(super) fn local(&mut self, caller: Id, now: Instant) -> Result<()> {
        self.tick(now)?;
        self.callers.retain(|_, q| { LOCAL.expire(q, now); !q.is_empty() });
        if !self.callers.contains_key(&caller) && self.callers.len() >= MAX_CALLERS { return Err(Error::Denied); }
        if !LOCAL.charge(self.callers.entry(caller).or_default(), now) { return Err(Error::Denied); } Ok(())
    }
    // Denial does not release the physical socket slot. Only the actual
    // transport close notification may release it.
    pub(super) fn denied(&self, id: ConnectionId) -> bool { self.connections.get(&id).is_none_or(|c|c.invalid) }
    pub(super) fn terminal_slot(&self,id:ConnectionId,listener:Listener)->bool {
        self.connections.get(&id).is_some_and(|c|c.classified && c.invalid && c.listener==listener)
    }
    pub(super) fn deny(&mut self, id: ConnectionId) { if let Some(c)=self.connections.get_mut(&id) { c.invalid=true; } }
    pub(super) fn close(&mut self, id: ConnectionId) { self.connections.remove(&id); }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source(n: u8) -> IpAddr { IpAddr::from([10,0,0,n]) }
    #[test]
    fn source_and_global_attempts_roll_independently() {
        let mut r=Resources::new(); let t=Instant::now();
        for _ in 0..12 { let c=r.connect(source(1),Carrier::Tcp,Listener::Production,t).unwrap(); r.close(c); }
        assert!(r.connect(source(1),Carrier::Tcp,Listener::Production,t).is_err());
        for n in 2..=108 { let c=r.connect(source(n),Carrier::Tcp,Listener::Production,t).unwrap(); r.close(c); }
        // 12 + 1 rejected + 107 = 120; rejected attempts consumed global budget.
        assert!(r.connect(source(109),Carrier::Tcp,Listener::Production,t).is_err());
        assert!(r.connect(source(109),Carrier::Tcp,Listener::Production,t+Duration::from_secs(59)).is_err());
        assert!(r.connect(source(1),Carrier::Tcp,Listener::Production,t+Duration::from_secs(60)).is_ok());
    }
    #[test]
    fn live_slots_and_normalized_source_cannot_be_bypassed() {
        let mut r=Resources::new(); let t=Instant::now();
        let mut c=vec![];
        for _ in 0..4 { c.push(r.connect(source(1),Carrier::Tcp,Listener::Production,t).unwrap()); }
        let mapped:IpAddr="::ffff:10.0.0.1".parse().unwrap();
        assert!(r.connect(mapped,Carrier::Tcp,Listener::Production,t).is_err());
        r.deny(c[0]);
        assert!(r.connect(source(1),Carrier::Tcp,Listener::Production,t).is_err());
        r.close(c[0]);
        assert!(r.connect(source(1),Carrier::Tcp,Listener::Production,t).is_ok());
        for n in 2..=29 { r.connect(source(n),Carrier::Tcp,Listener::Production,t).unwrap(); }
        assert!(r.connect(source(30),Carrier::Tcp,Listener::Production,t).is_err());
    }
    #[test]
    fn handshake_and_classification_deadlines_are_absolute() {
        let mut r=Resources::new(); let t=Instant::now();
        let c=r.connect(source(1),Carrier::Tcp,Listener::Production,t).unwrap();
        assert!(r.classify(c,Listener::Production,t).is_err());
        r.preclass_bytes(c,MAX_PRECLASS_BYTES,t).unwrap();
        assert!(r.preclass_bytes(c,1,t).is_err());
        assert!(r.handshake_complete(c,t).is_err());
        r.close(c);
        let c=r.connect(source(1),Carrier::Tcp,Listener::Production,t).unwrap();
        assert!(r.handshake_complete(c,t+Duration::from_secs(5)).is_err());
        r.close(c);
        let t=t+Duration::from_secs(5);
        let c=r.connect(source(1),Carrier::Tcp,Listener::Production,t).unwrap();
        r.handshake_complete(c,t+Duration::from_secs(4)).unwrap();
        assert!(r.classify(c,Listener::Production,t+Duration::from_secs(9)).is_err());
    }
    #[test]
    fn local_and_enrolled_ingress_are_independent() {
        let mut r=Resources::new(); let t=Instant::now();
        let c=r.connect(source(1),Carrier::Tcp,Listener::Production,t).unwrap();
        assert!(r.ingress(c,t).is_err());
        r.handshake_complete(c,t).unwrap(); r.classify(c,Listener::Production,t).unwrap();
        for _ in 0..30 { r.local([1;16],t).unwrap(); r.ingress(c,t).unwrap(); }
        assert!(r.local([1;16],t).is_err()); assert!(r.ingress(c,t).is_err());
        r.local([2;16],t).unwrap();
        let t2=t+Duration::from_secs(60);
        r.local([1;16],t2).unwrap(); r.ingress(c,t2).unwrap();
        assert!(matches!(r.local([1;16],t),Err(Error::Clock)));
    }
    #[test]
    fn enrollment_cap_and_unsupported_carrier() {
        let mut r=Resources::new(); let t=Instant::now();
        for n in 1..=2 { r.connect(source(n),Carrier::Tcp,Listener::Enrollment,t).unwrap(); }
        assert!(r.connect(source(3),Carrier::Tcp,Listener::Enrollment,t).is_err());
        assert!(r.connect(source(3),Carrier::Ble,Listener::Production,t).is_err());
        let c=r.connect(source(3),Carrier::Tcp,Listener::Production,t).unwrap();
        r.handshake_complete(c,t).unwrap(); assert!(r.classify(c,Listener::Enrollment,t).is_err());
    }
}
