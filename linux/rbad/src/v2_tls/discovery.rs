//! DNS-SD is an endpoint hint only. No advertisement authorizes a connection,
//! operation, host identity or credential. Keep V2 separate from V1 discovery.
use super::{hash, Id};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::net::{IpAddr, SocketAddr};

const SERVICE: &str = "_rba-v2._tcp.local.";
#[derive(Clone, Copy)]
pub(super) enum Role { Authentication, Enrollment }
impl Role {
    fn name(self) -> &'static str { match self { Self::Authentication => "auth", Self::Enrollment => "pair" } }
}
fn eligible(address: SocketAddr) -> bool {
    address.port() != 0 && matches!(address.ip(), IpAddr::V4(ip) if ip.is_private())
}
struct Record {
    name: String,
    hostname: String,
    host: String,
    key: String,
    role: &'static str,
    attempt: String,
    label: String,
}
impl Record {
    fn new(host: Id, point: &[u8;65], role: Role, attempt: Option<Id>) -> Self {
        let host = hex::encode(host);
        let attempt = attempt.map(hex::encode).unwrap_or_default();
        let label: String = std::env::var("HOSTNAME").unwrap_or_default().chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c,'-'|'_'|' ')).take(32).collect();
        let name=if attempt.is_empty(){format!("RBA-{}-{}",host,role.name())}else{format!("RBA-{}-{}",&host[..16],&attempt[..16])};
        Self { name, hostname: format!("rba-{host}.local."), label: if label.trim().is_empty(){format!("Host {}",&host[..8])}else{label}, host, key: hex::encode(hash(point)), role: role.name(), attempt }

    }
    fn properties(&self) -> [(&str,&str);6] {
        [("v","2"),("id",&self.host),("key",&self.key),("role",self.role),("attempt",&self.attempt),("name",&self.label)]
    }
}
/// One registration owned by the already-bound listener. Drop unregisters and
/// stops the DNS-SD worker. A cached advert may outlive the socket; it is never
/// treated as proof of reachability or trust.
pub(super) struct Announcement { daemon: ServiceDaemon, fullname: String }
impl Announcement {
    pub(super) fn publish(address: SocketAddr, host: Id, point: &[u8;65], role: Role, attempt: Option<Id>) -> Option<Self> {
        if !eligible(address) { return None; }
        let record = Record::new(host, point, role, attempt);
        let addresses = [address.ip()];
        let info = ServiceInfo::new(SERVICE, &record.name, &record.hostname, &addresses[..], address.port(), &record.properties()[..]).ok()?;
        let fullname = info.get_fullname().to_owned();
        let daemon = ServiceDaemon::new().ok()?;
        let announcement = Self { daemon, fullname };
        if announcement.daemon.register(info).is_err() {
            eprintln!("RBA: LAN discovery registration unavailable");
            return None;
        }
        Some(announcement)
    }
}
impl Drop for Announcement {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn discovery_only_advertises_concrete_private_ipv4() {
        for a in ["192.168.1.4:8765", "10.1.2.3:8766", "172.16.1.1:8765"] { assert!(eligible(a.parse().unwrap())); }
        for a in ["0.0.0.0:8765", "127.0.0.1:8765", "8.8.8.8:8765", "192.168.1.1:0", "[::]:8765", "100.85.36.40:8765"] { assert!(!eligible(a.parse().unwrap())); }
    }
    #[test] fn discovery_roles_and_key_hash_are_distinct_from_trust() {
        let point = [7;65];
        let a = Record::new([1;16], &point, Role::Authentication, None);
        let p = Record::new([1;16], &point, Role::Enrollment, Some([2;16]));
        assert_ne!(a.name,p.name);
        assert_eq!(a.host,p.host);
        assert_eq!(a.key,hex::encode(hash(&point)));
        assert_eq!(a.properties()[..4],[("v","2"),("id",a.host.as_str()),("key",a.key.as_str()),("role","auth")]);
        assert_eq!(p.properties()[3],("role","pair"));
    }
}
