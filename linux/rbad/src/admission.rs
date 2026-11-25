//! One admission boundary for pairing and authentication attempts. The engine
//! serializes all changes with one mutex. Persistent deployments commit every
//! accepted reservation before any enrollment session or challenge is exposed.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rba_protocol::errors::{ProtocolError, Result};
use rba_protocol::ratelimit::RateLimiter;
use rba_protocol::types::Transport;

const FORMAT: &str = "rba-admission-v1";
const SECTIONS: [&str; 5] = ["pairing", "wifi", "ble", "accounts", "devices"];

fn storage_error(e: io::Error) -> ProtocolError {
    ProtocolError::Internal(format!("admission state: {e}"))
}

fn invalid_state() -> ProtocolError {
    ProtocolError::Internal("invalid or obsolete admission state".into())
}

#[derive(Clone)]
struct Budgets {
    pairing: RateLimiter,
    wifi: RateLimiter,
    ble: RateLimiter,
    accounts: RateLimiter,
    devices: RateLimiter,
    last_admitted: u64,
}

impl Budgets {
    fn new() -> Self {
        Self {
            pairing: RateLimiter::new(RateLimiter::pairing_limit()),
            wifi: RateLimiter::for_auth_transport(Transport::Wifi),
            ble: RateLimiter::for_auth_transport(Transport::Ble),
            accounts: RateLimiter::new(RateLimiter::prompt_limit()),
            devices: RateLimiter::new(RateLimiter::prompt_limit()),
            last_admitted: 0,
        }
    }

    fn prune(&mut self, now: u64) -> Result<()> {
        if now < self.last_admitted {
            // A wall-clock rollback cannot reopen a previously used budget.
            return Err(ProtocolError::Internal("admission clock moved backwards".into()));
        }
        self.pairing.prune(now);
        self.wifi.prune(now);
        self.ble.prune(now);
        self.accounts.prune(now);
        self.devices.prune(now);
        Ok(())
    }

    fn transport(&mut self, transport: Transport) -> &mut RateLimiter {
        match transport {
            Transport::Wifi => &mut self.wifi,
            Transport::Ble => &mut self.ble,
        }
    }

    fn encode(&self) -> String {
        let mut text = format!("{FORMAT} {}\n", self.last_admitted);
        for (section, limiter) in SECTIONS.iter().zip([
            &self.pairing, &self.wifi, &self.ble, &self.accounts, &self.devices,
        ]) {
            text.push_str(&format!("[{section}]\n"));
            text.push_str(&limiter.to_lines());
        }
        text
    }

    fn decode(text: &str) -> Result<Self> {
        let (header, body) = text.split_once('\n').ok_or_else(invalid_state)?;
        let last_admitted = header.strip_prefix(format!("{FORMAT} ").as_str())
            .and_then(|ts| ts.parse().ok()).ok_or_else(invalid_state)?;
        let mut remaining = body;
        let limits = [RateLimiter::pairing_limit(), RateLimiter::for_auth_transport(Transport::Wifi).limit(),
            RateLimiter::for_auth_transport(Transport::Ble).limit(), RateLimiter::prompt_limit(), RateLimiter::prompt_limit()];
        let mut decoded = Vec::new();
        for (index, (section, limit)) in SECTIONS.iter().zip(limits).enumerate() {
            remaining = remaining.strip_prefix(format!("[{section}]\n").as_str())
                .ok_or_else(invalid_state)?;
            let contents = if let Some(next) = SECTIONS.get(index + 1) {
                let marker = format!("[{next}]\n");
                let end = remaining.find(marker.as_str()).ok_or_else(invalid_state)?;
                let (contents, rest) = remaining.split_at(end);
                remaining = rest;
                contents
            } else {
                remaining
            };
            decoded.push(RateLimiter::from_lines(contents, limit, last_admitted)
                .ok_or_else(invalid_state)?);
        }
        let [pairing, wifi, ble, accounts, devices]: [RateLimiter; 5] =
            decoded.try_into().map_err(|_| invalid_state())?;
        Ok(Self { pairing, wifi, ble, accounts, devices, last_admitted })
    }
}

struct Store {
    path: PathBuf,
    // Keep the exclusive lock alive for the lifetime of the engine. Closing the
    // descriptor releases it even after process death; no stale PID file.
    _lock: File,
}

impl Store {
    fn open(dir: &Path) -> Result<Self> {
        crate::config::ensure_private_dir(dir).map_err(storage_error)?;
        // Persist the directory entry itself before trusting state stored in it.
        if let Some(parent) = dir.parent() {
            File::open(parent).and_then(|f| f.sync_all()).map_err(storage_error)?;
        }
        let lock = OpenOptions::new().read(true).write(true).create(true)
            .truncate(false).mode(0o600).open(dir.join("admission.lock"))
            .map_err(storage_error)?;
        // SAFETY: `lock` owns a live descriptor and flock only operates on it.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(storage_error(io::Error::last_os_error()));
        }
        Ok(Self { path: dir.join("admission-v1.state"), _lock: lock })
    }
}

pub(crate) struct Admission {
    budgets: Budgets,
    store: Option<Store>,
    // If durability is uncertain, no further dispatch is safe in this process.
    failed: bool,
}

impl Admission {
    pub(crate) fn open(dir: Option<&Path>) -> Result<Self> {
        let store = dir.map(Store::open).transpose()?;
        let budgets = if let Some(store) = &store {
            match std::fs::read_to_string(&store.path) {
                Ok(text) => Budgets::decode(&text)?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => Budgets::new(),
                Err(e) => return Err(storage_error(e)),
            }
        } else {
            Budgets::new()
        };
        Ok(Self { budgets, store, failed: false })
    }

    fn candidate(&self, now: u64) -> Result<Budgets> {
        if self.failed {
            return Err(ProtocolError::Internal("admission persistence failed; restart required".into()));
        }
        let mut candidate = self.budgets.clone();
        candidate.prune(now)?;
        Ok(candidate)
    }

    fn commit(&mut self, mut candidate: Budgets, now: u64) -> Result<()> {
        candidate.last_admitted = now;
        if let Some(store) = &self.store {
            if let Err(e) = crate::config::write_private(&store.path, candidate.encode().as_bytes()) {
                self.failed = true;
                return Err(storage_error(e));
            }
        }
        self.budgets = candidate;
        Ok(())
    }

    pub(crate) fn pairing(&mut self, peer: &str, now: u64) -> Result<()> {
        let key = hex::encode(peer.as_bytes());
        let mut next = self.candidate(now)?;
        if !next.pairing.check_and_record(&key, now) {
            return Err(ProtocolError::RateLimited(next.pairing.retry_after(&key, now)));
        }
        self.commit(next, now)
    }

    pub(crate) fn authenticate(&mut self, account: &str, device: &str, transport: Transport, now: u64) -> Result<()> {
        // Encode arbitrary account labels as unambiguous, whitespace-free keys.
        let account = hex::encode(account.as_bytes());
        let mut next = self.candidate(now)?;
        if !next.accounts.peek(&account, now)
            || !next.devices.peek(device, now)
            || !next.transport(transport).peek(device, now)
        {
            let retry = next.accounts.retry_after(&account, now)
                .max(next.devices.retry_after(device, now))
                .max(next.transport(transport).retry_after(device, now));
            return Err(ProtocolError::RateLimited(retry));
        }
        // All three checks succeeded on the same candidate. A denial commits
        // nothing; a success commits all budgets in a single durable snapshot.
        next.accounts.check_and_record(&account, now);
        next.devices.check_and_record(device, now);
        next.transport(transport).check_and_record(device, now);
        self.commit(next, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rba_protocol::types::{RATE_AUTH_PROMPT, RATE_AUTH_PROMPT_WINDOW, RATE_PAIRING, RATE_PAIRING_WINDOW};

    #[test]
    fn admission_uses_central_policy_for_new_and_restored_budgets() {
        let fresh = Budgets::new();
        let restored = Budgets::decode(&fresh.encode()).unwrap();
        for budgets in [&fresh, &restored] {
            assert_eq!(budgets.accounts.limit(), RateLimiter::prompt_limit());
            assert_eq!(budgets.devices.limit(), RateLimiter::prompt_limit());
            assert_eq!(budgets.pairing.limit(), RateLimiter::pairing_limit());
            assert_eq!(budgets.wifi.limit(), RateLimiter::for_auth_transport(Transport::Wifi).limit());
            assert_eq!(budgets.ble.limit(), RateLimiter::for_auth_transport(Transport::Ble).limit());
        }
    }

    #[test]
    fn prompt_ceiling_is_intentional_even_with_larger_transport_budget() {
        let mut admission = Admission::open(None).unwrap();
        for _ in 0..RATE_AUTH_PROMPT {
            admission.authenticate("alice", "device", Transport::Wifi, 100).unwrap();
        }
        assert!(admission.budgets.wifi.peek("device", 101));
        assert_eq!(admission.authenticate("alice", "device", Transport::Ble, 101),
            Err(ProtocolError::RateLimited(RATE_AUTH_PROMPT_WINDOW - 1)));
        admission.authenticate("alice", "device", Transport::Ble, 100 + RATE_AUTH_PROMPT_WINDOW).unwrap();
    }

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("rba-admission-{}", rba_protocol::types::Id::random().unwrap().to_hex()))
    }

    #[test]
    fn account_budget_is_shared_across_devices() {
        let mut admission = Admission::open(None).unwrap();
        for device in ["a", "b", "c"] {
            admission.authenticate("alice", device, Transport::Wifi, 100).unwrap();
        }
        assert_eq!(admission.authenticate("alice", "d", Transport::Ble, 101), Err(ProtocolError::RateLimited(59)));
        admission.authenticate("bob", "d", Transport::Ble, 101).unwrap();
    }

    #[test]
    fn device_budget_is_shared_across_accounts_and_rejections_do_not_extend_it() {
        let mut admission = Admission::open(None).unwrap();
        for account in ["alice", "bob", "carol"] {
            admission.authenticate(account, "a", Transport::Wifi, 100).unwrap();
        }
        for _ in 0..100 {
            assert_eq!(admission.authenticate("dave", "a", Transport::Ble, 159), Err(ProtocolError::RateLimited(1)));
        }
        admission.authenticate("dave", "a", Transport::Ble, 160).unwrap();
    }

    #[test]
    fn restart_preserves_all_budgets_and_denials_do_not_commit() {
        let dir = temp_dir();
        let mut admission = Admission::open(Some(&dir)).unwrap();
        for _ in 0..3 {
            admission.authenticate("alice", "device", Transport::Ble, 100).unwrap();
        }
        for _ in 0..3 {
            admission.authenticate("bob", "second", Transport::Wifi, 100).unwrap();
        }
        for _ in 0..RATE_PAIRING {
            admission.pairing("uid:42", 100).unwrap();
        }
        let before = std::fs::read(dir.join("admission-v1.state")).unwrap();
        assert!(Admission::open(Some(&dir)).is_err()); // concurrent daemon
        drop(admission);
        let mut admission = Admission::open(Some(&dir)).unwrap();
        let wifi_limit = RateLimiter::for_auth_transport(Transport::Wifi).limit();
        assert_eq!(admission.budgets.wifi.to_lines(), format!("limit {} {}\nsecond 100 100 100\n", wifi_limit.max_events, wifi_limit.window_secs));
        assert_eq!(admission.budgets.ble.retry_after("device", 101), 0);
        let ble_limit = RateLimiter::for_auth_transport(Transport::Ble).limit();
        assert_eq!(admission.budgets.ble.to_lines(), format!("limit {} {}\ndevice 100 100 100\n", ble_limit.max_events, ble_limit.window_secs));
        assert_eq!(admission.authenticate("alice", "other", Transport::Wifi, 101), Err(ProtocolError::RateLimited(59)));
        assert_eq!(admission.authenticate("carol", "device", Transport::Wifi, 101), Err(ProtocolError::RateLimited(59)));
        assert_eq!(admission.pairing("uid:42", 101), Err(ProtocolError::RateLimited(RATE_PAIRING_WINDOW - 1)));
        assert_eq!(std::fs::read(dir.join("admission-v1.state")).unwrap(), before);
        admission.authenticate("alice", "device", Transport::Wifi, 160).unwrap();
        drop(admission);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_requests_share_one_atomic_budget() {
        use std::sync::{Arc, Barrier, Mutex};
        let admission = Arc::new(Mutex::new(Admission::open(None).unwrap()));
        let barrier = Arc::new(Barrier::new(8));
        let workers: Vec<_> = (0..8).map(|index| {
            let admission = Arc::clone(&admission);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                admission.lock().unwrap().authenticate(
                    "alice", &format!("device-{index}"), Transport::Wifi, 100,
                ).is_ok()
            })
        }).collect();
        let admitted = workers.into_iter().map(|worker| worker.join().unwrap())
            .filter(|allowed| *allowed).count();
        assert_eq!(admitted, 3);
    }

    #[test]
    fn transport_denial_leaves_account_and_device_budget_unchanged() {
        let mut admission = Admission::open(None).unwrap();
        // Saturate the transport budget independently to exercise the all-or-none
        // check even though production prompt limits are normally tighter.
        let limit = admission.budgets.wifi.limit();
        for _ in 0..limit.max_events {
            assert!(admission.budgets.wifi.check_and_record("device", 100));
        }
        let before = admission.budgets.encode();
        assert_eq!(admission.authenticate("alice", "device", Transport::Wifi, 100),
            Err(ProtocolError::RateLimited(limit.window_secs)));
        assert_eq!(admission.budgets.encode(), before);
        admission.authenticate("alice", "device", Transport::Ble, 100).unwrap();
    }

    #[test]
    fn invalid_state_and_clock_rollback_fail_closed() {
        let dir = temp_dir();
        let mut admission = Admission::open(Some(&dir)).unwrap();
        admission.authenticate("alice", "device", Transport::Wifi, 100).unwrap();
        drop(admission);
        let mut admission = Admission::open(Some(&dir)).unwrap();
        assert!(matches!(admission.authenticate("alice", "device", Transport::Wifi, 99), Err(ProtocolError::Internal(_))));
        drop(admission);
        std::fs::write(dir.join("admission-v1.state"), "corrupt").unwrap();
        assert!(Admission::open(Some(&dir)).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn persistence_failure_prevents_subsequent_admission() {
        let dir = temp_dir();
        let mut admission = Admission::open(Some(&dir)).unwrap();
        // Force the atomic replacement to fail without relying on permissions
        // (tests may run as root).
        std::fs::create_dir(dir.join("admission-v1.state")).unwrap();
        assert!(admission.authenticate("alice", "device", Transport::Wifi, 100).is_err());
        std::fs::remove_dir(dir.join("admission-v1.state")).unwrap();
        assert!(admission.authenticate("alice", "device", Transport::Wifi, 101).is_err());
        drop(admission);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
