//! Linux-only V2 transactional host persistence. No V1 reader or fallback.
//! Callers must establish authenticated platform facts before invoking mutations.
//! This module does not validate attestation chains, local caller provenance, or
//! live protocol sessions. Those are mandatory upstream gates, not booleans
//! supplied by a network client. Do not activate the V2 runtime until integrated.
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;

pub type Id = [u8; 16];
pub type Hash = [u8; 32];
mod admission;
pub mod authority;
pub mod attestation;

const SCHEMA: &str = include_str!("schema.sql");
const RETRY: i64 = 30 * 86400;
const APP_ID: i64 = 0x52424132;
const VERSION: i64 = 2;
const ZERO: Id = [0; 16];
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Sql(rusqlite::Error),
    Invalid,
    Denied,
    Clock,
    State,
}
impl From<std::io::Error> for Error { fn from(e: std::io::Error) -> Self { Self::Io(e) } }
impl From<rusqlite::Error> for Error { fn from(e: rusqlite::Error) -> Self { Self::Sql(e) } }
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope { Cli, SudoService, GdmSession, PolkitAction }
impl Scope {
    fn parts(self) -> (&'static str, &'static str) {
        match self {
            Self::Cli => ("rba", "authenticate"),
            Self::SudoService => ("sudo", "service-auth"),
            Self::GdmSession => ("gdm", "session-auth"),
            Self::PolkitAction => ("polkit", "action-auth"),
        }
    }
    fn parse(service: &str, op: &str) -> Result<Self> {
        [Self::Cli, Self::SudoService, Self::GdmSession, Self::PolkitAction]
            .into_iter().find(|s| s.parts() == (service, op)).ok_or(Error::State)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant { pub approver: Id, pub target: Id, pub scope: Scope }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal { pub id: Id, pub uid: u32, pub name: String, pub generation: Id }
/// Evidence retained for revalidation, not evidence validated by this store.
pub struct Enrollment<'a> {
    pub id: Id,
    pub credential: Id,
    pub owner: Id,
    pub transport_key: &'a [u8; 65],
    pub biometric_key: &'a [u8; 65],
    /// Canonically encoded certificate chains from the verified enrollment.
    pub transport_chain: &'a [u8],
    pub biometric_chain: &'a [u8],
    pub attested_at: i64,
    pub assurance_until: i64,
    pub status_checked_at: i64,
    pub status_until: i64,
    pub token_hash: Hash,
    pub receipt_hash: Hash,
    pub offer_hash: Hash,
    pub initial_cli_grant: bool,
    /// Exact hashes of old same-host revocation tokens verified by the PAKE handler.
    pub cleanup_tokens: &'a [Hash],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy { pub revision: i64, pub digest: Hash }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState { Active, RevocationOnly, Unknown }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reservation { Granted, Exhausted }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent { pub seq: i64, pub kind: String, pub subject: Id, pub at: i64 }

pub struct Evidence {
    pub transport_key: Vec<u8>, pub biometric_key: Vec<u8>,
    pub transport_chain: Vec<u8>, pub biometric_chain: Vec<u8>,
    pub attested_at:i64, pub assurance_until:i64, pub status_checked_at:i64, pub status_until:i64,
}

/// Public inventory metadata only; never contains keys, chains or tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InventoryRecord { pub id: Id, pub revision: i64, pub revoked: bool }

pub struct Store { db: Connection, _lock: Option<File> }
fn digest(bytes: &[u8]) -> Hash { Sha256::digest(bytes).into() }
fn valid_id(id: &Id) -> bool { *id != ZERO }
pub(crate) fn private_regular(path: &Path, uid: u32) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.uid() != uid || m.mode() & 0o7777 != 0o600 || m.nlink() != 1 { return Err(Error::State); }
    Ok(())
}
pub(crate) fn private_dir(dir: &Path, uid: u32) -> Result<()> {
    if !dir.is_absolute() { return Err(Error::Invalid); }
    if dir.components().any(|c| matches!(c, std::path::Component::ParentDir | std::path::Component::CurDir)) { return Err(Error::Invalid); }
    let m = fs::symlink_metadata(dir)?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o7777 != 0o700 { return Err(Error::State); }
    // The effective service/user identity is the local trust boundary.
    // Root-owned or same-owner ancestors only; never symlinks or writable by others.
    // For uid 0 this preserves the original strictly root-owned path rule.
    for p in dir.ancestors().skip(1) {
        let m = fs::symlink_metadata(p)?;
        if !m.is_dir() || (m.uid() != 0 && m.uid() != uid) || m.mode() & 0o022 != 0 { return Err(Error::State); }
    }
    Ok(())
}
fn new_private(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().read(true).write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?)
}
fn check_sidecars(dir: &Path, uid: u32) -> Result<()> {
    for name in ["state.sqlite3-wal", "state.sqlite3-shm", "state.sqlite3-journal"] {
        let p = dir.join(name);
        match fs::symlink_metadata(&p) {
            Ok(_) if name.ends_with("-journal") => private_regular(&p, uid)?,
            Ok(_) => return Err(Error::State),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn configure(db: &Connection, memory: bool) -> Result<()> {
    if rusqlite::version_number() < 3_037_000 { return Err(Error::State); }
    db.busy_timeout(Duration::from_secs(2))?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA synchronous=EXTRA; PRAGMA temp_store=MEMORY;")?;
    if !memory {
        let pages:i64=db.query_row("PRAGMA max_page_count=262144",[],|r|r.get(0))?;
        if pages>262144 { return Err(Error::State); }
        let mode: String = db.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("delete") { return Err(Error::State); }
    }
    let fk: i64 = db.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
    let sync: i64 = db.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    if fk != 1 || sync != 3 { return Err(Error::State); }
    Ok(())
}
fn schema_rows(db: &Connection) -> Result<Vec<(String,String,String,String)>> {
    let mut s = db.prepare("SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name")?;
    let rows = s.query_map([], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
fn validate_db(db: &Connection, host: &Id) -> Result<()> {
    let app: i64 = db.query_row("PRAGMA application_id", [], |r| r.get(0))?;
    let ver: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if app != APP_ID || ver != VERSION { return Err(Error::State); }
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA)?;
    if schema_rows(db)? != schema_rows(&reference)? { return Err(Error::State); }
    let integrity: String = db.query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))?;
    if integrity != "ok" || db.prepare("PRAGMA foreign_key_check")?.exists([])? { return Err(Error::State); }
    let stored: Vec<u8> = db.query_row("SELECT host_id FROM host_meta WHERE singleton=1", [], |r| r.get(0))?;
    if stored.as_slice() != &host[..] { return Err(Error::State); }
    // Cross-table invariants not expressible as simple CHECK constraints.
    let invalid: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM credentials c WHERE NOT EXISTS(SELECT 1 FROM enrollments e WHERE e.credential=c.id) OR NOT EXISTS(SELECT 1 FROM key_history k WHERE k.credential=c.id AND k.role=0 AND k.key=c.transport_key) OR NOT EXISTS(SELECT 1 FROM key_history k WHERE k.credential=c.id AND k.role=1 AND k.key=c.biometric_key) OR (c.revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM principals p WHERE p.id=c.owner AND p.active=1))) OR EXISTS(SELECT 1 FROM grants g JOIN credentials c ON c.id=g.credential JOIN principals a ON a.id=g.approver JOIN principals t ON t.id=g.target WHERE c.revoked_at IS NOT NULL OR c.owner<>g.approver OR a.active=0 OR t.active=0)", [], |r| r.get(0))?;
    if invalid { return Err(Error::State); }
    Ok(())
}
impl Store {
    /// Explicit offline initialization only. Directory must already be owner-only
    /// on supported local storage. Never delete/reinitialize an existing DB.
    pub fn initialize(dir: &Path, host: Id, now: i64) -> Result<Self> {
        if !valid_id(&host) || now < 0 { return Err(Error::Invalid); }
        let uid = unsafe { libc::geteuid() };
        private_dir(dir, uid)?;
        if fs::read_dir(dir)?.next().is_some() { return Err(Error::State); }
        let lock = new_private(&dir.join("state.lock"))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 { return Err(std::io::Error::last_os_error().into()); }
        new_private(&dir.join("state.sqlite3"))?.sync_all()?;
        lock.sync_all()?;
        File::open(dir)?.sync_all()?;
        let mut db = Self::open_connection(dir)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        tx.execute("INSERT INTO host_meta VALUES(1,?,?)", params![&host[..],now])?;
        tx.commit()?;
        File::open(dir)?.sync_all()?;
        validate_db(&db, &host)?;
        Ok(Self { db, _lock: Some(lock) })
    }
    fn open_connection(dir: &Path) -> Result<Connection> {
        let db = Connection::open_with_flags(dir.join("state.sqlite3"), OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE)?;
        configure(&db, false)?;
        Ok(db)
    }
    /// Normal startup never creates a database, directory, or lock file.
    pub fn open(dir: &Path, host: Id) -> Result<Self> {
        let uid = unsafe { libc::geteuid() };
        private_dir(dir, uid)?;
        private_regular(&dir.join("state.lock"), uid)?;
        let lock = OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(dir.join("state.lock"))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 { return Err(std::io::Error::last_os_error().into()); }
        private_regular(&dir.join("state.sqlite3"),uid)?;
        check_sidecars(dir,uid)?;
        let db = Self::open_connection(dir)?;
        validate_db(&db, &host)?;
        Ok(Self { db, _lock: Some(lock) })
    }
    /// Standalone inventory for the verified local UID. This is read-only;
    /// a stored record is not an authorization or proof of a live connection.
    pub(crate) fn inventory(&self, uid: u32) -> Result<Vec<InventoryRecord>> {
        let mut stmt = self.db.prepare("SELECT c.id,c.revision,c.revoked_at IS NOT NULL FROM credentials c JOIN principals p ON p.id=c.owner WHERE p.uid=? ORDER BY c.id")?;
        let rows = stmt.query_map([uid], |r| Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,i64>(1)?,r.get::<_,bool>(2)?)))?;
        rows.map(|row| {
            let (id, revision, revoked) = row?;
            Ok(InventoryRecord { id: as_id(id)?, revision, revoked })
        }).collect()
    }
    /// Standalone user state only. A disabled or renamed identity must not
    /// silently inherit a previously enrolled principal. System account
    /// lifecycle tracking is a separate privileged adapter.
    fn standalone_principal(&self, uid: u32, name: &str) -> Result<Option<Principal>> {
        let row = self.db.query_row("SELECT id,name,generation,active FROM principals WHERE uid=? ORDER BY active DESC LIMIT 1", [uid], |r| Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,bool>(3)?))).optional()?;
        match row {
            None => Ok(None),
            Some((id,stored,generation,true)) if stored == name => Ok(Some(Principal{id:as_id(id)?,uid,name:stored,generation:as_id(generation)?})),
            _ => Err(Error::Denied),
        }
    }
    fn tx(&mut self) -> Result<Transaction<'_>> { Ok(self.db.transaction_with_behavior(TransactionBehavior::Immediate)?) }
    fn add_principal(&mut self, p: &Principal, now: i64) -> Result<()> {
        if !valid_id(&p.id) || !valid_id(&p.generation) || p.name.is_empty() || p.name.len()>64 || !p.name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) { return Err(Error::Invalid); }
        let t = self.tx()?; observe(&t,now)?;
        t.execute("INSERT INTO principals VALUES(?,?,?,?,1)", params![&p.id[..],p.uid,&p.name,&p.generation[..]])?;
        audit(&t,"principal-add",&p.id,now)?; t.commit()?; Ok(())
    }
    /// Exact generation must be supplied by trusted account lifecycle adapter.
    pub fn principal_matches(&self, p: &Principal) -> Result<bool> {
        principal_matches(&self.db,p)
    }
    fn disable_principal(&mut self, id: Id, now: i64) -> Result<()> {
        let t = self.tx()?; let now=observe_revocation(&t,now)?;
        if t.execute("UPDATE principals SET active=0 WHERE id=? AND active=1",[&id[..]])? != 1 { return Err(Error::Denied); }
        // Owner credentials are revoked; affected delegated grants are removed.
        let owned = { let mut s=t.prepare("SELECT id FROM credentials WHERE owner=? AND revoked_at IS NULL")?; let rows=s.query_map([&id[..]],|r|r.get::<_,Vec<u8>>(0))?; rows.collect::<rusqlite::Result<Vec<_>>>()? };
        for c in owned { revoke_tx(&t,&as_id(c)?,now)?; }
        t.execute("UPDATE credentials SET revision=revision+1 WHERE revoked_at IS NULL AND id IN (SELECT credential FROM grants WHERE approver=? OR target=?)",params![&id[..],&id[..]])?;
        t.execute("DELETE FROM grants WHERE approver=? OR target=?",params![&id[..],&id[..]])?;
        audit(&t,"principal-disable",&id,now)?; t.commit()?; Ok(())
    }
    /// Must be invoked only after verified PAKE, attestation, explicit local
    /// approval and exact staged offer acknowledgement. No network-accessible API.
    fn commit_enrollment(&mut self, e: &Enrollment<'_>, now: i64) -> Result<()> {
        if !valid_id(&e.id) || !valid_id(&e.credential) || !valid_id(&e.owner) || e.cleanup_tokens.len()>32 || e.attested_at>now || e.assurance_until<=now || e.status_until<=now || e.status_checked_at<e.attested_at || e.status_checked_at>now || e.status_until.checked_sub(e.status_checked_at).is_none_or(|d| d>86400) || e.transport_key==e.biometric_key || e.transport_key[0]!=4 || e.biometric_key[0]!=4 || p256::PublicKey::from_sec1_bytes(e.transport_key).is_err() || p256::PublicKey::from_sec1_bytes(e.biometric_key).is_err() { return Err(Error::Invalid); }
        let t=self.tx()?; observe(&t,now)?;
        if !active_principal(&t,&e.owner)? { return Err(Error::Denied); }
        for token in e.cleanup_tokens {
            let old: Option<Vec<u8>>=t.query_row("SELECT id FROM credentials WHERE token_hash=?",[&token[..]],|r|r.get(0)).optional()?;
            let old=old.ok_or(Error::Denied)?; revoke_tx(&t,&as_id(old)?,now)?;
        }
        t.execute("INSERT INTO credentials VALUES(?,?,1,?,?,?,?,?,?,?,?,?,NULL,NULL)",params![&e.credential[..],&e.owner[..],&e.transport_key[..],&e.biometric_key[..],e.transport_chain,e.biometric_chain,e.attested_at,e.assurance_until,e.status_checked_at,e.status_until,&e.token_hash[..]])?;
        for (key,role) in [(e.transport_key,0),(e.biometric_key,1)] { t.execute("INSERT INTO key_history VALUES(?,?,?)",params![&key[..],&e.credential[..],role])?; }
        if e.initial_cli_grant { insert_grant(&t,&e.credential,&Grant{approver:e.owner,target:e.owner,scope:Scope::Cli})?; }
        t.execute("INSERT INTO enrollments VALUES(?,?,?,?,?)",params![&e.id[..],&e.credential[..],&e.receipt_hash[..],&e.offer_hash[..],now])?;
        audit(&t,"enroll",&e.credential,now)?; t.commit()?; Ok(())
    }
    /// Restricted receipt recovery: caller must have authenticated exact TLS key.
    /// Returns only the stored offer hash; protocol echoes the verified receipt.
    pub fn enrollment_status(&self, id: Id, credential: Id, peer_key: &[u8;65], receipt: &Hash, now: i64) -> Result<Option<Hash>> {
        if self.peer_state(peer_key,&credential,now)? != PeerState::Active { return Ok(None); }
        let row: Option<Vec<u8>>=self.db.query_row("SELECT offer_hash FROM enrollments WHERE id=? AND credential=? AND receipt_hash=?",params![&id[..],&credential[..],&digest(receipt)[..]],|r|r.get(0)).optional()?;
        row.map(as_hash).transpose()
    }
    pub fn peer_state(&self, key: &[u8;65], credential: &Id, now: i64) -> Result<PeerState> {
        check_clock(&self.db,now)?;
        let state: Option<i64>=self.db.query_row("SELECT CASE WHEN c.revoked_at IS NULL AND c.assurance_until>?1 AND c.status_until>?1 AND p.active=1 THEN 1 WHEN c.revoked_at IS NOT NULL AND c.retry_until>?1 THEN 2 ELSE 0 END FROM credentials c JOIN principals p ON p.id=c.owner WHERE c.id=?2 AND c.transport_key=?3",params![now,&credential[..],&key[..]],|r|r.get(0)).optional()?;
        Ok(match state { Some(1)=>PeerState::Active,Some(2)=>PeerState::RevocationOnly,_=>PeerState::Unknown })
    }
    /// Admin revoke: caller authorization enforced by the local adapter.
    fn revoke(&mut self, credential: Id, now: i64) -> Result<()> {
        let t=self.tx()?; let now=observe_revocation(&t,now)?; revoke_tx(&t,&credential,now)?; t.commit()?; Ok(())
    }
    /// Remote revoke is bound to an exact TLS key, credential and token hash.
    fn revoke_with_token(&mut self, credential: Id, peer_key: &[u8;65], token: &Hash, now: i64) -> Result<()> {
        let t=self.tx()?; observe(&t,now)?;
        let hash=digest(token);
        let matched: bool=t.query_row("SELECT EXISTS(SELECT 1 FROM credentials WHERE id=? AND transport_key=? AND token_hash=? AND ((revoked_at IS NULL AND assurance_until>?4 AND status_until>?4) OR retry_until>?4))",params![&credential[..],&peer_key[..],&hash[..],now],|r|r.get(0))?;
        if !matched { return Err(Error::Denied); }
        revoke_tx(&t,&credential,now)?; t.commit()?; Ok(())
    }
    /// Expire online retry authority, retaining the token hash for authenticated
    /// same-host PAKE cleanup. Revoked records never regain authentication.
    fn cleanup_tombstones(&mut self, now: i64) -> Result<usize> {
        let t=self.tx()?; observe(&t,now)?;
        let n=t.execute("UPDATE credentials SET retry_until=NULL WHERE retry_until<=?",[now])?;
        if n>0 { audit(&t,"tombstone-cleanup",&ZERO,now)?; }
        t.commit()?; Ok(n)
    }
    /// Retrieve stored public keys and attestation material for the trusted verifier.
    /// This is not authorization and does not assert current assurance.
    pub fn evidence(&self, credential: Id) -> Result<Option<Evidence>> {
        let row=self.db.query_row("SELECT transport_key,biometric_key,transport_chain,biometric_chain,attested_at,assurance_until,status_checked_at,status_until FROM credentials WHERE id=? AND revoked_at IS NULL",[&credential[..]],|r|Ok(Evidence{transport_key:r.get(0)?,biometric_key:r.get(1)?,transport_chain:r.get(2)?,biometric_chain:r.get(3)?,attested_at:r.get(4)?,assurance_until:r.get(5)?,status_checked_at:r.get(6)?,status_until:r.get(7)?})).optional()?;
        Ok(row)
    }
    pub fn policy(&self, credential: Id) -> Result<(Policy,Vec<Grant>)> { policy(&self.db,&credential) }
    /// `accepted_digest` is obtained by the authenticated, same-channel device
    /// consent handler (not by accepting arbitrary local or remote input).
    fn replace_policy(&mut self, credential: Id, expected_revision: i64, grants: &[Grant], accepted_digest: Option<Hash>, now: i64) -> Result<Policy> {
        if grants.len()>32 { return Err(Error::Invalid); }
        let t=self.tx()?; observe(&t,now)?;
        let (old,old_grants)=policy(&t,&credential)?;
        if old.revision!=expected_revision { return Err(Error::Denied); }
        let revision=old.revision.checked_add(1).ok_or(Error::State)?;
        let digest=policy_digest(&credential,revision,grants)?;
        if grants.iter().any(|g| !old_grants.contains(g)) && accepted_digest!=Some(digest) { return Err(Error::Denied); }
        t.execute("DELETE FROM grants WHERE credential=?",[&credential[..]])?;
        for g in grants { insert_grant(&t,&credential,g)?; }
        t.execute("UPDATE credentials SET revision=? WHERE id=?",params![revision,&credential[..]])?;
        audit(&t,"policy",&credential,now)?; t.commit()?; Ok(Policy{revision,digest})
    }
    /// Only the attestation/status verifier may call this with fresh evidence.
    /// Never extends the 30-day key assurance lifetime.
    #[cfg(test)]
    fn refresh_status(&mut self, credential: Id, verified_at: i64, status_until: i64, now: i64) -> Result<()> {
        if verified_at<0 || verified_at>now || status_until<=now || status_until.checked_sub(verified_at).is_none_or(|d| d>86400) { return Err(Error::Invalid); }
        let t=self.tx()?; observe(&t,now)?;
        if t.execute("UPDATE credentials SET status_checked_at=?,status_until=? WHERE id=? AND revoked_at IS NULL AND assurance_until>? AND status_checked_at<=?",params![verified_at,status_until,&credential[..],now,verified_at])? != 1 { return Err(Error::Denied); }
        audit(&t,"status-refresh",&credential,now)?; t.commit()?; Ok(())
    }
    /// Durable independent pairing budget; only eligible local initiators.
    fn reserve_pairing(&mut self, initiator: Id, now: i64) -> Result<Reservation> {
        let t=self.tx()?; observe(&t,now)?;
        if !active_principal(&t,&initiator)? { return Err(Error::Denied); }
        let r=reserve(&t,&admission::pairing_budgets(initiator),now)?;
        if r==Reservation::Granted { audit(&t,"pairing",&initiator,now)?; }
        t.commit()?; Ok(r)
    }
    /// Only call after verified local intent. This is a storage reservation, not
    /// a complete authorization decision; runtime must also enforce caller,
    /// adapter, channel, live request limits and final serialized acceptance.
    #[cfg(test)]
    fn reserve_prompt(&mut self, credential: Id, grant: Grant, revision: i64, now: i64) -> Result<Reservation> {
        let t=self.tx()?; observe(&t,now)?;
        if !eligible(&t,&credential,&grant,revision,now)? { return Err(Error::Denied); }
        let r=reserve(&t,&admission::prompt_budgets(grant.target,credential,grant.scope!=Scope::Cli),now)?;
        if r==Reservation::Granted { audit(&t,"prompt",&credential,now)?; }
        t.commit()?; Ok(r)
    }
    pub fn read_audit(&self, limit: u32) -> Result<Vec<AuditEvent>> {
        if !(1..=256).contains(&limit) { return Err(Error::Invalid); }
        let mut s=self.db.prepare("SELECT seq,kind,subject,at FROM audit_outbox ORDER BY seq LIMIT ?")?;
        let rows=s.query_map([limit],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,i64>(3)?)))?;
        rows.map(|r| { let (seq,kind,subject,at)=r?; Ok(AuditEvent{seq,kind,subject:as_id(subject)?,at}) }).collect()
    }
    /// Call only after durable redacted log delivery; at-least-once outbox.
    fn acknowledge_audit(&mut self, through: i64) -> Result<()> {
        if through<1 { return Err(Error::Invalid); }
        let t=self.tx()?; t.execute("DELETE FROM audit_outbox WHERE seq<=?",[through])?; t.commit()?; Ok(())
    }
}
fn as_id(v:Vec<u8>)->Result<Id> { v.try_into().map_err(|_|Error::State) }
fn as_hash(v:Vec<u8>)->Result<Hash> { v.try_into().map_err(|_|Error::State) }
fn check_clock(db:&Connection,now:i64)->Result<()> {
    let last:i64=db.query_row("SELECT clock_high FROM host_meta WHERE singleton=1",[],|r|r.get(0))?;
    if now<last || now<0 { return Err(Error::Clock); } Ok(())
}
fn observe(t:&Transaction<'_>,now:i64)->Result<()> { check_clock(t,now)?; t.execute("UPDATE host_meta SET clock_high=? WHERE singleton=1",[now])?; Ok(()) }
fn observe_revocation(t:&Transaction<'_>,now:i64)->Result<i64> {
    let last:i64=t.query_row("SELECT clock_high FROM host_meta WHERE singleton=1",[],|r|r.get(0))?;
    let safe=now.max(last); observe(t,safe)?; Ok(safe)
}
fn audit(t:&Transaction<'_>,kind:&str,id:&Id,now:i64)->Result<()> { t.execute("INSERT INTO audit_outbox(kind,subject,at) VALUES(?,?,?)",params![kind,&id[..],now])?; Ok(()) }
fn principal_matches(db: &Connection, p: &Principal) -> Result<bool> {
    Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM principals WHERE id=? AND uid=? AND name=? AND generation=? AND active=1)",params![&p.id[..],p.uid,&p.name,&p.generation[..]],|r|r.get(0))?)
}
fn active_principal(db:&Connection,id:&Id)->Result<bool> { Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM principals WHERE id=? AND active=1)",[&id[..]],|r|r.get(0))?) }
fn revoke_tx(t:&Transaction<'_>,id:&Id,now:i64)->Result<()> {
    let changed=t.execute("UPDATE credentials SET revoked_at=?,retry_until=?,revision=revision+1 WHERE id=? AND revoked_at IS NULL",params![now,now.checked_add(RETRY).ok_or(Error::Invalid)?,&id[..]])?;
    if changed==0 {
        let exists:bool=t.query_row("SELECT EXISTS(SELECT 1 FROM credentials WHERE id=? AND revoked_at IS NOT NULL)",[&id[..]],|r|r.get(0))?;
        if !exists { return Err(Error::Denied); } return Ok(());
    }
    t.execute("DELETE FROM grants WHERE credential=?",[&id[..]])?; audit(t,"revoke",id,now)
}
fn insert_grant(t:&Transaction<'_>,id:&Id,g:&Grant)->Result<()> { let (s,o)=g.scope.parts(); t.execute("INSERT INTO grants VALUES(?,?,?,'authenticate',?,?)",params![&id[..],&g.approver[..],&g.target[..],s,o])?; Ok(()) }
fn policy_core(id:&Id,revision:i64,grants:&[Grant])->Result<rba_protocol::cbor::Value> {
    use rba_protocol::{cbor::Value,v2_wire::encode_payload};
    let mut encoded=Vec::new();
    for g in grants {
        let (s,o)=g.scope.parts();
        let v=Value::map([("credential_id",Value::bytes(id.to_vec())),("approver",Value::bytes(g.approver.to_vec())),("target",Value::bytes(g.target.to_vec())),("scope",Value::map([("purpose",Value::text("authenticate")),("service",Value::text(s)),("operation",Value::text(o))]))]);
        encoded.push((encode_payload(&v).map_err(|_|Error::Invalid)?,v));
    }
    encoded.sort_by(|a,b|a.0.cmp(&b.0));
    if encoded.windows(2).any(|w|w[0].0==w[1].0) { return Err(Error::Invalid); }
    let v=Value::map([("revision",Value::Uint(u64::try_from(revision).map_err(|_|Error::Invalid)?)),("grants",Value::Array(encoded.into_iter().map(|(_,v)|v).collect()))]);
    Ok(v)
}
fn policy_digest(id:&Id,revision:i64,grants:&[Grant])->Result<Hash> {
    use rba_protocol::v2_message::{hash,Domain};
    hash(Domain::Policy,&policy_core(id,revision,grants)?).map_err(|_|Error::Invalid)
}
fn policy(db:&Connection,id:&Id)->Result<(Policy,Vec<Grant>)> {
    let revision:i64=db.query_row("SELECT revision FROM credentials WHERE id=? AND revoked_at IS NULL",[&id[..]],|r|r.get(0)).optional()?.ok_or(Error::Denied)?;
    let mut s=db.prepare("SELECT approver,target,service,operation FROM grants WHERE credential=?")?;
    let rows=s.query_map([&id[..]],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?)))?;
    let grants=rows.map(|r|{let(a,t,s,o)=r?; Ok(Grant{approver:as_id(a)?,target:as_id(t)?,scope:Scope::parse(&s,&o)?})}).collect::<Result<Vec<_>>>()?;
    Ok((Policy{revision,digest:policy_digest(id,revision,&grants)?},grants))
}
fn eligible(db:&Connection,id:&Id,g:&Grant,revision:i64,now:i64)->Result<bool> {
    let(s,o)=g.scope.parts();
    Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM grants g JOIN credentials c ON c.id=g.credential JOIN principals a ON a.id=g.approver JOIN principals p ON p.id=g.target JOIN principals owner ON owner.id=c.owner WHERE c.id=? AND g.approver=? AND g.target=? AND g.service=? AND g.operation=? AND c.revision=? AND c.revoked_at IS NULL AND c.assurance_until>? AND c.status_until>? AND a.active=1 AND p.active=1 AND owner.active=1)",params![&id[..],&g.approver[..],&g.target[..],s,o,revision,now,now],|r|r.get(0))?)
}
fn reserve(t:&Transaction<'_>,budgets:&[(i64,Id,i64,i64)],now:i64)->Result<Reservation> {
    t.execute("DELETE FROM admission WHERE at<=?",[now-admission::DURABLE_RETENTION])?;
    for (kind,id,limit,window) in budgets {
        let count:i64=t.query_row("SELECT count(*) FROM admission WHERE kind=? AND subject=? AND at>?",params![kind,&id[..],now-window],|r|r.get(0))?;
        if count>=*limit { return Ok(Reservation::Exhausted); }
    }
    for (kind,id,_,_) in budgets { t.execute("INSERT INTO admission(kind,subject,at) VALUES(?,?,?)",params![kind,&id[..],now])?; }
    Ok(Reservation::Granted)
}

#[cfg(any(test, fuzzing))]
mod tests;

/// Loopback TLS fixture only. No test trust bypass is compiled into the daemon.
#[cfg(test)]
pub(crate) fn tls_test_store(transport:&[u8;65],biometric:&[u8;65],now:i64)->Store {
    let db=Connection::open_in_memory().unwrap();configure(&db,true).unwrap();db.execute_batch(SCHEMA).unwrap();
    db.execute("INSERT INTO host_meta VALUES(1,?,?)",params![&[99u8;16][..],now]).unwrap();
    let mut store=Store{db,_lock:None};
    store.add_principal(&Principal{id:[1;16],uid:1000,name:"user1000".into(),generation:[2;16]},now).unwrap();
    store.commit_enrollment(&Enrollment{id:[3;16],credential:[4;16],owner:[1;16],transport_key:transport,biometric_key:biometric,transport_chain:b"test-only",biometric_chain:b"test-only",attested_at:now,assurance_until:now+3600,status_checked_at:now,status_until:now+3600,token_hash:digest(&[5;32]),receipt_hash:digest(&[6;32]),offer_hash:[7;32],initial_cli_grant:true,cleanup_tokens:&[]},now).unwrap();
    store
}

// This driver builds only in instrumented fuzz builds. It constructs its own
// in-memory database and synthetic credentials; it is not a runtime adapter.
#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_state_trace(data: &[u8]) {
    if data.first().copied().unwrap_or(0) & 1 == 0 {
        tests::trace_auth(data.get(1..).unwrap_or_default());
    } else {
        authority::trace_enrollment(data.get(1..).unwrap_or_default());
    }
}
