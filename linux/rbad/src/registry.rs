//! Host identity and the trusted device registry.
//!
//! The registry is the authoritative store of *which authenticator devices this
//! host trusts*. It holds only public keys and metadata. Private keys never
//! enter this file: the host's own key lives beside it with mode 0600.

use std::collections::BTreeMap;
use std::path::Path;

use rba_protocol::crypto::{PrivateKey, PublicKey};
use rba_protocol::errors::{ProtocolError, Result};
use rba_protocol::types::Id;
use serde::{Deserialize, Serialize};

use crate::config;

/// Device lifecycle states (`PROTOCOL.md` / project brief §30).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// Explicitly trusted, may authenticate.
    Paired,
    /// Pairing started but not yet completed.
    Pairing,
    /// Revoked by the operator. Must never authenticate.
    Revoked,
    /// Its key was replaced; retained for audit only.
    Replaced,
}

impl DeviceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceStatus::Paired => "paired",
            DeviceStatus::Pairing => "pairing",
            DeviceStatus::Revoked => "revoked",
            DeviceStatus::Replaced => "replaced",
        }
    }

    /// Only a `Paired` device may authenticate. Everything else fails closed.
    pub fn may_authenticate(self) -> bool {
        matches!(self, DeviceStatus::Paired)
    }
}

/// Explicit principal/scope relationships for a single credential.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePolicy {
    pub grants: std::collections::BTreeSet<crate::authz::Grant>,
}

impl DevicePolicy {
    pub fn for_user(user: impl Into<String>) -> DevicePolicy {
        let user = user.into();
        let scope = crate::authz::Scope::parse("authenticate", "rba", "authenticate")
            .expect("constant enrollment scope");
        DevicePolicy { grants: std::collections::BTreeSet::from([crate::authz::Grant::new(&user, scope)]) }
    }

    /// Visibility/lifecycle filtering, never a substitute for scope evaluation.
    pub fn is_bound_to(&self, user: &str) -> bool {
        self.grants.iter().any(|g| g.principal.as_str() == user)
    }

    fn grants_display(&self) -> String {
        self.grants.iter().map(|g| format!("{}: {}/{}/{:?}", g.principal.as_str(), g.scope.purpose, g.scope.service, g.scope.operation)).collect::<Vec<_>>().join(", ")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: String,
    pub name: String,
    /// Lowercase hex of the raw 65-byte uncompressed public key.
    pub public_key: String,
    #[serde(default)]
    pub added_at: u64,
    #[serde(default)]
    pub last_seen: Option<u64>,
    pub status: DeviceStatus,
    /// Explicit authorization grants; an absent policy denies all operations.
    #[serde(default)]
    pub policy: DevicePolicy,
    /// SHA-256 of the bearer token that authorizes this device to revoke itself.
    #[serde(default)]
    pub revocation_token_hash: Option<String>,
    /// Number of successful authentications, for operator visibility.
    #[serde(default)]
    pub auth_count: u64,
}

impl DeviceRecord {
    pub fn id(&self) -> Result<Id> {
        Id::from_hex(&self.device_id)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        let raw = hex::decode(&self.public_key).map_err(|_| {
            ProtocolError::BadRequest(format!(
                "device {} has a malformed public key in the registry",
                self.device_id
            ))
        })?;
        PublicKey::from_bytes(&raw)
    }

    pub fn key_id(&self) -> Result<String> {
        Ok(self.public_key()?.key_id_hex())
    }

    /// Whether this record is bound to `user`, regardless of lifecycle state.
    pub fn is_bound_to(&self, user: &str) -> bool {
        self.policy.is_bound_to(user)
    }

    /// Rendering for `rba devices`. Contains no secrets.
    pub fn summary(&self) -> String {
        let fp = match self.public_key() {
            Ok(pk) => pk.short_fingerprint(),
            Err(_) => "????????????????".into(),
        };
        format!(
            "  {}\n    id:      {}\n    key:     SHA256:{}...\n    status:  {}\n    grants:  {}\n    paired:  {}\n    seen:    {}\n    auths:   {}",
            self.name,
            self.device_id,
            fp,
            self.status.as_str(),
            self.policy.grants_display(),
            format_epoch(self.added_at),
            match self.last_seen {
                Some(t) => format_epoch(t),
                None => "never".into(),
            },
            self.auth_count,
        )
    }
}

fn format_epoch(t: u64) -> String {
    if t == 0 {
        return "unknown".into();
    }
    // Minimal civil-time conversion; avoids pulling in a date dependency for
    // what is only an operator-facing hint.
    let days = (t / 86_400) as i64;
    let secs_of_day = t % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RegistryFile {
    #[serde(default)]
    devices: BTreeMap<String, DeviceRecord>,
}

/// In-memory registry with load/save. All mutations go through methods that
/// re-check invariants, so an impossible state cannot be written.
#[derive(Debug)]
pub struct Registry {
    path: std::path::PathBuf,
    devices: BTreeMap<Id, DeviceRecord>,
    dirty: bool,
}

impl Registry {
    pub fn load(path: &Path) -> Result<Registry> {
        let mut reg = Registry {
            path: path.to_path_buf(),
            devices: BTreeMap::new(),
            dirty: false,
        };
        if path.exists() {
            let raw = std::fs::read(path)
                .map_err(|e| ProtocolError::Internal(format!("read registry: {e}")))?;
            let file = serde_json::from_slice::<RegistryFile>(&raw)
                .map_err(|e| ProtocolError::Internal(format!("invalid or obsolete registry: {e}")))?;
            for rec in file.devices.values() {
                let id = rec.id()?;
                // A record with an unparseable key is dropped rather than
                // loaded: it can never authenticate, and keeping it would
                // suggest trust that does not exist.
                if rec.public_key().is_err() {
                    continue;
                }
                reg.devices.insert(id, rec.clone());
            }
        }
        Ok(reg)
    }

    pub fn in_memory() -> Registry {
        Registry {
            path: std::path::PathBuf::new(),
            devices: BTreeMap::new(),
            dirty: false,
        }
    }

    pub fn save(&mut self) -> Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        let mut file = RegistryFile::default();
        for (id, rec) in &self.devices {
            file.devices.insert(id.to_hex(), rec.clone());
        }
        let json = serde_json::to_vec_pretty(&file)
            .map_err(|e| ProtocolError::Internal(format!("serialise registry: {e}")))?;
        config::write_private(&self.path, &json)
            .map_err(|e| ProtocolError::Internal(format!("write registry: {e}")))?;
        self.dirty = false;
        Ok(())
    }

    pub fn all(&self) -> Vec<DeviceRecord> {
        self.devices.values().cloned().collect()
    }

    pub fn get(&self, id: &Id) -> Option<&DeviceRecord> {
        self.devices.get(id)
    }

    /// Resolves a device that is allowed to authenticate, or explains why not.
    pub fn resolve_authenticating(&self, id: &Id) -> Result<PublicKey> {
        let rec = self.devices.get(id).ok_or(ProtocolError::NotPaired)?;
        match rec.status {
            DeviceStatus::Paired => {}
            DeviceStatus::Revoked => return Err(ProtocolError::Revoked),
            DeviceStatus::Pairing => return Err(ProtocolError::NotPaired),
            DeviceStatus::Replaced => return Err(ProtocolError::NotPaired),
        }
        rec.public_key()
    }

    /// Evaluate current policy and return the credential used for verification.
    pub fn authorize_scope(&self, id: &Id, user: &str, scope: &crate::authz::Scope) -> Result<PublicKey> {
        let key = self.resolve_authenticating(id)?;
        let rec = self.devices.get(id).ok_or(ProtocolError::NotPaired)?;
        crate::authz::evaluate(
            &crate::authz::PrincipalId::new(user), &rec.policy.grants, scope,
        ).map_err(|reason| ProtocolError::ContextMismatch(format!("authorization denied: {reason:?}")))?;
        Ok(key)
    }

    /// Replace one exact scope grant. The caller must be the trusted administrator.
    pub fn set_scope(&mut self, id: &Id, permission: crate::authz::Grant, grant: bool) -> Result<()> {
        let rec = self.devices.get_mut(id).ok_or(ProtocolError::NotPaired)?;
        if !rec.status.may_authenticate() {
            return Err(ProtocolError::NotPaired);
        }
        let previous = rec.policy.grants.clone();
        if grant {
            rec.policy.grants.insert(permission);
        } else {
            rec.policy.grants.remove(&permission);
        }
        self.dirty = true;
        if let Err(error) = self.save() {
            self.devices.get_mut(id).expect("record exists").policy.grants = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn by_name(&self, name: &str) -> Vec<&DeviceRecord> {
        self.devices
            .values()
            .filter(|r| r.name.eq_ignore_ascii_case(name))
            .collect()
    }

    /// Adds or updates a paired device.
    ///
    /// Rejects a `device_id` already registered to a different public key: that
    /// is the shape of an attempt to take over an existing device identity, so
    /// it must fail rather than overwrite.
    pub fn upsert_paired(
        &mut self,
        device_id: Id,
        name: &str,
        pk: &PublicKey,
        now: u64,
    ) -> Result<()> {
        self.upsert_paired_full(device_id, name, pk, now, None, &DevicePolicy::default())
    }

    /// Same as [`Registry::upsert_paired`], recording the revocation token hash.
    pub fn upsert_paired_with_token(
        &mut self,
        device_id: Id,
        name: &str,
        pk: &PublicKey,
        now: u64,
        revocation_token_hash: Option<&str>,
    ) -> Result<()> {
        self.upsert_paired_full(
            device_id,
            name,
            pk,
            now,
            revocation_token_hash,
            &DevicePolicy::default(),
        )
    }

    /// Pairs a device for exactly one Linux user. Used by tests and simple
    /// callers that do not need the full policy.
    pub fn upsert_paired_for_user(
        &mut self,
        device_id: Id,
        name: &str,
        pk: &PublicKey,
        now: u64,
        user: &str,
    ) -> Result<()> {
        self.upsert_paired_full(
            device_id,
            name,
            pk,
            now,
            None,
            &DevicePolicy::for_user(user),
        )
    }

    /// Full form: records the account binding chosen at pairing time.
    ///
    /// Re-pairing an existing device replaces its policy: a fresh physical
    /// pairing is an explicit operator decision about who the device belongs to.
    pub fn upsert_paired_full(
        &mut self,
        device_id: Id,
        name: &str,
        pk: &PublicKey,
        now: u64,
        revocation_token_hash: Option<&str>,
        policy: &DevicePolicy,
    ) -> Result<()> {
        if let Some(existing) = self.devices.get(&device_id) {
            // A revoked record may be replaced by a fresh pairing, including one
            // with a new key. A still-usable record may only be replaced by the
            // same key; otherwise this is an identity takeover attempt.
            if existing.public_key != hex::encode(pk.as_bytes())
                && existing.status.may_authenticate()
            {
                return Err(ProtocolError::BadRequest(format!(
                    "device {} is already paired with a different key; revoke it first",
                    device_id.short()
                )));
            }
        }
        let rec = DeviceRecord {
            device_id: device_id.to_hex(),
            name: name.to_owned(),
            public_key: hex::encode(pk.as_bytes()),
            added_at: now,
            last_seen: Some(now),
            status: DeviceStatus::Paired,
            policy: policy.clone(),
            revocation_token_hash: revocation_token_hash.map(str::to_owned),
            auth_count: 0,
        };
        self.devices.insert(device_id, rec);
        self.dirty = true;
        self.save()
    }

    pub fn revoke(&mut self, id: &Id) -> Result<()> {
        let rec = self.devices.get_mut(id).ok_or(ProtocolError::NotPaired)?;
        rec.status = DeviceStatus::Revoked;
        self.dirty = true;
        self.save()
    }

    /// Marks a device `Replaced`: retained for audit, no longer usable.
    /// Used by `rba unpair`, where the operator removes trust but the record
    /// stays visible for forensics.
    pub fn unpair(&mut self, id: &Id) -> Result<()> {
        let rec = self.devices.get_mut(id).ok_or(ProtocolError::NotPaired)?;
        rec.status = DeviceStatus::Replaced;
        self.dirty = true;
        self.save()
    }

    /// Revokes the device whose revocation-token hash matches, if any.
    ///
    /// The token is a bearer capability; no device identity or signature is
    /// needed. Returns the revoked device id for auditing.
    pub fn revoke_by_token_hash(&mut self, hash: &str) -> Result<Option<Id>> {
        let id = self
            .devices
            .iter()
            .find(|(_, rec)| rec.revocation_token_hash.as_deref() == Some(hash))
            .map(|(id, _)| *id);
        if let Some(id) = id {
            self.revoke(&id)?;
            Ok(Some(id))
        } else {
            Ok(None)
        }
    }

    /// Removes a device entirely and returns it. Used by `pair --replace`, which
    /// marks the old record `Replaced` for audit before forgetting it.
    pub fn replace(&mut self, id: &Id) -> Result<DeviceRecord> {
        let rec = self.devices.remove(id).ok_or(ProtocolError::NotPaired)?;
        self.dirty = true;
        self.save()?;
        Ok(rec)
    }

    pub fn mark_seen(&mut self, id: &Id, now: u64) {
        if let Some(rec) = self.devices.get_mut(id) {
            rec.last_seen = Some(now);
            self.dirty = true;
        }
    }

    pub fn record_success(&mut self, id: &Id, now: u64) -> Result<()> {
        if let Some(rec) = self.devices.get_mut(id) {
            rec.auth_count += 1;
            rec.last_seen = Some(now);
            self.dirty = true;
        }
        self.save()
    }

    pub fn paired_count(&self) -> usize {
        self.devices
            .values()
            .filter(|r| r.status.may_authenticate())
            .count()
    }
}

// ---------------------------------------------------------------------------
// Host identity
// ---------------------------------------------------------------------------

/// The Linux host's long-term identity. Created on first run.
#[derive(Debug)]
pub struct HostIdentity {
    pub host_id: Id,
    pub key: PrivateKey,
}

impl HostIdentity {
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    /// Loads the host identity, generating it on first run.
    pub fn load_or_create(state_dir: &Path) -> Result<HostIdentity> {
        let key_path = state_dir.join("host.key");
        let id_path = state_dir.join("host.id");
        let key = if key_path.exists() {
            let pem = std::fs::read_to_string(&key_path)
                .map_err(|e| ProtocolError::Internal(format!("read host key: {e}")))?;
            PrivateKey::from_pem(&pem)?
        } else {
            let k = PrivateKey::generate()?;
            config::write_private(&key_path, k.to_pem().as_bytes())
                .map_err(|e| ProtocolError::Internal(format!("write host key: {e}")))?;
            k
        };
        let host_id = if id_path.exists() {
            let raw = std::fs::read_to_string(&id_path)
                .map_err(|e| ProtocolError::Internal(format!("read host id: {e}")))?;
            Id::from_hex(raw.trim())
                .map_err(|_| ProtocolError::Internal("host.id is corrupt".into()))?
        } else {
            let id = Id::random()?;
            config::write_private(&id_path, id.to_hex().as_bytes())
                .map_err(|e| ProtocolError::Internal(format!("write host id: {e}")))?;
            id
        };
        Ok(HostIdentity { host_id, key })
    }

    pub fn for_tests(key: PrivateKey, host_id: Id) -> HostIdentity {
        HostIdentity { host_id, key }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rba_protocol::crypto::PrivateKey;

    fn pk(seed: u8) -> PublicKey {
        PrivateKey::from_bytes(&[seed; 32]).unwrap().public_key()
    }

    /// PROTOCOL §11.3: a host may hold records for any number of devices. A user with
    /// a work device and a personal device is the ordinary case, not an edge case, and a
    /// registry that quietly kept only the last one would be indistinguishable from
    /// one that had silently dropped the other.
    #[test]
    fn a_host_holds_many_devices_and_keeps_them_all_usable() {
        let mut r = Registry::in_memory();
        let mut ids = Vec::new();
        for seed in 1..=4u8 {
            let id = Id::random().unwrap();
            r.upsert_paired(id, &format!("Pixel {seed}"), &pk(seed), 100)
                .unwrap();
            ids.push(id);
        }

        assert_eq!(r.paired_count(), 4);
        for id in &ids {
            assert!(
                r.resolve_authenticating(id).is_ok(),
                "every paired device must remain able to authenticate"
            );
        }
        let names: Vec<String> = r.all().iter().map(|d| d.name.clone()).collect();
        assert_eq!(
            names.len(),
            4,
            "no record may be displaced by a later pairing"
        );
    }

    /// Revocation is scoped to one (host, device) pair.
    #[test]
    fn revoking_one_device_leaves_the_others_paired() {
        let mut r = Registry::in_memory();
        let work = Id::random().unwrap();
        let personal = Id::random().unwrap();
        r.upsert_paired(work, "Work", &pk(1), 100).unwrap();
        r.upsert_paired(personal, "Personal", &pk(2), 100).unwrap();

        r.revoke(&work).unwrap();

        assert_eq!(r.resolve_authenticating(&work), Err(ProtocolError::Revoked));
        assert!(
            r.resolve_authenticating(&personal).is_ok(),
            "revoking one device must not lock out another"
        );
        assert_eq!(r.paired_count(), 1);
    }

    /// Re-pairing one device must not disturb another's record, including its key.
    #[test]
    fn re_pairing_one_device_leaves_another_untouched() {
        let mut r = Registry::in_memory();
        let a = Id::random().unwrap();
        let b = Id::random().unwrap();
        r.upsert_paired(a, "A", &pk(1), 100).unwrap();
        r.upsert_paired(b, "B", &pk(2), 100).unwrap();

        r.upsert_paired(a, "A renamed", &pk(1), 200).unwrap();

        assert_eq!(r.get(&b).unwrap().name, "B");
        assert_eq!(r.get(&b).unwrap().public_key, hex::encode(pk(2).as_bytes()));
        assert_eq!(r.get(&a).unwrap().name, "A renamed");
        assert_eq!(r.paired_count(), 2);
    }

    #[test]
    fn paired_devices_may_authenticate_but_revoked_ones_may_not() {
        let mut r = Registry::in_memory();
        let id = Id::random().unwrap();
        r.upsert_paired(id, "Pixel", &pk(1), 100).unwrap();
        assert!(r.resolve_authenticating(&id).is_ok());

        r.revoke(&id).unwrap();
        assert_eq!(r.resolve_authenticating(&id), Err(ProtocolError::Revoked));
    }

    #[test]
    fn a_device_is_bound_to_the_user_it_was_paired_for() {
        let mut r = Registry::in_memory();
        let id = Id::random().unwrap();
        r.upsert_paired_for_user(id, "Pixel", &pk(1), 100, "alice")
            .unwrap();

        let rec = r.get(&id).unwrap();
        assert!(rec.is_bound_to("alice"));
        assert!(!rec.is_bound_to("bob"));
        assert!(!rec.is_bound_to("root"));
        let scope = crate::authz::Scope::parse("authenticate", "rba", "authenticate").unwrap();
        assert!(r.authorize_scope(&id, "alice", &scope).is_ok());
        assert!(r.authorize_scope(&id, "bob", &scope).is_err());
    }

    #[test]
    fn root_is_denied_by_default_and_allowed_only_explicitly() {
        let mut r = Registry::in_memory();
        let id = Id::random().unwrap();
        r.upsert_paired_for_user(id, "Pixel", &pk(1), 100, "alice")
            .unwrap();
        assert!(!r.get(&id).unwrap().is_bound_to("root"));

        let mut policy = DevicePolicy::for_user("alice");
        policy.grants.extend(DevicePolicy::for_user("root").grants);
        r.upsert_paired_full(id, "Pixel", &pk(1), 200, None, &policy)
            .unwrap();
        assert!(r.get(&id).unwrap().is_bound_to("alice"));
        assert!(r.get(&id).unwrap().is_bound_to("root"));
        assert!(!r.get(&id).unwrap().is_bound_to("bob"));
    }

    #[test]
    fn existing_record_requires_explicit_privileged_scope_and_removal_denies() {
        let mut registry = Registry::in_memory();
        let id = Id::random().unwrap();
        registry.upsert_paired_for_user(id, "Pixel", &pk(1), 100, "alice").unwrap();
        let scope = crate::authz::Scope::parse("sudo", "sudo", "authenticate").unwrap();
        assert!(registry.authorize_scope(&id, "alice", &scope).is_err());
        registry.set_scope(&id, crate::authz::Grant::new("alice", scope.clone()), true).unwrap();
        assert!(registry.authorize_scope(&id, "alice", &scope).is_ok());
        registry.set_scope(&id, crate::authz::Grant::new("alice", scope.clone()), false).unwrap();
        assert!(registry.authorize_scope(&id, "alice", &scope).is_err());
    }

    /// A registry written before per-device policy existed must not become an
    /// allow-all after an upgrade. The missing field deserialises to deny-all.
    #[test]
    fn a_record_without_a_policy_denies_everyone() {
        let id = Id::random().unwrap();
        let raw = serde_json::json!({
            "device_id": id.to_hex(),
            "name": "Pixel",
            "public_key": hex::encode(pk(1).as_bytes()),
            "status": "paired",
        });
        let rec: DeviceRecord = serde_json::from_value(raw).unwrap();
        assert!(!rec.is_bound_to("alice"));
        assert!(!rec.is_bound_to("root"));
        assert!(rec.policy.grants.is_empty());
    }

    #[test]
    fn unknown_device_is_not_paired() {
        let r = Registry::in_memory();
        assert_eq!(
            r.resolve_authenticating(&Id::random().unwrap()),
            Err(ProtocolError::NotPaired)
        );
    }

    #[test]
    fn re_pairing_the_same_id_with_a_different_key_is_refused() {
        let mut r = Registry::in_memory();
        let id = Id::random().unwrap();
        r.upsert_paired(id, "Pixel", &pk(1), 100).unwrap();
        assert!(r.upsert_paired(id, "Impostor", &pk(2), 101).is_err());
        // The original is untouched.
        let rec = r.get(&id).unwrap();
        assert_eq!(rec.name, "Pixel");
        assert_eq!(rec.public_key, hex::encode(pk(1).as_bytes()));
    }

    #[test]
    fn re_pairing_the_same_id_with_the_same_key_updates_metadata() {
        let mut r = Registry::in_memory();
        let id = Id::random().unwrap();
        r.upsert_paired(id, "Pixel", &pk(1), 100).unwrap();
        r.upsert_paired(id, "Pixel 9", &pk(1), 200).unwrap();
        assert_eq!(r.get(&id).unwrap().name, "Pixel 9");
        assert_eq!(r.all().len(), 1);
    }

    #[test]
    fn registry_roundtrips_through_disk_with_private_permissions() {
        let dir = std::env::temp_dir().join(format!("rba-reg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("registry.json");

        let id = Id::random().unwrap();
        {
            let mut r = Registry::load(&path).unwrap();
            r.upsert_paired_for_user(id, "Pixel 9", &pk(3), 1700, "alice").unwrap();
        }
        let r = Registry::load(&path).unwrap();
        assert_eq!(r.get(&id).unwrap().name, "Pixel 9");
        assert_eq!(r.get(&id).unwrap().status, DeviceStatus::Paired);
        let basic = crate::authz::Scope::parse("authenticate", "rba", "authenticate").unwrap();
        assert!(r.authorize_scope(&id, "alice", &basic).is_ok());
        assert!(r.authorize_scope(&id, "bob", &basic).is_err());

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_key_in_the_registry_is_dropped_not_trusted() {
        let dir = std::env::temp_dir().join(format!("rba-reg2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("registry.json");
        let good = Id::random().unwrap();
        let bad = Id::random().unwrap();
        let json = format!(
            r#"{{"devices":{{
                "{}":{{"device_id":"{}","name":"Good","public_key":"{}","status":"paired"}},
                "{}":{{"device_id":"{}","name":"Bad","public_key":"00112233","status":"paired"}}
            }}}}"#,
            good.to_hex(),
            good.to_hex(),
            hex::encode(pk(4).as_bytes()),
            bad.to_hex(),
            bad.to_hex(),
        );
        std::fs::write(&path, json).unwrap();
        let r = Registry::load(&path).unwrap();
        assert!(r.get(&good).is_some());
        assert!(r.get(&bad).is_none(), "malformed key must not be loaded");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_identity_is_stable_across_loads() {
        let dir = std::env::temp_dir().join(format!("rba-host-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = HostIdentity::load_or_create(&dir).unwrap();
        let b = HostIdentity::load_or_create(&dir).unwrap();
        assert_eq!(a.host_id, b.host_id);
        assert_eq!(a.public_key(), b.public_key());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revocation_token_lookup_revokes_only_the_matching_record() {
        let mut r = Registry::in_memory();
        let a = Id::random().unwrap();
        let b = Id::random().unwrap();
        r.upsert_paired_with_token(a, "Pixel A", &pk(1), 10, Some("hash-a"))
            .unwrap();
        r.upsert_paired_with_token(b, "Pixel B", &pk(2), 10, Some("hash-b"))
            .unwrap();

        assert_eq!(r.revoke_by_token_hash("hash-b").unwrap(), Some(b));
        assert_eq!(
            r.get(&a).unwrap().status,
            DeviceStatus::Paired,
            "unrelated token must not revoke the other device"
        );
        assert_eq!(r.get(&b).unwrap().status, DeviceStatus::Revoked);
        assert_eq!(r.revoke_by_token_hash("missing").unwrap(), None);
    }

    #[test]
    fn a_revoked_record_can_be_replaced_with_a_new_key() {
        let mut r = Registry::in_memory();
        let id = Id::random().unwrap();
        r.upsert_paired_with_token(id, "Pixel", &pk(1), 10, Some("old"))
            .unwrap();
        r.revoke(&id).unwrap();
        r.upsert_paired_with_token(id, "Pixel 2", &pk(2), 20, Some("new"))
            .unwrap();
        assert_eq!(r.get(&id).unwrap().status, DeviceStatus::Paired);
        assert!(r.resolve_authenticating(&id).is_ok());
        assert_eq!(
            r.get(&id).unwrap().revocation_token_hash.as_deref(),
            Some("new")
        );
    }

    #[test]
    fn summary_contains_no_private_material() {
        let mut r = Registry::in_memory();
        let id = Id::random().unwrap();
        r.upsert_paired(id, "Pixel 9", &pk(5), 1_700_000_000)
            .unwrap();
        let s = r.get(&id).unwrap().summary();
        assert!(s.contains("Pixel 9"));
        assert!(!s.contains("PRIVATE"));
        assert!(!s.contains("secret"));
    }

    #[test]
    fn epoch_formatting_is_sane() {
        assert_eq!(format_epoch(0), "unknown");
        assert_eq!(format_epoch(1_700_000_000), "2023-11-14T22:13:20Z");
    }
}
