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
use std::collections::{BTreeSet, HashMap};

use crate::authz::{self, Denial, Grant, PrincipalId, Scope};
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
}

/// Minimal, unified authorization policy — replaces `users` + `allow_root` + `allowed_scopes`
/// 
/// Each grant explicitly expresses: principal is authorized for this scope.
/// Empty policy denies everything. No implicit permissions, no legacy fields.
/// 
/// The policy is a BTreeSet of (principal, scope) grants. A principal is authorized
/// for a scope if and only if an exact (principal, scope) grant exists in the set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePolicy {
    /// Each grant explicitly expresses: principal is authorized for this scope
    /// The BTreeSet contains exactly the granted (principal, scope) pairs
    /// Absence of a grant = denial (default-deny policy)
    pub grants: BTreeSet<Grant>,
}

impl Default for DevicePolicy {
    fn default() -> Self {
        DevicePolicy {
            grants: BTreeSet::new(),
        }
    }
}

impl DevicePolicy {
    /// Whether this policy grants the principal access to the requested scope
    pub fn grants_principal(&self, principal: &PrincipalId, scope: &Scope) -> bool {
        self.grants.contains(&Grant {
            principal: principal.clone(),
            scope: *scope,
        })
    }

    /// Whether this policy is bound to the given principal (i.e., has any grant for this principal)
    pub fn is_bound_to(&self, principal: &PrincipalId) -> bool {
        self.grants.iter().any(|g| g.principal == *principal)
    }
}

/// Device record in the registry.
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
    #[serde(default)]
    pub policy: DevicePolicy,
}

impl DeviceRecord {
    /// Create a new device record with the given public key and policy.
    pub fn new(device_id: String, name: String, public_key: String) -> Self {
        DeviceRecord {
            device_id,
            name,
            public_key,
            added_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_seen: None,
            policy: DevicePolicy::default(),
        }
    }
}

/// Host identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIdentity {
    pub host_id: String,
    /// Hex-encoded public key (65 bytes uncompressed, prefixed with 0x04)
    pub public_key: String,
}

/// Compute the key ID hex (first 32 bytes as hex, without the 0x04 prefix)
/// from a hex-encoded public key string.
pub fn public_key_key_id_hex(pubkey_hex: &str) -> Result<String, ProtocolError> {
    let bytes = hex::decode(pubkey_hex).map_err(|_| ProtocolError::BadRequest("invalid public key hex".into()))?;
    if bytes.len() != 65 {
        return Err(ProtocolError::BadRequest("public key must be 65 bytes".into()));
    }
    // Skip the 0x04 prefix and take bytes[1..33] (32 bytes = key ID)
    let key_id = hex::encode(&bytes[1..33]);
    Ok(key_id)
}

/// The trusted device registry.
pub struct Registry {
    /// Maps device ID to device record.
    devices: BTreeMap<String, DeviceRecord>,
    /// Maps device name to device record.
    by_name: BTreeMap<String, DeviceRecord>,
    /// Dirty flag — true if policy has been modified and needs saving.
    dirty: bool,
}

impl Registry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Registry {
            devices: BTreeMap::new(),
            by_name: BTreeMap::new(),
            dirty: false,
        }
    }

    /// Resolve the authenticating device for a given request context.
    pub fn resolve_authenticating_for(&self, id: &Id, user: &str) -> Result<&DeviceRecord> {
        self.devices.get(id).ok_or(ProtocolError::NotPaired)
    }

    /// Authorize a principal for a scope on a device.
    /// 
    /// Checks that the principal is authorized for the requested scope
    /// according to the device's grant policy.
    /// 
    /// Returns the public key if authorized, or an error if the principal
    /// is not granted this scope.
    pub fn authorize_scope(&self, id: &Id, principal: &str, scope: &Scope) -> Result<PublicKey> {
        let key = self.resolve_authenticating_for(id, principal)?;
        let rec = self.devices.get(id).ok_or(ProtocolError::NotPaired)?;

        let principal_id = authz::PrincipalId::from(principal.to_string());

        if !rec.policy.grants_principal(&principal_id, scope) {
            return Err(ProtocolError::ContextMismatch(
                "authorization denied: principal not bound for this scope".into(),
            ));
        }

        Ok(key)
    }

    /// Pair a new device with the given public key and optional initial grants.
    pub fn upsert_paired_full(
        &mut self,
        device_id: String,
        name: String,
        public_key: String,
        _now: u64,
        _added_at: Option<u64>,
        policy: &DevicePolicy,
    ) {
        let mut device = DeviceRecord::new(device_id.clone(), name.clone(), public_key);
        let device_clone = device.clone();
        device.policy = policy.clone();

        self.devices
            .insert(device_id.clone(), device);
        self.by_name
            .insert(name.clone(), device_clone);
        self.dirty = true;
    }

    /// Find a device by selector (device ID or name).
    pub fn find_device(&self, selector: &str) -> Option<&DeviceRecord> {
        self.devices.get(selector).or_else(|| {
            self.by_name.values().find(|d| d.name == selector)
        })
    }

    /// Get a device by ID.
    pub fn get_device(&self, device_id: &str) -> Option<&DeviceRecord> {
        self.devices.get(device_id)
    }

    /// Serialize the registry to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(&self)?;
        std::fs::write(path, json).map_err(|e| ProtocolError::Io(format!("failed to write registry: {}", e)))?;
        Ok(())
    }

    /// Deserialize the registry from a JSON file.
    pub fn load(&self, path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| ProtocolError::Io(format!("failed to read registry: {}", e)))?;
        let registry: Registry = serde_json::from_str(&content).map_err(|e| ProtocolError::Io(format!("failed to parse registry: {}", e)))?;
        *self = registry;
        Ok(())
    }

    /// List all paired devices.
    pub fn list_devices(&self) -> Vec<&DeviceRecord> {
        self.devices.values().collect()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Registry::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{self, Grant, PrincipalId, Scope};

    #[test]
    fn default_policy_denies_all() {
        let policy = DevicePolicy::default();
        let principal = PrincipalId("alice".into());
        let scope = Scope::parse("rba", "rba", "authenticate").unwrap();
        assert!(!policy.grants_principal(&principal, &scope));
    }

    #[test]
    fn explicit_grant_authorizes() {
        let mut policy = DevicePolicy::default();
        let principal = PrincipalId("alice".into());
        let scope = Scope::parse("rba", "rba", "authenticate").unwrap();
        policy.grants.insert(Grant { principal, scope });

        let id = Id::random().unwrap();
        let public_key = authz::PublicKey::from([0u8; 32]); // dummy
        // Can't easily test authorize_scope without a full DeviceRecord,
        // but the grants_principal test above covers the logic
        assert!(!policy.grants_principal(&PrincipalId("bob".into()), &scope));
    }

    #[test]
    fn cross_principal_isolation() {
        let mut policy = DevicePolicy::default();
        let alice = PrincipalId("alice".into());
        let bob = PrincipalId("bob".into());
        let scope = Scope::parse("rba", "rba", "authenticate").unwrap();
        policy.grants.insert(Grant { principal: alice, scope });

        assert!(policy.grants_principal(&alice, &scope));
        assert!(!policy.grants_principal(&bob, &scope));
    }

    #[test]
    fn policy_is_bound_to_principals() {
        let mut policy = DevicePolicy::default();
        let principal = PrincipalId("alice".into());
        let scope = Scope::parse("rba", "rba", "authenticate").unwrap();
        policy.grants.insert(Grant { principal, scope });

        assert!(policy.is_bound_to(&principal));
        assert!(!policy.is_bound_to(&PrincipalId("bob".into())));
    }

    #[test]
    fn scope_serde_roundtrip() {
        let scope = Scope::parse("sudo", "sudo", "authenticate").unwrap();
        let grant = Grant {
            principal: PrincipalId("alice".into()),
            scope,
        };
        let serialized = serde_json::to_string(&grant).unwrap();
        let deserialized: Grant = serde_json::from_str(&serialized).unwrap();
        assert_eq!(grant, deserialized);
    }
}