//! Pure authorization policy. No OS, transport, persistence or crypto I/O.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Authenticate,
    Authorize,
}

/// Purpose and service are exact namespaced identifiers supplied by an adapter.
/// No wildcard or implicit elevation is supported.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Scope {
    pub purpose: String,
    pub service: String,
    pub operation: Operation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    InvalidScope,
    PrincipalNotBound,
    ScopeNotGranted,
}

impl Scope {
    pub fn parse(purpose: &str, service: &str, operation: &str) -> Result<Self, Denial> {
        let valid = |s: &str| !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'/')
        });
        if !valid(purpose) || !valid(service) {
            return Err(Denial::InvalidScope);
        }
        let operation = match operation {
            "authenticate" => Operation::Authenticate,
            "authorize" => Operation::Authorize,
            _ => return Err(Denial::InvalidScope),
        };
        Ok(Self { purpose: purpose.into(), service: service.into(), operation })
    }
}

/// Canonical host-local identity, supplied by the trusted OS adapter.
/// The registry is local to one host. No interpretation of names occurs here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrincipalId(String);

impl PrincipalId {
    pub fn new(id: &str) -> Self {
        Self(id.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub principal: PrincipalId,
    pub scope: Scope,
}

impl Grant {
    pub fn new(principal: &str, scope: Scope) -> Self {
        Self { principal: PrincipalId::new(principal), scope }
    }
}

/// The only authorization rule: the exact principal and exact scope must occur
/// together in an explicit grant. Empty policies deny all operations.
pub fn evaluate(
    principal: &PrincipalId,
    grants: &std::collections::BTreeSet<Grant>,
    scope: &Scope,
) -> Result<(), Denial> {
    if grants.contains(&Grant { principal: principal.clone(), scope: scope.clone() }) {
        Ok(())
    } else if !grants.iter().any(|g| &g.principal == principal) {
        Err(Denial::PrincipalNotBound)
    } else {
        Err(Denial::ScopeNotGranted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn basic() -> Scope { Scope::parse("authenticate", "rba", "authenticate").unwrap() }
    fn sudo() -> Scope { Scope::parse("sudo", "sudo", "authenticate").unwrap() }

    #[test]
    fn empty_policy_denies_basic_and_privileged() {
        let grants = BTreeSet::new();
        for name in ["alice", "root"] {
            for scope in [basic(), sudo()] {
                assert_eq!(evaluate(&PrincipalId::new(name), &grants, &scope), Err(Denial::PrincipalNotBound));
            }
        }
    }

    #[test]
    fn grants_are_not_a_cartesian_product() {
        let grants = BTreeSet::from([Grant::new("alice", sudo()), Grant::new("bob", basic())]);
        assert!(evaluate(&PrincipalId::new("alice"), &grants, &sudo()).is_ok());
        assert!(evaluate(&PrincipalId::new("bob"), &grants, &basic()).is_ok());
        assert_eq!(evaluate(&PrincipalId::new("bob"), &grants, &sudo()), Err(Denial::ScopeNotGranted));
        assert_eq!(evaluate(&PrincipalId::new("alice"), &grants, &basic()), Err(Denial::ScopeNotGranted));
        assert_eq!(evaluate(&PrincipalId::new("charlie"), &grants, &basic()), Err(Denial::PrincipalNotBound));
    }

    #[test]
    fn privileged_identity_requires_its_own_grant() {
        let mut grants = BTreeSet::from([Grant::new("alice", sudo())]);
        assert!(evaluate(&PrincipalId::new("root"), &grants, &sudo()).is_err());
        grants.insert(Grant::new("root", sudo()));
        assert!(evaluate(&PrincipalId::new("root"), &grants, &sudo()).is_ok());
        assert!(evaluate(&PrincipalId::new("root"), &grants, &basic()).is_err());
    }

    #[test]
    fn unknown_operations_are_rejected() {
        assert_eq!(Scope::parse("sudo", "sudo", "unknown"), Err(Denial::InvalidScope));
        assert_eq!(Scope::parse("*", "sudo", "authenticate"), Err(Denial::InvalidScope));
    }
}
