//! Pure authorization policy. No OS, transport, persistence or crypto I/O.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

/// Represents a requested operation with its purpose and service context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Authenticate,
    Authorize,
}

/// Granular denial reasons for authorization failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    InvalidScope,          // malformed or unknown scope
    PrincipalNotBound,   // caller not recognized as authorized principal
    RootNotGranted,      // root access not explicitly granted
    ScopeNotGranted,     // scope not explicitly granted for this operation
}

/// Scope (purpose, service, operation) identifying an authorization boundary.
/// Exact string matching; no wildcards or implicit elevation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// The purpose identifier (e.g., "rba", "sudo")
    pub purpose: String,
    /// The service identifier (e.g., "rba", "sudo")
    pub service: String,
    /// The operation being requested
    pub operation: Operation,
}

impl Scope {
    /// Parse a scope from three space-separated strings: purpose, service, operation.
    /// 
    /// Validates that strings are non-empty, at most 128 bytes, and contain
    /// only ASCII alphanumeric characters, hyphens, underscores, dots, colons, or slashes.
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

    /// Check if this is a basic authentication scope (rba/rba/authenticate).
    pub fn is_basic(&self) -> bool {
        self.purpose == "authenticate" && self.service == "rba"
            && self.operation == Operation::Authenticate
    }
}

impl Hash for Scope {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.purpose.hash(state);
        self.service.hash(state);
        self.operation.hash(state);
    }
}

/// A complete authorization relationship between a principal and an operation.
/// Each grant explicitly expresses: principal is authorized for this scope.
/// The absence of a grant denotes denial — no implicit permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The identity being authenticated — resolved by platform adapter
    pub principal: PrincipalId,
    
    /// The scope being granted — exact purpose/service/operation
    pub scope: Scope,
}

/// Minimal, unified authorization policy — replaces users + allow_root + allowed_scopes
/// 
/// Each grant explicitly expresses: principal is authorized for this scope.
/// Empty policy denies everything. No implicit permissions, no legacy fields.
/// 
/// The policy is a HashSet of (principal, scope) grants. A principal is authorized
/// for a scope if and only if an exact (principal, scope) grant exists in the set.
pub struct DevicePolicy {
    /// Each grant explicitly expresses: principal is authorized for this scope
    /// The HashSet contains exactly the granted (principal, scope) pairs
    /// Absence of a grant = denial (default-deny policy)
    pub grants: HashSet<Grant>,
}

impl Default for DevicePolicy {
    fn default() -> Self {
        DevicePolicy {
            grants: HashSet::new(),
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

/// Central authorization evaluator — no platform I/O, testable in isolation
/// 
/// Evaluates whether a principal is authorized for a given scope,
/// given the device's policy configuration.
/// 
/// # Security
/// - Default-deny: absent grants deny
/// - Root requires explicit grant (no implicit elevation)
/// - Principal must have exact (principal, scope) grant
/// - Scope must be explicitly granted
pub fn evaluate(
    principal: PrincipalId,
    policy_grants: &HashSet<Grant>,
) -> Result<(), Denial> {
    // Check if there's an explicit grant for this principal and scope
    if policy_grants.contains(&Grant {
        principal: principal.clone(),
        scope: /* scope */,
    }) {
        return Ok(());
    }
    
    // No explicit grant = denial (default-deny)
    Err(Denial::ScopeNotGranted)
}

/// Convenience overload that takes a scope parameter
pub fn evaluate_with_scope(
    principal: PrincipalId,
    policy_grants: &HashSet<Grant>,
    scope: &Scope,
) -> Result<(), Denial> {
    // Check if there's an explicit grant for this principal and scope
    if policy_grants.contains(&Grant {
        principal: principal.clone(),
        scope: *scope,
    }) {
        return Ok(());
    }
    
    // No explicit grant = denial (default-deny)
    Err(Denial::ScopeNotGranted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authenticate_scope() -> Scope {
        Scope::parse("rba", "rba", "authenticate").unwrap()
    }

    fn sudo_scope() -> Scope {
        Scope::parse("sudo", "sudo", "authenticate").unwrap()
    }

    #[test]
    fn grant_denies_unauthorized_principal() {
        // Empty policy denies everything
        let policy = DevicePolicy::default();
        let principal = PrincipalId("alice".into());
        assert_eq!(evaluate_with_scope(principal, &policy.grants, &authenticate_scope), Err(Denial::ScopeNotGranted));
    }

    #[test]
    fn grant_allows_authorized_principal() {
        let mut grants = HashSet::new();
        grants.insert(Grant { principal: PrincipalId("alice".into()), scope: authenticate_scope });
        let policy = DevicePolicy { grants };
        let principal = PrincipalId("alice".into());
        assert!(evaluate_with_scope(principal, &policy.grants, &authenticate_scope).is_ok());
    }

    #[test]
    fn cross_principal_isolation() {
        let mut grants = HashSet::new();
        grants.insert(Grant { principal: PrincipalId("alice".into()), scope: authenticate_scope });
        let policy = DevicePolicy { grants };
        // bob should be denied even though alice is authorized
        let principal = PrincipalId("bob".into());
        assert_eq!(evaluate_with_scope(principal, &policy.grants, &authenticate_scope), Err(Denial::ScopeNotGranted));
    }

    #[test]
    fn root_access_requires_explicit_grant() {
        let mut grants = HashSet::new();
        // root does NOT get automatic access — must be explicit
        let policy = DevicePolicy { grants };
        let principal = PrincipalId("root".into());
        assert_eq!(evaluate_with_scope(principal, &policy.grants, &authenticate_scope), Err(Denial::RootNotGranted));
    }

    #[test]
    fn root_with_explicit_grant() {
        let mut grants = HashSet::new();
        grants.insert(Grant { principal: PrincipalId("root".into()), scope: authenticate_scope });
        let policy = DevicePolicy { grants };
        let principal = PrincipalId("root".into());
        assert!(evaluate_with_scope(principal, &policy.grants, &authenticate_scope).is_ok());
    }

    #[test]
    fn unknown_operations_are_rejected() {
        assert_eq!(Scope::parse("sudo", "sudo", "unknown"), Err(Denial::InvalidScope));
    }
}