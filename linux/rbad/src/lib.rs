//! `rbad`: the Linux side of the Remote Biometric Authenticator.
//!
//! The crate is split so that each layer can be tested in isolation:
//!
//! * [`protocol`] (external) — canonical CBOR, framing, crypto, verification
//! * [`registry`] — trusted device registry and host identity
//! * [`engine`] — challenge generation, dispatch, verification, pairing
//! * [`transport`] — Wi-Fi (TCP/TLS/mDNS) and BLE adapters
//! * [`ipc`] — peer-credential-checked local control socket
//! * [`audit`] — structured logging with no secret-bearing API
//!
//! Every authentication path terminates in a deny-by-default decision.

pub mod audit;
pub mod authz;
pub mod config;
pub mod engine;
pub mod ipc;
pub mod registry;
pub mod server;
pub mod tls;
pub mod transport;

use std::sync::Arc;

use rba_protocol::types::Transport;

use crate::audit::AuditLog;
use crate::config::Config;
use crate::engine::Engine;
use crate::registry::{HostIdentity, Registry};

/// Everything the daemon needs, assembled once at startup.
pub struct Daemon {
    pub config: Config,
    pub engine: Arc<Engine>,
}

impl Daemon {
    /// Loads or creates persistent state and builds the engine.
    pub fn bootstrap(config: Config, echo_audit: bool) -> Result<Daemon, String> {
        config::ensure_private_dir(&config.state_dir).map_err(|e| {
            format!(
                "cannot create state directory {}: {e}",
                config.state_dir.display()
            )
        })?;
        let host = HostIdentity::load_or_create(&config.state_dir)
            .map_err(|e| format!("cannot load host identity: {e}"))?;
        let registry = Registry::load(&config.registry_path())
            .map_err(|e| format!("cannot load device registry: {e}"))?;
        let audit = AuditLog::to_file(&config.audit_log)
            .map_err(|e| format!("cannot open audit log {}: {e}", config.audit_log.display()))?
            .with_echo(echo_audit);
        let name = config.host_name.clone().unwrap_or_else(host_name);
        let rate_path = config.state_dir.join("ratelimits");
        let engine = Engine::with_rate_limit_path(host, registry, audit, name, Some(rate_path));
        Ok(Daemon { config, engine })
    }

    /// Loads and validates configuration without opening the audit log.
    ///
    /// Used by `--check`, which must be runnable before any privileged file
    /// exists (for example from a package post-install script running as a
    /// normal user). It reports what *would* happen instead.
    pub fn bootstrap_check(config: Config) -> Result<Daemon, String> {
        config::ensure_private_dir(&config.state_dir).map_err(|e| {
            format!(
                "cannot create state directory {}: {e}",
                config.state_dir.display()
            )
        })?;
        let host = HostIdentity::load_or_create(&config.state_dir)
            .map_err(|e| format!("cannot load host identity: {e}"))?;
        let registry = Registry::load(&config.registry_path())
            .map_err(|e| format!("cannot load device registry: {e}"))?;
        let name = config.host_name.clone().unwrap_or_else(host_name);
        Ok(Daemon {
            config,
            engine: Engine::with_rate_limit_path(host, registry, AuditLog::null(), name, None),
        })
    }

    /// A daemon with in-memory state, for tests.
    pub fn in_memory(config: Config) -> Daemon {
        let key = rba_protocol::crypto::PrivateKey::generate().expect("OS randomness is required");
        let host = HostIdentity {
            host_id: "test-host".into(),
            public_key: "0400a0c9d3b6e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e".into(),
        };
        let audit = AuditLog::null();
        let engine = Engine::with_rate_limit_path(
            host,
            Registry::new(),
            audit,
            "test-host".into(),
            None,
        );
        Daemon { config, engine }
    }
}

/// Host label shown on the device. Derived from the hostname for operator
/// convenience only; never part of any trust decision.
pub fn host_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty() && s.len() <= 64)
        .unwrap_or_else(|| "linux-host".to_string())
}

/// The default transport preference.
pub const DEFAULT_TRANSPORT: Transport = Transport::Wifi;
