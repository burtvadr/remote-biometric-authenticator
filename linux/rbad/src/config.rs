//! Filesystem layout and runtime configuration.
//!
//! Paths follow `PROTOCOL.md` §29 / the project brief: secrets and the device
//! registry live in a root-only directory. Everything is overridable so the
//! daemon and its tests can run unprivileged against a temporary directory.

use std::path::{Path, PathBuf};

/// Default root-only state directory.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/rba";
/// Default Unix socket for PAM and other local clients.
pub const DEFAULT_SOCKET: &str = "/run/rba/control.sock";
/// Default TCP port for the Wi-Fi transport.
pub const DEFAULT_TCP_PORT: u16 = 47123;
/// Default audit log path.
pub const DEFAULT_AUDIT_LOG: &str = "/var/log/rba/audit.log";

/// Group allowed to open the control socket, in addition to root.
pub const CONTROL_GROUP: &str = "rba";

#[derive(Debug, Clone)]
pub struct Config {
    /// Root-only directory holding `host.key`, `host.crt` and `registry.json`.
    pub state_dir: PathBuf,
    pub socket_path: PathBuf,
    pub audit_log: PathBuf,
    pub tcp_port: u16,
    /// TCP bind address. Loopback by default: exposing the port on a LAN is an
    /// explicit deployment decision (`--bind` / the systemd unit), never a
    /// library default.
    pub bind_addr: std::net::SocketAddr,
    /// Announce the host over mDNS/DNS-SD.
    pub advertise_mdns: bool,
    /// Transport preference (`PROTOCOL.md` §13).
    pub transport: rba_protocol::types::Transport,
    /// Optional fixed device endpoint, used when mDNS is unavailable (guest
    /// networks with multicast filtered, for example). Never a trust anchor:
    /// the address only decides where to send the first packet.
    pub device_endpoint: Option<SocketEndpoint>,
    /// Optional operator-visible host label. The systemd unit passes `%H` so the
    /// sandboxed daemon still reports the machine's real hostname.
    pub host_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEndpoint {
    pub host: String,
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
            socket_path: PathBuf::from(DEFAULT_SOCKET),
            audit_log: PathBuf::from(DEFAULT_AUDIT_LOG),
            tcp_port: DEFAULT_TCP_PORT,
            bind_addr: std::net::SocketAddr::from(([127, 0, 0, 1], DEFAULT_TCP_PORT)),
            advertise_mdns: true,
            transport: rba_protocol::types::Transport::Wifi,
            device_endpoint: None,
            host_name: None,
        }
    }
}

impl Config {
    /// A configuration rooted entirely inside `dir`, suitable for tests and for
    /// unprivileged operation.
    pub fn for_tests(dir: &Path, port: u16) -> Config {
        Config {
            state_dir: dir.join("state"),
            socket_path: dir.join("control.sock"),
            audit_log: dir.join("audit.log"),
            tcp_port: port,
            bind_addr: std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            advertise_mdns: false,
            transport: rba_protocol::types::Transport::Wifi,
            device_endpoint: None,
            host_name: Some("test-host".into()),
        }
    }

    pub fn host_key_path(&self) -> PathBuf {
        self.state_dir.join("host.key")
    }

    pub fn host_cert_path(&self) -> PathBuf {
        self.state_dir.join("host.crt")
    }

    pub fn host_tls_key_path(&self) -> PathBuf {
        self.state_dir.join("host-tls.key")
    }

    pub fn registry_path(&self) -> PathBuf {
        self.state_dir.join("registry.json")
    }
}

/// Creates `dir` with mode 0700 if it does not exist.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    Ok(())
}

/// Writes `contents` to `path` with mode 0600, replacing atomically via a
/// temporary file in the same directory.
pub fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    ensure_private_dir(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("rbad")
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paths_are_all_inside_the_state_dir() {
        let c = Config::default();
        for p in [c.host_key_path(), c.host_cert_path(), c.registry_path()] {
            assert!(p.starts_with(&c.state_dir), "{p:?} escaped the state dir");
        }
    }

    #[test]
    fn private_files_are_owner_only() {
        let dir = std::env::temp_dir().join(format!("rba-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("secret");
        write_private(&path, b"x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "host key must not be group/world readable");
        let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700);
        // No temporary files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left temp files: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
