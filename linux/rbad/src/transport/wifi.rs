//! Wi-Fi transport: TCP, TLS 1.3, and DNS-SD advertisement.
//!
//! The layering is deliberate:
//!
//! ```text
//! mDNS/DNS-SD   discovery only: "something is at this address"
//! TCP           byte stream
//! TLS 1.3      confidentiality + a pinned transport credential
//! protocol      the actual authentication decision
//! ```
//!
//! A successful TLS handshake is **not** an authentication result. The device is
//! trusted because it holds a private key registered at pairing time, and it
//! proves that per request with a signature.

use std::sync::Arc;

use tokio::net::TcpListener;

use rba_protocol::errors::{ProtocolError, Result};
use rba_protocol::types::Transport;

use crate::config::Config;
use crate::engine::Engine;
use crate::tls;

/// Maximum simultaneous Wi-Fi connections, including ones still in the TLS
/// handshake. A device uses one connection; the rest is headroom for reconnects.
const MAX_WIFI_CONNECTIONS: usize = 64;

/// Time allowed for the TLS handshake before the connection is dropped.
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// TCP keepalive timing. A device that dies without closing the socket (battery
/// pull, sudden loss of Wi-Fi) leaves a half-open connection that application
/// traffic cannot detect, because a healthy idle link sends no frames. Keepalive
/// probes notice the drop in roughly a minute instead of waiting out the full
/// idle read timeout, so `rba devices` stops claiming the device is available.
const KEEPALIVE_IDLE_SECS: libc::c_int = 30;
const KEEPALIVE_INTERVAL_SECS: libc::c_int = 10;
const KEEPALIVE_PROBES: libc::c_int = 3;

/// Enables TCP keepalive on an accepted device connection.
fn enable_keepalive(stream: &tokio::net::TcpStream) {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let set = |level: libc::c_int, opt: libc::c_int, val: libc::c_int| unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    };
    set(libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1);
    // The per-probe timing knobs are Linux-specific; elsewhere SO_KEEPALIVE alone
    // still applies the system default.
    #[cfg(target_os = "linux")]
    {
        set(libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, KEEPALIVE_IDLE_SECS);
        set(
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            KEEPALIVE_INTERVAL_SECS,
        );
        set(libc::IPPROTO_TCP, libc::TCP_KEEPCNT, KEEPALIVE_PROBES);
    }
}

/// Returns the host's non-VPN, non-loopback addresses for mDNS publication.
///
/// When `interface` is `Some`, only that interface's addresses are returned.
/// Otherwise all non-loopback, non-Tailscale (100.64.0.0/10) addresses are
/// included so a device on the LAN does not resolve the service to a VPN
/// address it cannot route to.
fn lan_addresses(interface: Option<&str>) -> Vec<std::net::IpAddr> {
    use std::net::IpAddr;
    let mut result = Vec::new();
    // Enumerate interfaces via the standard library's (limited) API. For named
    // interface filtering we fall back to checking all addresses; a full
    // interface-name filter would need the `nix` or `if-addrs` crate.
    for iface in get_if_addrs() {
        if let Some(name) = interface {
            if iface.name != name {
                continue;
            }
        }
        let addr = iface.addr;
        if addr.is_loopback() {
            continue;
        }
        // Tailscale: 100.64.0.0/10
        if let IpAddr::V4(v4) = addr {
            let octets = v4.octets();
            if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
                continue;
            }
        }
        result.push(addr);
    }
    result
}

/// Minimal interface enumeration. Uses `std::net` which doesn't expose interface
/// names, so we use a libc-based fallback for name filtering.
struct IfAddr {
    name: String,
    addr: std::net::IpAddr,
}

fn get_if_addrs() -> Vec<IfAddr> {
    // Use `hostname` crate? No. Use libc getifaddrs.
    let mut result = Vec::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return result;
        }
        let mut p = ifap;
        while !p.is_null() {
            let ifa = &*p;
            if !ifa.ifa_addr.is_null() {
                let family = (*ifa.ifa_addr).sa_family as i32;
                if family == libc::AF_INET {
                    let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                    let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                        .to_string_lossy()
                        .to_string();
                    result.push(IfAddr {
                        name,
                        addr: std::net::IpAddr::V4(ip),
                    });
                } else if family == libc::AF_INET6 {
                    let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
                    if !ip.is_loopback() {
                        let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                            .to_string_lossy()
                            .to_string();
                        result.push(IfAddr {
                            name,
                            addr: std::net::IpAddr::V6(ip),
                        });
                    }
                }
            }
            p = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    result
}

/// Advertises the host over DNS-SD so devices can find it without a fixed
/// address. Publication contains only non-secret metadata (`PROTOCOL.md` §13.1).
pub fn advertise(
    config: &Config,
    host_name: &str,
    host_key_id: &str,
) -> Result<mdns_sd::ServiceDaemon> {
    let daemon = mdns_sd::ServiceDaemon::new().map_err(|e| {
        ProtocolError::Internal(format!(
            "mDNS daemon unavailable (multicast may be filtered): {e}"
        ))
    })?;
    let props = [
        ("v", "1"),
        ("id", host_key_id),
        ("name", host_name),
        ("caps", "auth"),
    ];
    // The daemon needs a DNS hostname, not just a label. Host labels can contain
    // characters that mDNS rejects, and the crate requires the `.local.` suffix
    // explicitly, so derive one that is always valid.
    let mdns_host = {
        let label: String = host_name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .take(63)
            .collect();
        let label = label.trim_matches('-');
        if label.is_empty() {
            "rba.local.".to_string()
        } else {
            format!("{label}.local.")
        }
    };
    // A wildcard bind address is not a routable address. Advertising `0.0.0.0`
    // would tell devices to connect nowhere, so publish the host's real
    // interface addresses instead. Tailscale/VPN ranges (100.64.0.0/10) are
    // excluded by default so a device on the LAN does not resolve the service
    // to a VPN address it cannot route to.
    // Publish only non-VPN addresses. Tailscale uses 100.64.0.0/10; other VPNs
    // typically use 10.x or 172.16-31.x. We filter the Tailscale range
    // explicitly and let the operator override with --mdns-interface.
    let addresses: Vec<std::net::IpAddr> = if config.bind_addr.ip().is_unspecified() {
        lan_addresses(config.mdns_interface.as_deref())
    } else {
        vec![config.bind_addr.ip()]
    };

    if addresses.is_empty() {
        return Err(ProtocolError::Internal(
            "no non-VPN interface addresses to advertise; use --bind or --mdns-interface".into(),
        ));
    }

    let info = mdns_sd::ServiceInfo::new(
        rba_protocol::SERVICE_TYPE,
        host_name,
        &mdns_host,
        &addresses[..],
        config.tcp_port,
        &props[..],
    )
    .map_err(|e| ProtocolError::Internal(format!("mDNS service info: {e}")))?;
    daemon
        .register(info)
        .map_err(|e| ProtocolError::Internal(format!("mDNS register: {e}")))?;
    Ok(daemon)
}

/// Resolves candidate devices of this service type on the local network.
pub fn discover(timeout: std::time::Duration) -> Result<Vec<String>> {
    let daemon =
        mdns_sd::ServiceDaemon::new().map_err(|e| ProtocolError::Internal(format!("mDNS: {e}")))?;
    let receiver = daemon
        .browse(rba_protocol::SERVICE_TYPE)
        .map_err(|e| ProtocolError::Internal(format!("mDNS browse: {e}")))?;
    let mut found = Vec::new();
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        match receiver.recv_timeout(std::time::Duration::from_millis(250)) {
            Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                for addr in info.get_addresses() {
                    found.push(format!("{}:{}", addr, info.get_port()));
                }
            }
            Ok(_) => {}
            Err(e) => return Err(ProtocolError::Internal(format!("mDNS browse: {e}"))),
        }
    }
    Ok(found)
}

/// Binds the TCP listener and serves connections until `shutdown` resolves.
pub async fn serve(
    engine: Arc<Engine>,
    config: Config,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let (tls_config, fingerprint) = tls::server_config_with_fingerprint(&config)?;
    let tls_config = Arc::new(tls_config);
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .map_err(|e| ProtocolError::Internal(format!("bind {}: {e}", config.bind_addr)))?;
    let pairing_timeout = rba_protocol::types::PAIRING_TTL;
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_WIFI_CONNECTIONS));

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                enable_keepalive(&stream);
                let permit = match Arc::clone(&slots).try_acquire_owned() {
                    Ok(permit) => permit,
                    // No slot: drop the socket. This bounds descriptors, memory
                    // and tasks even under a stalled-connection flood.
                    Err(_) => continue,
                };
                let tls_cfg = tls_config.clone();
                let engine = engine.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let handshake = tokio::time::timeout(
                        TLS_HANDSHAKE_TIMEOUT,
                        tls::accept(stream, tls_cfg),
                    )
                    .await;
                    match handshake {
                        Ok(Ok(tls_stream)) => {
                            let peer_label = peer.to_string();
                            let conn = crate::transport::open(engine.clone(), tls_stream, Transport::Wifi, peer_label, Some(fingerprint));
                            if let Err(e) = conn.run(pairing_timeout).await {
                                let ev = crate::audit::Event::new("session_error")
                                    .denied(e.code().as_str())
                                    .detail(e.to_string());
                                engine.audit().write(&ev);
                            }
                        }
                        Ok(Err(e)) => {
                            // A failed TLS handshake is not an authentication
                            // event; it may just be an unrelated scanner.
                            let _ = e;
                        }
                        Err(_) => {
                            // Handshake deadline hit; the stream is dropped with
                            // the future.
                        }
                    }
                    let _ = shutdown;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    /// A silently-dead device must be detectable: the accepted socket has
    /// keepalive on, with the short probe timing rather than the system default.
    #[tokio::test]
    async fn accepted_device_connections_have_keepalive_enabled() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        enable_keepalive(&server);

        let get = |level: libc::c_int, opt: libc::c_int| -> libc::c_int {
            let mut val: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    server.as_raw_fd(),
                    level,
                    opt,
                    &mut val as *mut libc::c_int as *mut libc::c_void,
                    &mut len,
                )
            };
            assert_eq!(rc, 0, "getsockopt must succeed");
            val
        };
        assert_eq!(get(libc::SOL_SOCKET, libc::SO_KEEPALIVE), 1);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                get(libc::IPPROTO_TCP, libc::TCP_KEEPIDLE),
                KEEPALIVE_IDLE_SECS
            );
            assert_eq!(
                get(libc::IPPROTO_TCP, libc::TCP_KEEPINTVL),
                KEEPALIVE_INTERVAL_SECS
            );
            assert_eq!(get(libc::IPPROTO_TCP, libc::TCP_KEEPCNT), KEEPALIVE_PROBES);
        }
    }
}
