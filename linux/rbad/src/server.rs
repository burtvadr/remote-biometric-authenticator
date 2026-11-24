//! Process wiring: the control socket, the transport listeners, and shutdown.
//!
//! The control socket is the only way an unprivileged process can reach the
//! engine, and every request on it is attributed to a verified peer UID before
//! it is allowed to name a Linux user (`PROTOCOL.md` §14).

use std::os::fd::AsRawFd;
use std::sync::Arc;

use rba_protocol::errors::{ProtocolError, Result};
use rba_protocol::pairing::CodeEntry;
use rba_protocol::types::Transport;
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};

use crate::audit::Event;
use crate::config::{self, Config};
use crate::engine::Engine;
use crate::ipc::{self, ControlRequest, ControlResponse};
use crate::transport;

/// Default timeout for an authentication, generous enough for a human to
/// complete a fingerprint check plus a confirmation dialog.
pub const DEFAULT_AUTH_TIMEOUT_MS: u64 = 90_000;

/// Hard cap on a caller-supplied authentication timeout. The protocol's
/// authentication request lifetime is the natural upper bound: a request that
/// lives longer than this cannot be valid anyway.
pub const MAX_AUTH_TIMEOUT_MS: u64 = rba_protocol::types::AUTH_REQUEST_TTL_MAX * 1_000;

/// Concurrent control-socket connections. PAM and the CLI are one-shot clients,
/// so this is far above normal use while still bounding descriptors and tasks.
const MAX_CONTROL_CONNECTIONS: usize = 32;

/// Time allowed to send one request or receive one response.
const CONTROL_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Binds the local control socket.
///
/// The socket is reachable by any local user; the daemon authorises every
/// request from `SO_PEERCRED` and the per-device account binding. Filesystem
/// permissions are therefore not the user boundary, and there is no group for an
/// operator to join before `rba` works.
///
/// Must be called from inside the Tokio runtime: converting a std listener into a
/// reactor-aware one requires a live reactor.
pub fn bind_control_socket(path: &std::path::Path) -> Result<UnixListener> {
    if let Some(parent) = path.parent() {
        config::ensure_private_dir(parent).map_err(|e| {
            ProtocolError::Internal(format!("create socket dir {}: {e}", parent.display()))
        })?;
    }
    // A stale socket from a crashed daemon must not block startup.
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = std::os::unix::net::UnixListener::bind(path)
        .map_err(|e| ProtocolError::Internal(format!("bind {}: {e}", path.display())))?;
    // Publish the socket before it accepts connections. Every request is still
    // authenticated from the peer's kernel credentials.
    publish_socket(path);
    listener
        .set_nonblocking(true)
        .map_err(|e| ProtocolError::Internal(format!("set nonblocking: {e}")))?;
    UnixListener::from_std(listener)
        .map_err(|e| ProtocolError::Internal(format!("register listener: {e}")))
}

/// Makes the socket reachable by every local user.
///
/// This is deliberate: the socket is a local API, not an administrative one.
/// Pairing, listing, status and authentication are each authorised from the
/// caller's UID and the device policy; `revoke` remains root-only.
fn publish_socket(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
}

/// Serves the control socket until `shutdown` fires.
pub async fn serve_control(
    engine: Arc<Engine>,
    config: Config,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let listener = bind_control_socket(&config.socket_path)?;
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONTROL_CONNECTIONS));
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    let _ = std::fs::remove_file(&config.socket_path);
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        // Transient accept errors (EMFILE, ECONNABORTED) must not
                        // kill the daemon.
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::WouldBlock
                        ) {
                            continue;
                        }
                        return Err(ProtocolError::Internal(format!("accept: {e}")));
                    }
                };
                let permit = match Arc::clone(&slots).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        // Dropping `stream` closes the connection. A client that
                        // cannot get a slot is refused rather than queued, so
                        // stalled callers cannot accumulate tasks.
                        continue;
                    }
                };
                let engine = engine.clone();
                let cfg = config.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_control_connection(engine.clone(), stream, cfg).await {
                        engine
                            .audit()
                            .write(&Event::new("ipc_error").denied("INTERNAL").detail(e.to_string()));
                    }
                });
            }
        }
    }
}

async fn handle_control_connection(
    engine: Arc<Engine>,
    stream: UnixStream,
    config: Config,
) -> Result<()> {
    // Peer credentials must be read from the socket itself, before any request
    // is interpreted.
    let peer = ipc::peer_credentials(stream.as_raw_fd())
        .map_err(|e| ProtocolError::Internal(format!("SO_PEERCRED: {e}")))?;

    let (r, w) = tokio::io::split(stream);
    let mut reader = BufReader::new(r);
    let mut writer = w;

    let Some(request) = tokio::time::timeout(CONTROL_IO_TIMEOUT, ipc::read_request(&mut reader))
        .await
        .map_err(|_| ProtocolError::BadRequest("control request timed out".into()))?
        .map_err(|e| ProtocolError::BadRequest(format!("control request: {e}")))?
    else {
        return Ok(());
    };

    let response = dispatch(&engine, &config, peer, request).await;
    tokio::time::timeout(
        CONTROL_IO_TIMEOUT,
        ipc::write_response(&mut writer, &response),
    )
    .await
    .map_err(|_| ProtocolError::Internal("control response timed out".into()))?
    .map_err(|e| ProtocolError::Internal(format!("write control response: {e}")))?;
    Ok(())
}

async fn dispatch(
    engine: &Arc<Engine>,
    config: &Config,
    peer: ipc::PeerCredentials,
    request: ControlRequest,
) -> ControlResponse {
    let peer_key = format!("uid:{}", peer.uid);
    let viewer = match ipc::viewer_name(peer) {
        Ok(viewer) => viewer,
        Err(e) => return ControlResponse::from_protocol_error(&e),
    };

    match request {
        ControlRequest::List => ControlResponse::ok(serde_json::json!({
            "devices": engine.list_devices(viewer.as_deref()),
        })),

        ControlRequest::Status => ControlResponse::ok(engine.status(viewer.as_deref(), &peer_key)),

        ControlRequest::PairingStatus => {
            match engine.pairing_status_for(&peer_key, false) {
                Ok(Some(status)) => ControlResponse::ok(status),
                Ok(None) => ControlResponse::ok(serde_json::json!({ "active": false })),
                Err(e) => ControlResponse::from_protocol_error(&e),
            }
        }

        ControlRequest::Pair {
            code_entry,
            timeout_ms: _,
            owner,
        } => {
            let mode = match code_entry.as_deref() {
                None | Some("device") => CodeEntry::Device,
                Some("host") => CodeEntry::Host,
                Some(other) => {
                    return ControlResponse::from_protocol_error(&ProtocolError::BadRequest(
                        format!("unknown code_entry {other:?}; expected device or host"),
                    ))
                }
            };
            // The device is bound to the local principal that opened pairing.
            // Root must name an existing account explicitly; it is never an
            // implicit owner, and choosing that account explicitly grants basic authentication only.
            let owner = match (viewer.as_deref(), owner) {
                (None, Some(owner)) if !owner.is_empty() => {
                    if !ipc::user_exists(&owner) {
                        return ControlResponse::err(
                            "BAD_REQUEST",
                            format!("no such local user: {owner}"),
                        );
                    }
                    owner
                }
                (None, _) => {
                    return ControlResponse::err(
                        "BAD_REQUEST",
                        "root must pass --owner USER; root is not an implicit owner",
                    )
                }
                (Some(me), Some(owner)) if owner == me => owner,
                (Some(me), Some(_)) => {
                    return ControlResponse::err(
                        "CONTEXT_MISMATCH",
                        format!(
                            "caller is {me}; a device can only be paired for the invoking user"
                        ),
                    )
                }
                (Some(me), None) => me.to_owned(),
            };
            match engine.begin_pairing_with_mode(mode, owner, peer_key) {
                Ok((chosen, expires_at)) => ControlResponse::ok(serde_json::json!({
                    "display_code": chosen,
                    "expires_at": expires_at,
                    "seconds_remaining": expires_at.saturating_sub(rba_protocol::unix_now()),
                    "phase": "awaiting_device",
                    "code_entry": mode.as_str(),
                    "instructions": match mode {
                        CodeEntry::Device => "Enter the code shown here on the device.",
                        CodeEntry::Host => "Enter the code shown on the device here.",
                    },
                })),
                Err(e) => ControlResponse::from_protocol_error(&e),
            }
        }

        ControlRequest::ConfirmPairing { code } => {
            if engine.pairing_active() && !engine.pairing_opened_by(&peer_key) {
                return ControlResponse::err(
                    "PERMISSION_DENIED",
                    "this pairing session was opened by another user",
                );
            }
            match engine.confirm_pairing_with_code(&peer_key, code.as_deref()) {
                Ok(()) => ControlResponse::ok(serde_json::json!({ "confirmed": true })),
                Err(e) => ControlResponse::from_protocol_error(&e),
            }
        }

        ControlRequest::PairingConfirmed => {
            // This is a query, not a confirmation: the host-side human gate was
            // already passed via ConfirmPairing. Here the caller learns whether
            // the device sent PAIRING_CONFIRMED after persisting its record.
            if let Some(confirmed) = engine.pairing_acknowledged_by(&peer_key) {
                return ControlResponse::ok(serde_json::json!({
                    "confirmed": confirmed,
                    "active": false,
                    "completed": true,
                }));
            }
            if !engine.pairing_active() {
                return ControlResponse::err(
                    "NOT_PAIRED",
                    "no active or completed pairing session",
                );
            }
            if !engine.pairing_opened_by(&peer_key) {
                return ControlResponse::err(
                    "PERMISSION_DENIED",
                    "this pairing session was opened by another user",
                );
            }
            ControlResponse::ok(serde_json::json!({
                "confirmed": false,
                "active": true,
                "seconds_remaining": engine.pairing_remaining().unwrap_or(0),
            }))
        }

        ControlRequest::CancelPairing => {
            match engine.cancel_pairing_for(&peer_key, peer.uid == 0) {
                Ok(()) => ControlResponse::ok(serde_json::json!({ "cancelled": true })),
                Err(e) => ControlResponse::from_protocol_error(&e),
            }
        }

        ControlRequest::Authenticate {
            user,
            purpose,
            service,
            operation,
            device,
            timeout_ms,
        } => {
            // Bind the request to the verified peer before anything else.
            let username = match ipc::authorize_caller(peer, &user) {
                Ok(u) => u,
                Err(e) => {
                    engine.audit().write(
                        &Event::new("auth")
                            .denied(e.code().as_str())
                            .username(user.clone())
                            .local_uid(peer.uid)
                            .detail("caller may not authenticate as that user"),
                    );
                    return ControlResponse::from_protocol_error(&e);
                }
            };
            match engine
                .authenticate(crate::engine::AuthContext {
                    local_uid: peer.uid,
                    username: &username,
                    purpose: &purpose,
                    service: &service,
                    operation: &operation,
                    device_selector: device.as_deref(),
                    timeout_ms: timeout_ms
                        .unwrap_or(DEFAULT_AUTH_TIMEOUT_MS)
                        .clamp(1, MAX_AUTH_TIMEOUT_MS),
                    transport_pref: config.transport,
                })
                .await
            {
                Ok(outcome) => ControlResponse::ok(outcome.to_json()),
                Err(e) => ControlResponse::from_protocol_error(&e),
            }
        }

        ControlRequest::SetScope { device, user, purpose, service, operation, grant } => {
            if peer.uid != 0 {
                return ControlResponse::err("PERMISSION_DENIED", "only root may change scope grants");
            }
            let scope = match crate::authz::Scope::parse(&purpose, &service, &operation) {
                Ok(scope) => scope,
                Err(_) => return ControlResponse::err("BAD_REQUEST", "invalid scope"),
            };
            if grant && !ipc::user_exists(&user) {
                return ControlResponse::err("BAD_REQUEST", "grant requires a canonical local account");
            }
            match engine.set_device_scope(&device, crate::authz::Grant::new(&user, scope), grant) {
                Ok(()) => ControlResponse::ok(serde_json::json!({ "updated": true })),
                Err(e) => ControlResponse::from_protocol_error(&e),
            }
        }
        ControlRequest::Revoke { device } => {
            // Revocation changes who may authenticate, so only root may do it.
            if peer.uid != 0 {
                return ControlResponse::err(
                    "PERMISSION_DENIED",
                    "only root may revoke an authenticator",
                );
            }
            match engine.revoke_device(&device) {
                Ok(name) => ControlResponse::ok(serde_json::json!({ "revoked": name })),
                Err(e) => ControlResponse::from_protocol_error(&e),
            }
        }

        ControlRequest::Unpair { device } => {
            // Shared credentials can only be removed by an administrator.
            match engine.unpair_device(&device, viewer.as_deref()) {
                Ok(name) => ControlResponse::ok(serde_json::json!({ "unpaired": name })),
                Err(e) => ControlResponse::from_protocol_error(&e),
            }
        }
    }
}

/// Starts every listener and waits for shutdown.
pub async fn run(
    engine: Arc<Engine>,
    config: Config,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mdns = if config.advertise_mdns {
        let host_key_id = engine.host.public_key().key_id_hex();
        match transport::wifi::advertise(&config, &engine.host_name, &host_key_id) {
            Ok(d) => Some(d),
            Err(e) => {
                // Discovery failing must not stop authentication: a device can
                // still connect by address.
                engine
                    .audit()
                    .write(&Event::new("mdns_unavailable").detail(e.to_string()));
                None
            }
        }
    } else {
        None
    };

    let wifi = transport::wifi::serve(engine.clone(), config.clone(), shutdown.clone());
    let ctl = serve_control(engine.clone(), config, shutdown.clone());

    tokio::select! {
        r = wifi => {
            let _ = &mdns;
            r
        }
        r = ctl => r,
    }
}

/// The transports this build supports, for `status` output.
pub fn supported_transports() -> Vec<Transport> {
    vec![Transport::Wifi, Transport::Ble]
}
