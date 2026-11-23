//! Local control API: the Unix socket that PAM, `rba` and future
//! integrations use.
//!
//! Two rules from `PROTOCOL.md` §14 are enforced here:
//!
//! 1. The local caller is established from `SO_PEERCRED`, never from a field in
//!    the request body.
//! 2. If the caller is not root, the username it asks for must resolve, through
//!    the local user database, to the caller's own UID.
//!
//! Without (2), any unprivileged process could ask the daemon to authenticate as
//! `root`.

use rba_protocol::errors::{ProtocolError, Result};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Credentials of the process on the other end of the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// Reads peer credentials from a connected Unix socket.
pub fn peer_credentials(fd: std::os::fd::RawFd) -> io::Result<PeerCredentials> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCredentials {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

/// Looks up the local username for a UID via the NSS-aware libc interface, so
/// that network directory users resolve correctly.
///
/// # Safety
/// Uses `getpwuid_r`, which is thread-safe, and zero-initialises the `passwd`
/// struct before use. The returned pointers are valid only for the duration of
/// the call, and are copied out immediately.
pub fn user_for_uid(uid: u32) -> Option<String> {
    let mut size = 4096usize;
    for _ in 0..4 {
        let mut buf = vec![0i8; size];
        let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                &mut passwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE {
            size *= 2;
            continue;
        }
        if rc != 0 || result.is_null() || passwd.pw_name.is_null() {
            return None;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(passwd.pw_name) };
        return name.to_str().ok().map(|s| s.to_owned());
    }
    None
}

/// Decides whether `peer` may request an authentication for `requested_user`.
///
/// The authenticated principal is always the peer UID; `requested_user` is only
/// the *label* that goes into the signed request context.
pub fn authorize_caller(peer: PeerCredentials, requested_user: &str) -> Result<String> {
    if peer.uid == 0 {
        // root may ask on behalf of any user (login, PAM as root, etc.).
        return Ok(requested_user.to_owned());
    }
    match user_for_uid(peer.uid) {
        Some(actual) if actual == requested_user => Ok(actual),
        Some(actual) => Err(ProtocolError::ContextMismatch(format!(
            "caller is {actual} (uid {}) but requested {requested_user}",
            peer.uid
        ))),
        None => Err(ProtocolError::Internal(format!(
            "cannot resolve uid {} to a local user",
            peer.uid
        ))),
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Control requests, one JSON object per line.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ControlRequest {
    /// List paired authenticators.
    List,
    /// Daemon status: listeners, sessions, pending pairing.
    Status,
    /// Enter pairing mode for a bounded time, optionally with a chosen code.
    Pair {
        /// Six ASCII digits. The daemon generates one when absent.
        #[serde(default)]
        code: Option<String>,
        /// Which endpoint types the code: `device` (default) or `host`.
        #[serde(default)]
        code_entry: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    /// Ask a paired device to authenticate a Linux user.
    Authenticate {
        /// The Linux user. Checked against peer credentials.
        user: String,
        #[serde(default = "default_purpose")]
        purpose: String,
        #[serde(default = "default_service")]
        service: String,
        #[serde(default = "default_operation")]
        operation: String,
        /// Device selector: exact `device_id` hex, or a name.
        #[serde(default)]
        device: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    /// Revoke a device's authorisation immediately.
    Revoke { device: String },
    /// Fetch the pairing code for an in-progress pairing session.
    PairingCode,
    /// Record the operator's confirmation. In `host` mode this carries the code
    /// the operator typed from the device; the daemon verifies it before persisting.
    ConfirmPairing {
        #[serde(default)]
        code: Option<String>,
    },
}

fn default_purpose() -> String {
    "authenticate".into()
}
fn default_service() -> String {
    "rba".into()
}
fn default_operation() -> String {
    "authenticate".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

impl ControlResponse {
    pub fn ok(result: serde_json::Value) -> ControlResponse {
        ControlResponse {
            ok: true,
            code: None,
            error: None,
            result: Some(result),
        }
    }

    pub fn err(code: &str, error: impl Into<String>) -> ControlResponse {
        ControlResponse {
            ok: false,
            code: Some(code.to_owned()),
            error: Some(error.into()),
            result: None,
        }
    }

    pub fn from_protocol_error(e: &ProtocolError) -> ControlResponse {
        ControlResponse::err(e.code().as_str(), e.to_string())
    }
}

/// Hard cap on one control request, including the trailing newline.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Reads one newline-delimited JSON request with a *bounded* buffer.
///
/// `read_line` grows its `String` until it finds a newline, so a client that
/// streams data forever can exhaust memory before any size check runs. This
/// implementation inspects the buffered bytes first and rejects the request as
/// soon as the cap is exceeded, so allocation never goes above
/// `MAX_REQUEST_BYTES` plus one buffered chunk.
pub async fn read_request<R>(reader: &mut BufReader<R>) -> io::Result<Option<ControlRequest>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut line: Vec<u8> = Vec::with_capacity(512);
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            // EOF without a newline: no more requests.
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "control request ended before a newline",
                ))
            };
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let take = newline.unwrap_or(available.len());
        if line.len() + take > MAX_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take + usize::from(newline.is_some()));
        if newline.is_some() {
            break;
        }
    }
    let text = std::str::from_utf8(&line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request is not UTF-8"))?;
    match serde_json::from_str::<ControlRequest>(text.trim()) {
        Ok(r) => Ok(Some(r)),
        Err(e) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed control request: {e}"),
        )),
    }
}

/// Writes one newline-delimited JSON response and flushes.
pub async fn write_response<W>(writer: &mut W, resp: &ControlResponse) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut line =
        serde_json::to_vec(resp).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn resolves_this_process_uid_to_a_username() {
        let me = unsafe { libc::getuid() };
        let name = user_for_uid(me).expect("current uid must resolve");
        assert!(!name.is_empty());
        assert!(!name.contains('/'));
    }

    #[test]
    fn unknown_uid_does_not_resolve() {
        // 0x7FFFFFFF is not a normal account uid.
        assert!(user_for_uid(0x7FFF_FFFF).is_none());
    }

    #[test]
    fn caller_may_only_request_its_own_account() {
        let me = unsafe { libc::getuid() };
        let peer = PeerCredentials {
            pid: 0,
            uid: me,
            gid: 0,
        };
        let name = user_for_uid(me).unwrap();
        assert!(authorize_caller(peer, &name).is_ok());
        // Asking for anyone else must be refused.
        assert!(matches!(
            authorize_caller(peer, "root"),
            Err(ProtocolError::ContextMismatch(_))
        ));
        assert!(matches!(
            authorize_caller(peer, "nobody-at-all"),
            Err(ProtocolError::ContextMismatch(_))
        ));
    }

    #[test]
    fn root_may_request_any_user() {
        let peer = PeerCredentials {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        assert_eq!(authorize_caller(peer, "alice").unwrap(), "alice");
    }

    #[test]
    fn unresolvable_uid_is_an_error_not_a_bypass() {
        let peer = PeerCredentials {
            pid: 0,
            uid: 0x7FFF_FFFE,
            gid: 0,
        };
        assert!(matches!(
            authorize_caller(peer, "alice"),
            Err(ProtocolError::Internal(_))
        ));
    }

    #[tokio::test]
    async fn request_parsing_defaults_the_optional_fields() {
        let json = r#"{"cmd":"authenticate","user":"alice"}"#;
        match serde_json::from_str::<ControlRequest>(json).unwrap() {
            ControlRequest::Authenticate {
                user,
                purpose,
                service,
                operation,
                device,
                ..
            } => {
                assert_eq!(user, "alice");
                assert_eq!(purpose, "authenticate");
                assert_eq!(service, "rba");
                assert_eq!(operation, "authenticate");
                assert!(device.is_none());
            }
            other => panic!("unexpected parse: {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_requests_are_errors() {
        let raw = b"{\"cmd\":\"nonsense\"}\n";
        let mut r = BufReader::new(&raw[..]);
        assert!(read_request(&mut r).await.is_err());

        let raw2 = b"not json\n";
        let mut r2 = BufReader::new(&raw2[..]);
        assert!(read_request(&mut r2).await.is_err());
    }

    #[tokio::test]
    async fn oversized_requests_are_refused() {
        let big = format!("{{\"cmd\":\"list\",\"x\":\"{}\"}}\n", "A".repeat(70_000));
        let mut r = BufReader::new(big.as_bytes());
        assert!(read_request(&mut r).await.is_err());
    }

    #[tokio::test]
    async fn a_stream_without_a_newline_is_cut_off_at_the_limit() {
        // The old read_line implementation buffered this entire slice before it
        // checked the length. The bounded reader must reject it.
        let endless = vec![b'A'; MAX_REQUEST_BYTES + 1];
        let mut r = BufReader::new(&endless[..]);
        let err = read_request(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_valid_request_still_parses_after_the_bounded_read() {
        let mut r = BufReader::new(&b"{\"cmd\":\"list\"}\n"[..]);
        let request = read_request(&mut r).await.unwrap().unwrap();
        assert!(matches!(request, ControlRequest::List));
    }

    #[tokio::test]
    async fn response_shape_is_stable() {
        let mut buf: Vec<u8> = Vec::new();
        write_response(&mut buf, &ControlResponse::ok(serde_json::json!({"n": 1})))
            .await
            .unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.ends_with('\n'));
        assert!(text.contains("\"ok\":true"));
        assert!(!text.contains("\"error\""), "absent fields must be omitted");

        let mut buf2: Vec<u8> = Vec::new();
        write_response(&mut buf2, &ControlResponse::err("NOT_PAIRED", "no devices"))
            .await
            .unwrap();
        let text2 = String::from_utf8(buf2).unwrap();
        assert!(text2.contains("\"ok\":false"));
        assert!(text2.contains("\"code\":\"NOT_PAIRED\""));
    }

    #[test]
    fn peer_credentials_round_trip_over_a_real_socket() {
        // Confirms SO_PEERCRED actually reports this process, which is the
        // property the whole authorization decision rests on.
        use std::os::unix::net::{UnixListener, UnixStream};
        let path =
            std::path::PathBuf::from(format!("/tmp/rba-peertest-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();

        let client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();

        let cred = peer_credentials(server.as_raw_fd()).unwrap();
        assert_eq!(cred.uid, unsafe { libc::getuid() });
        assert_eq!(cred.gid, unsafe { libc::getgid() });
        assert!(cred.pid > 0);
        drop(client);
        let _ = std::fs::remove_file(&path);
    }
}

// ---------------------------------------------------------------------------
// Client
//
// The control-socket client. Lives here rather than in a PAM or polkit module
// because both integrations need exactly the same request/response handling, and
// two copies of a security-relevant client is two copies of a security-relevant
// bug.
// ---------------------------------------------------------------------------

/// A request to the daemon, mirroring the control protocol.
#[derive(Debug, Clone)]
pub enum ClientRequest {
    List,
    Status,
    Authenticate {
        user: String,
        purpose: String,
        service: String,
        operation: String,
        device: Option<String>,
        timeout_ms: Option<u64>,
    },
    Revoke {
        device: String,
    },
}

impl ClientRequest {
    fn to_json(&self) -> serde_json::Value {
        match self {
            ClientRequest::List => serde_json::json!({ "cmd": "list" }),
            ClientRequest::Status => serde_json::json!({ "cmd": "status" }),
            ClientRequest::Authenticate {
                user,
                purpose,
                service,
                operation,
                device,
                timeout_ms,
            } => {
                let mut v = serde_json::json!({
                    "cmd": "authenticate",
                    "user": user,
                    "purpose": purpose,
                    "service": service,
                    "operation": operation,
                });
                if let Some(d) = device {
                    v["device"] = serde_json::Value::String(d.clone());
                }
                if let Some(t) = timeout_ms {
                    v["timeout_ms"] = serde_json::Value::from(*t);
                }
                v
            }
            ClientRequest::Revoke { device } => {
                serde_json::json!({ "cmd": "revoke", "device": device })
            }
        }
    }
}

/// The daemon's answer.
#[derive(Debug, Clone)]
pub struct ClientResponse {
    pub ok: bool,
    pub code: Option<String>,
    pub error: Option<String>,
    pub result: Option<serde_json::Value>,
}

impl ClientResponse {
    /// True only when the daemon verified a signature over a fresh challenge for
    /// exactly the requested user.
    pub fn authenticated(&self) -> bool {
        self.ok
            && self
                .result
                .as_ref()
                .and_then(|r| r.get("authenticated"))
                .and_then(|v| v.as_bool())
                == Some(true)
    }
}

/// Why a control call could not be made.
#[derive(Debug)]
pub enum IpcError {
    Unreachable(String),
    Malformed(String),
    Io(std::io::Error),
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpcError::Unreachable(s) => write!(f, "rbad is not reachable: {s}"),
            IpcError::Malformed(s) => write!(f, "malformed reply from rbad: {s}"),
            IpcError::Io(e) => write!(f, "control socket error: {e}"),
        }
    }
}

impl From<std::io::Error> for IpcError {
    fn from(e: std::io::Error) -> Self {
        IpcError::Io(e)
    }
}

/// Sends one request and reads one reply.
pub fn call(
    socket: &Path,
    request: &ClientRequest,
) -> std::result::Result<ClientResponse, IpcError> {
    use std::io::{BufRead, BufReader, Write};
    let stream = std::os::unix::net::UnixStream::connect(socket)
        .map_err(|e| IpcError::Unreachable(format!("{}: {e}", socket.display())))?;
    let mut writer = &stream;
    let line = serde_json::to_string(&request.to_json())
        .map_err(|e| IpcError::Malformed(e.to_string()))?;
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut reply = String::new();
    let n = reader.read_line(&mut reply)?;
    if n == 0 {
        return Err(IpcError::Malformed(
            "the daemon closed the connection".into(),
        ));
    }
    let parsed: serde_json::Value =
        serde_json::from_str(reply.trim()).map_err(|e| IpcError::Malformed(e.to_string()))?;
    Ok(ClientResponse {
        ok: parsed.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
        code: parsed
            .get("code")
            .and_then(|v| v.as_str())
            .map(String::from),
        error: parsed
            .get("error")
            .and_then(|v| v.as_str())
            .map(String::from),
        result: parsed.get("result").cloned(),
    })
}

/// The control socket location, honouring `RBA_SOCKET` for testing.
pub fn default_socket() -> std::path::PathBuf {
    match std::env::var_os("RBA_SOCKET") {
        Some(p) => std::path::PathBuf::from(p),
        None => std::path::PathBuf::from(crate::config::DEFAULT_SOCKET),
    }
}
