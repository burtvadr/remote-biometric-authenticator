//! `pam_rba`: a very thin PAM adapter.
//!
//! What this module does, and all it does:
//!
//! 1. Determine the Linux user being authenticated.
//! 2. Hand that user, plus the PAM context, to `rbad`.
//! 3. Translate the daemon's answer into a PAM result.
//!
//! What it deliberately does **not** do: any networking, pairing, cryptography,
//! BLE, or Android protocol work. Those belong in the daemon, where they can be
//! tested and updated independently of the PAM ABI.
//!
//! Failure policy: every failure is a denial. The module never treats an
//! unreachable daemon, a malformed reply, or a timeout as an authentication, and
//! it never returns `PAM_SUCCESS` without a verified signature behind it. Whether
//! the *PAM stack* then falls through to a password is a policy decision for the
//! stack's `sufficient`/`required` ordering, not something this module decides.

pub mod ipc;

use std::ffi::{c_char, c_int, c_void, CStr, CString};

/// PAM return values, defined here rather than linked so the module has no build
/// dependency on `libpam`. The values are fixed by the PAM API.
pub mod pam {
    use std::ffi::c_int;

    pub const PAM_SUCCESS: c_int = 0;
    /// `PAM_TEXT_INFO`: a message for the user, not a prompt for input.
    pub const PAM_TEXT_INFO: c_int = 4;
    pub const PAM_AUTH_ERR: c_int = 7;
    pub const PAM_AUTHINFO_UNAVAIL: c_int = 9;
    /// libpam's `PAM_USER_ERR`: no user was established.
    pub const PAM_USER_ERR: c_int = 8;
    pub const PAM_PERM_DENIED: c_int = 6;
    pub const PAM_BUF_ERR: c_int = 5;
    pub const PAM_ABORT: c_int = 26;
}

/// The opaque PAM handle, used only to obtain callouts.
#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

extern "C" {
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_get_user(
        pamh: *const PamHandle,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
    fn pam_syslog(pamh: *const PamHandle, priority: c_int, fmt: *const c_char, ...);
    fn pam_prompt(
        pamh: *const PamHandle,
        style: c_int,
        response: *mut *mut c_char,
        fmt: *const c_char,
        ...
    ) -> c_int;
}

const PAM_SERVICE: c_int = 1; // PAM_SERVICE
const LOG_ERR: c_int = 3;
const LOG_WARNING: c_int = 4;
const LOG_INFO: c_int = 6;

/// Module arguments, parsed from the PAM configuration line.
#[derive(Debug, Clone)]
pub struct Options {
    /// The purpose shown on the device. `sudo` shows "sudo", `login` shows "login".
    pub purpose: String,
    /// The PAM service name to report.
    pub service: String,
    /// An optional device name or id, when a user has more than one authenticator.
    pub device: Option<String>,
    /// How long to wait for the operator.
    pub timeout_ms: u64,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            purpose: "authenticate".into(),
            service: "pam-rba".into(),
            device: None,
            timeout_ms: 90_000,
        }
    }
}

impl Options {
    /// Parses a PAM argument string such as `purpose=sudo device=Pixel timeout_ms=60000`.
    ///
    /// Unrecognised arguments are an error rather than being ignored: a typo in a
    /// security-relevant setting should be visible, not silently permissive. Bare
    /// flags (`debug`) are accepted, so the documented example actually parses.
    pub fn parse(args: &[String]) -> Result<(Options, bool), String> {
        let mut opts = Options::default();
        let mut debug = false;
        for arg in args {
            let (key, value) = match arg.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => {
                    // A bare argument is a flag.
                    match arg.trim() {
                        "debug" => {
                            debug = true;
                            continue;
                        }
                        other => return Err(format!("unknown flag {other:?}")),
                    }
                }
            };
            match key {
                "purpose" => opts.purpose = value.to_owned(),
                "service" => opts.service = value.to_owned(),
                "device" => opts.device = Some(value.to_owned()),
                "timeout_ms" => {
                    opts.timeout_ms = value
                        .parse()
                        .map_err(|_| format!("timeout_ms must be a number, got {value:?}"))?
                }
                "debug" => debug = true,
                other => return Err(format!("unknown option {other:?}")),
            }
        }
        Ok((opts, debug))
    }
}

/// The result of an authentication attempt, before it becomes a PAM code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The device signed a fresh challenge for exactly this request.
    Authenticated,
    /// The user declined, or no authenticator was willing.
    Denied(String),
    /// The daemon could not be asked. Distinct from a denial so the stack can log
    /// it usefully, but still never an authentication.
    Unavailable(String),
}

/// The core operation, callable without a live PAM stack so it can be tested.
pub fn authenticate(socket: &std::path::Path, user: &str, opts: &Options) -> Decision {
    let request = ipc::Request::Authenticate {
        user: user.to_owned(),
        purpose: opts.purpose.clone(),
        service: opts.service.clone(),
        operation: "authenticate".into(),
        device: opts.device.clone(),
        timeout_ms: Some(opts.timeout_ms),
    };
    match ipc::call(socket, &request) {
        Ok(response) => {
            if response.authenticated() {
                Decision::Authenticated
            } else {
                // A denial from the daemon is a denial here, with its reason kept
                // for the log.
                Decision::Denied(
                    response
                        .code
                        .or(response.error)
                        .unwrap_or_else(|| "denied".into()),
                )
            }
        }
        Err(ipc::IpcError::Unreachable(e)) => Decision::Unavailable(e),
        Err(ipc::IpcError::Malformed(e)) => Decision::Unavailable(e),
        // An I/O failure mid-reply means the answer is unknown, so it is treated as
        // "not authenticated".
        Err(ipc::IpcError::Io(e)) => Decision::Unavailable(e.to_string()),
    }
}

/// Maps a [Decision] onto a PAM return code.
pub fn to_pam_code(decision: &Decision) -> c_int {
    match decision {
        Decision::Authenticated => pam::PAM_SUCCESS,
        // "Authentication information unavailable" tells the stack the mechanism
        // could not run, which is distinct from "the credentials were wrong".
        Decision::Unavailable(_) => pam::PAM_AUTHINFO_UNAVAIL,
        Decision::Denied(_) => pam::PAM_AUTH_ERR,
    }
}

/// Reads the PAM user name.
///
/// The username is taken from PAM's own item, never from anything the client
/// supplies, and the daemon cross-checks it against the socket's peer UID. If PAM
/// has no user, authentication cannot proceed.
fn pam_user(pamh: *const PamHandle) -> Result<String, c_int> {
    let mut user: *const c_char = std::ptr::null();
    let rc = unsafe { pam_get_user(pamh, &mut user, std::ptr::null()) };
    if rc != pam::PAM_SUCCESS {
        return Err(rc);
    }
    if user.is_null() {
        return Err(pam::PAM_USER_ERR);
    }
    let name = unsafe { CStr::from_ptr(user) }
        .to_str()
        .map(|s| s.to_owned())
        .map_err(|_| pam::PAM_USER_ERR)?;
    if name.is_empty() {
        return Err(pam::PAM_USER_ERR);
    }
    Ok(name)
}

/// Reports the PAM service name, for the signed request context.
fn pam_service(pamh: *const PamHandle) -> String {
    let mut item: *const c_void = std::ptr::null();
    let rc = unsafe { pam_get_item(pamh, PAM_SERVICE, &mut item) };
    if rc == pam::PAM_SUCCESS && !item.is_null() {
        if let Ok(s) = unsafe { CStr::from_ptr(item as *const c_char) }.to_str() {
            if !s.is_empty() {
                return s.to_owned();
            }
        }
    }
    String::new()
}

/// Sends a best-effort informational message to the PAM conversation.
///
/// This is how a terminal or greeter can tell the user to check the device. GDM's
/// lock screen may ignore `PAM_TEXT_INFO`; in that case this is harmless and the
/// message remains in the journal. It is not an authentication result and is
/// never required for the module to work.
fn pam_info(pamh: *const PamHandle, message: &str) {
    let Ok(c) = CString::new(message) else {
        return;
    };
    // `pam_prompt` is a variadic extension; the format string has no `%` and no
    // arguments. The response pointer is null because this is informational.
    unsafe {
        let _ = pam_prompt(pamh, pam::PAM_TEXT_INFO, std::ptr::null_mut(), c.as_ptr());
    }
}

/// Logs through `pam_syslog`, which handles a null handle.
fn syslog(pamh: *const PamHandle, priority: c_int, message: &str) {
    let c = match std::ffi::CString::new(message) {
        Ok(c) => c,
        Err(_) => return,
    };
    unsafe { pam_syslog(pamh, priority, c.as_ptr()) };
}

/// PAM entry point for the `auth` stack phase.
///
/// # Safety
/// Called by PAM itself with a valid handle and argument array. Marked `unsafe`
/// because the pointers come from outside Rust, so this is the single place where
/// that trust boundary is crossed. No pointer is retained after the call.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *const PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // Panic containment (SEC-009): a panic in this module must never unwind
    // into the host process (PAM, polkit, sudo). Fail closed instead.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pam_sm_authenticate_inner(pamh, argc, argv)
    }));
    match result {
        Ok(rc) => rc,
        Err(_) => {
            // Log through a fresh call; pamh may be stale but pam_syslog handles
            // null handles.
            syslog(pamh, LOG_ERR, "pam_rba: panicked; failing closed");
            pam::PAM_AUTHINFO_UNAVAIL
        }
    }
}

/// Inner implementation of `pam_sm_authenticate`, separated so the outer
/// function can wrap it in `catch_unwind`.
unsafe fn pam_sm_authenticate_inner(
    pamh: *const PamHandle,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // Parse arguments first: a misconfigured module must not silently authenticate
    // with defaults.
    let args: Vec<String> = if argc > 0 && !argv.is_null() {
        (0..argc as isize)
            .map(|i| {
                CStr::from_ptr(*argv.offset(i))
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    } else {
        Vec::new()
    };
    let (mut opts, debug) = match Options::parse(&args) {
        Ok(v) => v,
        Err(e) => {
            // Deliberately not PAM_ABORT. Aborting would remove every later entry
            // from the stack, including the password fallback, turning a typo in this
            // module's arguments into a lockout. Reporting "unavailable" keeps the
            // recovery path intact while making the misconfiguration obvious in the
            // system log.
            syslog(
                pamh,
                LOG_ERR,
                &format!(
                    "pam_rba: misconfigured ({e}); skipping this module so the stack can continue"
                ),
            );
            return pam::PAM_AUTHINFO_UNAVAIL;
        }
    };

    let user = match pam_user(pamh) {
        Ok(u) => u,
        Err(rc) => {
            syslog(pamh, LOG_ERR, "pam_rba: no PAM user; cannot authenticate");
            return rc;
        }
    };

    // Report the actual PAM service, so the device shows what is asking.
    let service = pam_service(pamh);
    if !service.is_empty() {
        opts.service = service;
    }

    // Use the production socket path, ignoring RBA_SOCKET (SEC-006 hardening).
    let socket = ipc::production_socket();

    // Only attempt the device path when a device is actually connected.
    // Otherwise the prompt ("Check your device") is misleading and the 5 s
    // wait is pointless — fall straight through to the password.
    let connected = ipc::call(&socket, &ipc::Request::Status)
        .ok()
        .and_then(|r| r.result)
        .and_then(|r| r.get("connected_devices").and_then(|v| v.as_i64()))
        .unwrap_or(0);
    if connected == 0 {
        syslog(
            pamh,
            LOG_INFO,
            "pam_rba: no device connected; skipping to password",
        );
        return pam::PAM_AUTHINFO_UNAVAIL;
    }

    // Best effort: tell the user on the host to look at the device. Some PAM
    // consumers display this; GDM's lock screen may not.
    pam_info(pamh, "Check your device to approve this request.");

    let decision = authenticate(&socket, &user, &opts);
    if debug {
        let detail = match &decision {
            Decision::Authenticated => "authenticated".to_string(),
            Decision::Denied(r) => format!("denied: {r}"),
            Decision::Unavailable(r) => format!("unavailable: {r}"),
        };
        syslog(pamh, LOG_WARNING, &format!("pam_rba: user={user} {detail}"));
    }

    to_pam_code(&decision)
}

/// PAM entry point for setting credentials. This module authenticates; it never
/// *changes* a credential, so it has nothing to set.
/// # Safety
/// Called by PAM with a valid handle and argument array; nothing is dereferenced.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *const PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    pam::PAM_SUCCESS
}

/// PAM entry point for account management. Authentication is not an account
/// operation, so this is a no-op rather than a way to bypass a policy.
/// # Safety
/// Called by PAM with a valid handle and argument array; nothing is dereferenced.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *const PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    pam::PAM_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let o = Options::default();
        assert_eq!(o.purpose, "authenticate");
        assert!(o.device.is_none());
        assert_eq!(o.timeout_ms, 90_000);
    }

    #[test]
    fn parses_arguments() {
        let args: Vec<String> = ["purpose=sudo", "device=Pixel 9", "timeout_ms=5000"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (o, debug) = Options::parse(&args).unwrap();
        assert_eq!(o.purpose, "sudo");
        assert_eq!(o.device.as_deref(), Some("Pixel 9"));
        assert_eq!(o.timeout_ms, 5000);
        assert!(!debug);
    }

    #[test]
    fn a_bare_debug_flag_parses() {
        // This is the exact argument the documented example uses. Treating it as a
        // malformed key=value pair made the module abort the whole PAM stack.
        let args: Vec<String> = vec!["purpose=sudo".into(), "debug".into()];
        let (o, debug) = Options::parse(&args).unwrap();
        assert_eq!(o.purpose, "sudo");
        assert!(debug, "the bare debug flag must be recognised");
    }

    #[test]
    fn rejects_malformed_arguments() {
        for bad in [
            vec!["nosuchflag"],
            vec!["unknown=1"],
            vec!["timeout_ms=soon"],
        ] {
            let args: Vec<String> = bad.iter().map(|s| s.to_string()).collect();
            assert!(Options::parse(&args).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn the_documented_example_parses() {
        // Guards the README's recommended stack line against exactly the class of
        // bug that would lock an administrator out of their own machine.
        let args: Vec<String> = ["purpose=sudo", "timeout_ms=60000", "debug"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (o, debug) = Options::parse(&args).unwrap();
        assert_eq!(o.purpose, "sudo");
        assert_eq!(o.timeout_ms, 60_000);
        assert!(debug);
    }

    #[test]
    fn a_device_name_without_a_space_parses() {
        // libpam splits a configuration line on whitespace, so an argument value
        // cannot contain a space. Documented so nobody writes a config that silently
        // means something else.
        let args: Vec<String> = vec!["device=Pixel-9".into()];
        let (o, _) = Options::parse(&args).unwrap();
        assert_eq!(o.device.as_deref(), Some("Pixel-9"));
    }

    #[test]
    fn a_space_in_a_device_name_is_not_silently_accepted() {
        // PAM would hand this over as two arguments: "device=Pixel" and "9".
        // The second must be rejected rather than ignored.
        let args: Vec<String> = vec!["device=Pixel".into(), "9".into()];
        assert!(Options::parse(&args).is_err());
    }

    #[test]
    fn only_a_genuine_authentication_maps_to_success() {
        assert_eq!(to_pam_code(&Decision::Authenticated), pam::PAM_SUCCESS);
        assert_eq!(
            to_pam_code(&Decision::Denied("USER_CANCELLED".into())),
            pam::PAM_AUTH_ERR
        );
        // Unreachable daemon is not the same as wrong credentials, but it is
        // equally not a success.
        assert_eq!(
            to_pam_code(&Decision::Unavailable("socket missing".into())),
            pam::PAM_AUTHINFO_UNAVAIL
        );
    }

    #[test]
    fn an_unreachable_daemon_is_never_a_success() {
        let socket = std::path::Path::new("/nonexistent/rbad-test.sock");
        let decision = authenticate(socket, "alice", &Options::default());
        assert!(
            !matches!(decision, Decision::Authenticated),
            "an unreachable daemon must never authenticate"
        );
    }
}
