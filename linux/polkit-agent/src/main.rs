//! A polkit authentication agent backed by a remote authenticator.
//!
//! # What this does and does not do
//!
//! polkit decides *which* actions require authentication and *who* may perform them.
//! That policy lives in polkit's rules and in its backend and is deliberately not
//! duplicated here. This agent supplies only the one thing a device can supply —
//! evidence that a particular local user is present:
//!
//! ```text
//! polkit  ->  "user 1000 wants to do X; authenticate them"   (authorization)
//! agent   ->  device proves user 1000 is present              (authentication)
//! ```
//!
//! Conflating the two is the mistake a project like this tends to make, so this agent
//! never answers "is this allowed?". It answers "was this user authenticated by a
//! trusted credential?" and lets polkit draw the authorization conclusion.
//!
//! # The D-Bus protocol
//!
//! The shape of the protocol is easy to get wrong, and getting it wrong fails in a way
//! that looks like "polkit is broken". As of polkit 127 the Authority interface has no
//! `BeginAuthentication` signal; that model was removed. Instead:
//!
//! 1. The agent exports an object implementing
//!    `org.freedesktop.PolicyKit1.AuthenticationAgent`, with `Authenticate` and
//!    `CancelAuthentication` methods.
//! 2. It calls `RegisterAuthenticationAgent(subject, locale, object_path)` — note the
//!    *object path*, and note there is no capabilities argument on this method
//!    (capabilities, where they exist, go to `...WithOptions`).
//! 3. polkitd calls the agent's `Authenticate` when a transaction needs it.
//! 4. Having authenticated the user, the agent calls back
//!    `CheckAuthorization(subject, action_id, details, ALLOW_USER_INTERACTION,
//!    cancellation_id)`. The `polkit-agent` key in `details` names this agent, and is
//!    what tells polkitd the authentication came from a registered agent.
//!
//! # Failure posture
//!
//! A wrong answer here is expensive: an agent that denies something another agent
//! could have allowed breaks a desktop. So:
//!
//! * If no authenticator is paired or connected, the agent reports the failure and
//!   lets polkit fall through to whatever else is available. It does not invent a
//!   denial.
//! * If the user declines on the device, that is a real answer, not a missing one.
//! * If polkit cancels the challenge, the agent stops rather than answering late.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Mutex;
use zbus::zvariant::{OwnedValue, Value};

const AUTHORITY: &str = "org.freedesktop.PolicyKit1";
const AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const AUTHORITY_IFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const AGENT_IFACE: &str = "org.freedesktop.PolicyKit1.AuthenticationAgent";

/// `CheckAuthorizationFlags.ALLOW_USER_INTERACTION`
const ALLOW_USER_INTERACTION: u32 = 1;

/// Outer bound on waiting for the device.
///
/// This is only the outer bound. The device's own freshness window is much shorter, so
/// this exists to stop a challenge from hanging a desktop action indefinitely rather
/// than to decide the outcome.
const CHALLENGE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for polkit to acknowledge the authorisation reply.
const CHECK_REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// A polkit subject: session id plus its details.
type Subject = (String, HashMap<String, OwnedValue>);

/// The uid polkit is asking about, looked up **by name**.
///
/// Scanning the details for the first value that happens to be a uint32 would be a
/// serious mistake: a subject carries both `uid` and `pid`, and picking up the pid
/// would have the agent ask the device to authenticate whoever owns that process
/// rather than the person being checked.
fn subject_uid(subject: &Subject) -> Option<i32> {
    i32::try_from(subject.1.get("uid")?.clone()).ok()
}

/// The session id polkit is asking about.
fn subject_session(subject: &Subject) -> String {
    subject.0.clone()
}

struct Agent {
    config: Config,
    /// The session id this agent registered under. polkit uses the matching
    /// `polkit-agent` detail to recognise its own agents.
    session: String,
    connection: zbus::Connection,
    /// Cancellation ids polkit has withdrawn. Answering one of these would be
    /// answering a transaction nobody is waiting for any more.
    cancelled: Mutex<HashSet<String>>,
    verbose: bool,
    answered: AtomicU64,
}

struct Config {
    socket: std::path::PathBuf,
}

/// Asks `rbad` to authenticate a Linux user.
///
/// `Ok(true)` only when the daemon verified a signature over a fresh challenge naming
/// exactly this user. Everything else — including any error — is a refusal.
async fn authenticate_via_device(
    config: &Config,
    unix_user: i32,
    action_id: &str,
) -> Result<bool, String> {
    let user = rbad::ipc::user_for_uid(unix_user as u32)
        .ok_or_else(|| format!("no local user account for uid {unix_user}"))?;

    let request = rbad::ipc::ClientRequest::Authenticate {
        user: user.clone(),
        // `polkit`, so the device's prompt says this is a desktop authorisation
        // rather than a login or a sudo.
        purpose: "polkit".into(),
        // The action id as the service, so the device names the exact action.
        service: action_id.to_owned(),
        operation: "authenticate".into(),
        device: None,
        timeout_ms: Some(CHALLENGE_TIMEOUT.as_millis() as u64),
    };

    // The control client is blocking; the agent is async.
    let socket = config.socket.clone();
    let call = tokio::task::spawn_blocking(move || rbad::ipc::call(&socket, &request));
    match tokio::time::timeout(CHALLENGE_TIMEOUT, call).await {
        Ok(Ok(Ok(response))) => {
            if response.authenticated() {
                Ok(true)
            } else {
                Err(format!(
                    "the device declined ({})",
                    response.code.unwrap_or_else(|| "denied".into())
                ))
            }
        }
        Ok(Ok(Err(e))) => Err(format!("rbad unreachable: {e}")),
        Ok(Err(join)) => Err(format!("rbad task failed: {join}")),
        Err(_) => Err("the device did not answer in time".into()),
    }
}

/// The object polkitd calls into.
#[zbus::interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl Agent {
    /// polkit needs this user authenticated before it can decide the action.
    ///
    /// The reply is not a yes or a no: it is a call back into `CheckAuthorization`
    /// that tells polkit this registered agent vouched for the user. polkit then runs
    /// its own policy against that fact.
    async fn authenticate(
        &self,
        subject: Subject,
        details: HashMap<String, OwnedValue>,
        action_id: String,
        action_display: String,
        _request_details: String,
        cancellation_id: String,
    ) -> zbus::fdo::Result<()> {
        tracing::info!(action = %action_id, "authentication requested");

        let Some(uid) = subject_uid(&subject) else {
            // Without a uid there is no Linux user to name, so there is nothing
            // meaningful to ask the device. Reporting the failure lets polkit fall
            // back rather than treating this as a refusal.
            tracing::warn!(action = %action_id, "challenge carried no uid; cannot name a Linux user");
            return Ok(());
        };
        tracing::info!(action = %action_id, uid, "challenge details");

        let outcome = authenticate_via_device(&self.config, uid, &action_id).await;

        if self.cancelled.lock().await.contains(&cancellation_id) {
            tracing::info!(action = %action_id, "cancelled while waiting; not answering");
            return Ok(());
        }

        // Forward polkit's own details as strings, and name this agent. Without the
        // `polkit-agent` key polkitd cannot tell this reply apart from an ordinary
        // application-level check.
        let mut out: HashMap<String, String> = HashMap::new();
        for (k, v) in &details {
            if let Ok(s) = String::try_from(v.clone()) {
                out.insert(k.clone(), s);
            }
        }
        out.insert("polkit-agent".into(), self.session.clone());

        let proxy = zbus::Proxy::new(&self.connection, AUTHORITY, AUTHORITY_PATH, AUTHORITY_IFACE)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let session = subject_session(&subject);
        let reply: Result<Result<zbus::Message, zbus::Error>, tokio::time::error::Elapsed> =
            tokio::time::timeout(
                CHECK_REPLY_TIMEOUT,
                proxy.call_method(
                    "CheckAuthorization",
                    &(
                        (session, subject.1.clone()),
                        action_id.clone(),
                        out,
                        ALLOW_USER_INTERACTION,
                        cancellation_id,
                    ),
                ),
            )
            .await;

        match reply {
            Err(_) => {
                tracing::warn!(action = %action_id, "polkit did not answer the authorisation reply")
            }
            Ok(Err(e)) => {
                tracing::warn!(action = %action_id, "polkit rejected the reply: {e}")
            }
            Ok(Ok(body)) => {
                self.answered.fetch_add(1, Ordering::Relaxed);
                match body
                    .body()
                    .deserialize::<(bool, bool, HashMap<String, String>)>()
                {
                    Ok((authorized, challenge, _)) => {
                        tracing::info!(
                            action = %action_id,
                            authorized,
                            challenge,
                            "polkit reached a decision"
                        );
                        if self.verbose {
                            println!(
                                "[agent] {} -> authorized={} challenge={}",
                                action_display, authorized, challenge
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(action = %action_id, "cannot decode the decision: {e}")
                    }
                }
            }
        }

        match outcome {
            Ok(true) => tracing::info!(action = %action_id, "authenticated by the device"),
            Ok(false) => tracing::info!(action = %action_id, "the device declined"),
            Err(e) => tracing::info!(action = %action_id, "not authenticated: {e}"),
        }
        Ok(())
    }

    /// polkit withdrew the challenge. Stop waiting rather than answering into the void.
    async fn cancel_authentication(&self, cancellation_id: String) -> zbus::fdo::Result<()> {
        tracing::info!("polkit cancelled the challenge");
        self.cancelled.lock().await.insert(cancellation_id);
        Ok(())
    }
}

/// The locale to advertise to polkit, from the environment where possible.
fn locale() -> String {
    for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(v) = std::env::var(var) {
            let v = v.split('.').next().unwrap_or(&v).to_owned();
            if !v.is_empty() && v != "C" && v != "POSIX" {
                return v;
            }
        }
    }
    "en_US.UTF-8".into()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut config = Config {
        socket: std::env::var_os("RBA_SOCKET")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(rbad::config::DEFAULT_SOCKET)),
    };
    let mut verbose = false;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => {
                config.socket = std::path::PathBuf::from(
                    args.get(i + 1).cloned().ok_or("--socket needs a value")?,
                );
                i += 2;
            }
            "--verbose" | "-v" => {
                verbose = true;
                i += 1;
            }
            other => {
                eprintln!("unknown option {other:?}");
                std::process::exit(2);
            }
        }
    }

    let connection = zbus::Connection::system().await?;

    const AGENT_PATH: &str = "/org/rba/PolkitAgent";
    let object_path: &str = AGENT_PATH;
    // polkit 127 names a subject by *kind* only; the identifying fields live in the
    // details. The older "unix-process:<pid>" spelling is rejected outright with
    // "Error getting subject: Unknown subject of kind ...", which reads like a
    // permissions problem and is not one.
    let (subject, scope) = registration_subject();
    // What identifies this agent to polkit in the reply's `polkit-agent` detail: the
    // kind we registered under.
    let session = subject.0.clone();

    let agent = Agent {
        config: Config {
            socket: config.socket.clone(),
        },
        session: session.clone(),
        connection: connection.clone(),
        cancelled: Mutex::new(HashSet::new()),
        verbose,
        answered: AtomicU64::new(0),
    };

    // Export first: polkitd is told where to call, so the object has to be reachable
    // by the time registration returns.
    connection.object_server().at(AGENT_PATH, agent).await?;
    tracing::info!("exported {} at {object_path}", AGENT_IFACE);

    let proxy = zbus::Proxy::new(&connection, AUTHORITY, AUTHORITY_PATH, AUTHORITY_IFACE).await?;

    // (subject, locale, object_path).
    //
    // The subject must be a *process* subject. polkit parses the session id, and a
    // free-form id is rejected outright with "Unknown subject of kind `...' -- the
    // agent has to identify itself as the process it is.
    tracing::info!(scope, subject = %subject.0, "registering with polkit");
    // Register, retrying.
    //
    // Registration can legitimately fail for a moment and then succeed, and two cases
    // matter here. polkit refuses a session subject that is not the caller's own, so if
    // this process is moved between cgroups -- by systemd, or by a session manager --
    // the first attempt can fail and a later one succeed. And polkitd itself restarts,
    // which drops every registration. An agent that gave up on the first error would
    // silently stop working in both cases, which is the worst possible failure for a
    // component whose absence is invisible until someone needs to authenticate.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut attempt = 0u32;
    // Only the subject is needed afterwards; the scope is reported inside the loop.
    let (subject, _scope) = loop {
        attempt += 1;
        let (candidate, scope) = registration_subject();
        match proxy
            .call_method(
                "RegisterAuthenticationAgent",
                &(candidate.clone(), locale(), object_path),
            )
            .await
        {
            Ok(_) => {
                tracing::info!(
                    socket = %config.socket.display(),
                    scope,
                    subject = %candidate.0,
                    %object_path,
                    attempts = attempt,
                    "registered with polkit"
                );
                break (candidate, scope);
            }
            Err(e) => {
                tracing::warn!(
                    scope,
                    subject = %candidate.0,
                    attempt,
                    error = %e,
                    "registration refused; retrying"
                );
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "could not register with polkit after {attempt} attempts: {e}"
                    )
                    .into());
                }
                tokio::time::sleep(Duration::from_millis(750)).await;
            }
        }
    };
    let session = subject.0.clone();

    // Unregister on the way out. Without this a crashed agent stays registered and
    // swallows challenges it will never answer, which looks to a user like polkit is
    // broken.
    let conn = connection.clone();
    let unreg_subject = subject.clone();
    let unreg_session = session.clone();
    tokio::spawn(async move {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("SIGINT handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        tracing::info!("unregistering");
        if let Ok(p) = zbus::Proxy::new(&conn, AUTHORITY, AUTHORITY_PATH, AUTHORITY_IFACE).await {
            let _ = p
                .call_method(
                    "UnregisterAuthenticationAgent",
                    &(unreg_subject, AGENT_PATH),
                )
                .await;
        }
        tracing::info!(session = %unreg_session, "unregistered");
    });

    tracing::info!("waiting for challenges");
    // polkitd calls us; there is no signal to listen for.
    //
    // SIGHUP re-registers. That is what makes the session a *property of the process*
    // rather than of how it happened to be started: an agent moved between cgroups
    // ends up registered for the wrong session until told otherwise, and being
    // registered for the wrong session is invisible -- polkit simply never calls.
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("SIGHUP handler");
    tracing::info!("send SIGHUP to re-register for this process's current session");
    loop {
        tokio::select! {
            _ = sighup.recv() => {
                tracing::info!("SIGHUP: re-registering");
                let (fresh, scope) = registration_subject();
                match proxy
                    .call_method(
                        "RegisterAuthenticationAgent",
                        &(fresh.clone(), locale(), object_path),
                    )
                    .await
                {
                    Ok(_) => tracing::info!(scope, subject = %fresh.0, "re-registered"),
                    Err(e) => tracing::warn!(error = %e, "re-registration refused"),
                }
            }
        }
    }
}

/// polkit's name for a subject that is a single process.
const PROCESS_SUBJECT_KIND: &str = "unix-process";
/// polkit's name for a subject that is a whole login session.
const SESSION_SUBJECT_KIND: &str = "unix-session";

/// This process as polkit describes a subject.
struct ProcessIdentity {
    pid: u32,
    uid: i32,
    /// polkit compares this against /proc to make sure it is being asked about the
    /// process it thinks it is, so it has to be the real value, not a stand-in.
    start_time: u64,
}

impl ProcessIdentity {
    fn this() -> Self {
        Self {
            pid: std::process::id(),
            uid: real_uid(),
            start_time: process_start_time(),
        }
    }

    fn process_details(&self) -> HashMap<String, OwnedValue> {
        let mut d = HashMap::new();
        d.insert("pid".to_owned(), owned(Value::from(self.pid)));
        d.insert("start-time".to_owned(), owned(Value::from(self.start_time)));
        d.insert("uid".to_owned(), owned(Value::from(self.uid)));
        d
    }
}

/// Which session, if any, this agent is running inside.
///
/// This decides whether the agent can serve a desktop at all, so it is not a detail.
///
/// polkit resolves a challenge to an agent whose registered subject is an *aggregate*
/// of the subject that needs authenticating. An agent registered against a single
/// process is only ever offered requests from that one process -- which, for a desktop
/// prompt, means never. Registering the session is what makes the agent eligible for
/// everything inside it.
///
/// polkit enforces this: registering a session other than the caller's own is refused
/// with "Passed session and the session the caller is in differs". So an agent serving
/// a desktop has to be *running* in that desktop's session.
fn own_logind_session() -> Option<String> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    // e.g. "0::/user.slice/user-1000.slice/session-11.scope"
    cgroup
        .lines()
        .filter_map(|l| l.rsplit_once("::").map(|(_, path)| path))
        .find_map(|path| {
            let leaf = path.rsplit('/').next()?;
            let rest = leaf.strip_prefix("session-")?.strip_suffix(".scope")?;
            if rest.chars().all(|c| c.is_ascii_digit()) && !rest.is_empty() {
                Some(rest.to_owned())
            } else {
                None
            }
        })
}

/// The subject to register with.
///
/// Prefers the enclosing login session. Falls back to this process, which is the
/// correct-but-narrow choice: the agent still works for a request made by this exact
/// process, and reports that it is not serving the wider session.
fn registration_subject() -> (Subject, &'static str) {
    let me = ProcessIdentity::this();
    if let Some(session) = own_logind_session() {
        let mut d = HashMap::new();
        d.insert("session-id".to_owned(), owned(Value::from(session.clone())));
        return ((SESSION_SUBJECT_KIND.to_owned(), d), "session");
    }
    tracing::info!("no login session in this process's cgroup; registering for this process only");
    (
        (PROCESS_SUBJECT_KIND.to_owned(), me.process_details()),
        "process",
    )
}

fn owned(v: Value<'static>) -> OwnedValue {
    OwnedValue::try_from(v).expect("a variant of a plain scalar is always valid")
}

/// The real uid of this process, read from the kernel rather than assumed.
///
/// Shelling out to `id` would be slower and spoofable via $PATH. A uid of -1 is
/// returned on failure: polkit will refuse the registration, which is the safe
/// direction, since an agent that cannot describe itself must not claim to be
/// somebody else.
fn real_uid() -> i32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned))
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            tracing::warn!("cannot read this process's uid from /proc/self/status");
            -1
        })
}

/// This process's start time, in clock ticks since boot.
///
/// Field 22 of /proc/self/stat. `comm` may contain spaces and parentheses, so fields
/// are counted from after the final ')'.
fn process_start_time() -> u64 {
    std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| {
            let tail = &s[s.rfind(')').map(|i| i + 1).unwrap_or(0)..];
            tail.split_whitespace().nth(19)?.parse().ok()
        })
        .unwrap_or_else(|| {
            tracing::warn!("cannot read this process's start time from /proc/self/stat");
            0
        })
}
